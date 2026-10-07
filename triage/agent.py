"""The investigation agent: a LangGraph tool-calling loop that ends in a structured, cited submission.

    model ──tool calls──▶ tools ──▶ model ... ──submit──▶ END
      │                     │
      └─no tool call──▶ nudge (twice), then parse text as the answer
                            └─step limit──▶ model may only call the submit tool

The final answer is a tool call validated by a Pydantic schema (structured output that works the same on
OpenAI and on local models served by Ollama or LM Studio). Every tool result is stored in memory under an
evidence id like ``i5-q12:3`` and the submission must cite those ids; ``citations_valid`` records whether
it did, so reports can be audited back to the query that produced each claim.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Annotated, Any, Callable, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from pydantic import BaseModel, ValidationError

from triage.llm import ChatClient
from triage.memory import Memory
from triage.tracing import span


@dataclass
class Tool:
    name: str
    description: str
    schema: type[BaseModel]
    run: Callable[..., tuple[str, list | None]]  # -> (text for the model, untruncated rows for memory)

    def spec(self) -> dict:
        spec = convert_to_openai_tool(self.schema)
        spec["function"]["name"] = self.name
        spec["function"]["description"] = self.description
        return spec


@dataclass
class Submission:
    schema: type[BaseModel]
    name: str = "submit_answer"
    description: str = "Submit your final answer. Ends the investigation."

    def spec(self) -> dict:
        return Tool(self.name, self.description, self.schema, lambda **_: ("", None)).spec()


class State(TypedDict):
    messages: Annotated[list, add_messages]
    steps: int
    nudges: int
    force_submit: bool
    final: dict | None


@dataclass
class Result:
    task_id: str
    final: dict | None
    steps: int
    tool_calls: list = field(default_factory=list)
    transcript: list = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    model_seconds: float = 0.0
    wall_seconds: float = 0.0
    llm_calls: int = 0
    cached_calls: int = 0
    fallback: str | None = None  # "parsed_text" | "no_answer" when the model never submitted
    error: str | None = None
    citations_valid: bool | None = None
    evidence_ids: list = field(default_factory=list)

    def as_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "transcript"}
        d["transcript"] = [_msg_json(m) for m in self.transcript]
        return d


def _msg_json(m) -> dict:
    d = {"role": m.type, "content": m.content if isinstance(m.content, str) else json.dumps(m.content)}
    if isinstance(m, AIMessage) and m.tool_calls:
        d["tool_calls"] = [{"name": c["name"], "args": c["args"], "id": c.get("id")} for c in m.tool_calls]
    if isinstance(m, ToolMessage):
        d["tool_call_id"] = m.tool_call_id
    return d


NUDGE = ("You did not call a tool. Continue investigating with a tool call, or call {submit} with your "
         "final answer, confidence and evidence ids.")
FORCE = "Step limit reached. Call {submit} now with your best answer, your confidence and the evidence ids."


class Investigator:
    def __init__(self, client: ChatClient, tools: list[Tool], submission: Submission, memory: Memory,
                 system_prompt: str, max_steps: int = 15):
        self.client = client
        self.tools = {t.name: t for t in tools}
        self.submission = submission
        self.memory = memory
        self.system_prompt = system_prompt
        self.max_steps = max_steps
        self._specs = [t.spec() for t in tools] + [submission.spec()]
        self._submit_only = [submission.spec()]
        self.graph = self._build()

    def _build(self):
        g = StateGraph(State)
        g.add_node("model", self._model_node)
        g.add_node("tools", self._tools_node)
        g.add_node("nudge", self._nudge_node)
        g.set_entry_point("model")
        g.add_conditional_edges("model", self._after_model, {"tools": "tools", "nudge": "nudge", "end": END})
        g.add_conditional_edges("tools", self._after_tools, {"model": "model", "end": END})
        g.add_edge("nudge", "model")
        return g.compile()

    # ── nodes ──
    def _model_node(self, state: State):
        tools = self._submit_only if state["force_submit"] else self._specs
        messages = [SystemMessage(content=self.system_prompt)] + self._prefix + state["messages"]
        with span("llm", model=self.client.model, provider=self.client.provider, step=state["steps"]) as s:
            msg, info = self.client.invoke(messages, tools)
            s.set(input_tokens=info["input_tokens"], output_tokens=info["output_tokens"], cached=info["cached"])
        r = self._result
        r.llm_calls += 1
        r.cached_calls += int(info["cached"])
        r.input_tokens += info["input_tokens"]
        r.output_tokens += info["output_tokens"]
        r.cost_usd += info["cost_usd"]
        r.model_seconds += info["seconds"]
        return {"messages": [msg]}

    def _tools_node(self, state: State):
        last = state["messages"][-1]
        out, final, steps, bad_submit = [], None, state["steps"], False
        for call in last.tool_calls:
            name, args, cid = call["name"], call.get("args") or {}, call.get("id") or f"call{steps}"
            if name == self.submission.name:
                try:
                    final = self.submission.schema(**args).model_dump()
                    out.append(ToolMessage(content="Submitted.", tool_call_id=cid))
                except ValidationError as exc:
                    bad_submit = True
                    out.append(ToolMessage(content=f"Invalid submission, fix and resubmit: {exc.errors()[:3]}",
                                           tool_call_id=cid))
                continue
            steps += 1
            tool = self.tools.get(name)
            with span("tool", tool=name, step=steps) as s:
                if tool is None:
                    text, rows = f"Unknown tool {name!r}. Available: {', '.join(self.tools)}", None
                else:
                    try:
                        text, rows = tool.run(**args)
                    except TypeError as exc:
                        text, rows = f"Bad arguments for {name}: {exc}", None
                s.set(rows=len(rows or []), chars=len(text))
            obs_id = self.memory.record_step(self._task_id, steps, name, args, text, rows)
            self._result.tool_calls.append({"step": steps, "obs_id": obs_id, "tool": name, "args": args,
                                            "output": text[:4000]})
            out.append(ToolMessage(content=f"[evidence {obs_id}]\n{text}", tool_call_id=cid))
        update = {"messages": out, "steps": steps}
        if final is None and (bad_submit or state["force_submit"]):
            update["nudges"] = state["nudges"] + 1  # bounded retries for invalid or forced submissions
        if final is not None:
            update["final"] = final
        elif steps >= self.max_steps and not state["force_submit"]:
            update["force_submit"] = True
            update["messages"] = out + [HumanMessage(content=FORCE.format(submit=self.submission.name))]
        return update

    def _nudge_node(self, state: State):
        return {"nudges": state["nudges"] + 1,
                "messages": [HumanMessage(content=NUDGE.format(submit=self.submission.name))]}

    # ── routing ──
    def _after_model(self, state: State):
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and last.tool_calls:
            return "tools"
        if state["nudges"] < 2 and not state["force_submit"]:
            return "nudge"
        return "end"

    def _after_tools(self, state: State):
        if state.get("final") is not None:
            return "end"
        if state["nudges"] >= 4:
            return "end"
        return "model"

    # ── entry point ──
    def investigate(self, task_id: str, task: str) -> Result:
        self._task_id = task_id
        self._result = Result(task_id=task_id, final=None, steps=0)
        self._prefix = self.memory.prefix_messages(task)
        start = time.time()
        init = {"messages": [HumanMessage(content=task)], "steps": 0, "nudges": 0, "force_submit": False,
                "final": None}
        with span("investigation", task_id=task_id, memory=self.memory.mode) as s:
            try:
                state = self.graph.invoke(init, {"recursion_limit": 4 * self.max_steps + 20})
            except Exception as exc:  # budget, cache miss in replay, network: record and move on
                self._result.error = f"{exc.__class__.__name__}: {exc}"
                state = {"messages": init["messages"], "steps": self._result.steps, "final": None}
            r = self._result
            r.steps = state.get("steps", 0)
            r.transcript = list(state["messages"])
            r.final = state.get("final")
            if r.final is None and not r.error:
                text = _last_text(r.transcript)
                r.final, r.fallback = self.submission_from_text(text)
            r.wall_seconds = time.time() - start
            final = r.final or {}
            ids = list(final.get("evidence") or [])
            for claim in final.get("claims") or []:  # triage reports cite per claim
                ids += [e for e in claim.get("evidence", []) if e not in ids]
            r.evidence_ids = ids
            known = {c["obs_id"] for c in r.tool_calls}
            r.citations_valid = bool(r.evidence_ids) and all(e in known or self.memory.graph.observation(e)
                                                             for e in r.evidence_ids)
            s.set(steps=r.steps, submitted=r.final is not None, fallback=r.fallback, error=r.error)
        answer = (r.final or {}).get("answer") or (r.final or {}).get("verdict") or ""
        self.memory.record_answer(task_id, task, str(answer), r.transcript)
        return r

    def submission_from_text(self, text: str):
        """Last resort when a model answers in prose instead of calling the submit tool."""
        if not text.strip():
            return None, "no_answer"
        blob = re.search(r"\{.*\}", text, re.S)  # a JSON submission written as prose
        if blob:
            try:
                return self.submission.schema(**json.loads(blob.group(0))).model_dump(), "parsed_text"
            except (ValueError, ValidationError, TypeError):
                pass
        m = re.search(r"(?:final answer|answer)\s*[:\-]\s*(.+)", text, re.I)
        guess = (m.group(1) if m else text.strip().splitlines()[-1]).strip()[:300]
        fields = self.submission.schema.model_fields
        data: dict[str, Any] = {}
        if "answer" in fields:
            data["answer"] = guess
        if "verdict" in fields:
            v = re.search(r"\b(MALICIOUS|BENIGN|ESCALATE)\b", text.upper())
            data["verdict"] = v.group(1) if v else "ESCALATE"
            data.setdefault("summary", guess)
        if "confidence" in fields:
            data["confidence"] = 0
        try:
            return self.submission.schema(**data).model_dump(), "parsed_text"
        except ValidationError:
            return None, "no_answer"


def _last_text(messages) -> str:
    for m in reversed(messages):
        if isinstance(m, AIMessage) and isinstance(m.content, str) and m.content.strip():
            return m.content
    return ""
