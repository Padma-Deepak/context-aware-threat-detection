import asyncio

import agent as agent_module
from conftest import action, ip_rep, report
from context_manager import ContextManager
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, LLMResult
from observability import TraceCallback, UsageCallback


def llm_result(input_tokens, output_tokens):
    msg = AIMessage(content="x", usage_metadata={"input_tokens": input_tokens, "output_tokens": output_tokens,
                                                 "total_tokens": input_tokens + output_tokens})
    return LLMResult(generations=[[ChatGeneration(message=msg)]])


def test_usage_callback_sums_across_calls():
    cb = UsageCallback()
    cb.on_llm_end(llm_result(1000, 50))
    cb.on_llm_end(llm_result(1200, 80))
    assert (cb.input_tokens, cb.output_tokens, cb.total_tokens, cb.llm_calls) == (2200, 130, 2330, 2)


def test_usage_callback_falls_back_to_llm_output():
    cb = UsageCallback()
    cb.on_llm_end(LLMResult(generations=[[]], llm_output={"token_usage": {"prompt_tokens": 7, "completion_tokens": 3}}))
    assert cb.total_tokens == 10 and cb.llm_calls == 1


def test_trace_callback_writes_jsonl_only_when_enabled(tmp_path):
    path = tmp_path / "t.jsonl"
    TraceCallback(path=str(path), run_label="r").on_tool_start({"name": "lookup_cve"}, "CVE-1")
    assert '"tool": "lookup_cve"' in path.read_text()
    TraceCallback(path=None).on_tool_start({"name": "x"}, "y")  # no path -> no-op, no error


class FakeExecutor:
    """Stands in for AgentExecutor: no LLM, no MCP server, no network."""

    def __init__(self, output, steps, usage=None):
        self.output, self.steps, self.usage = output, steps, usage

    async def ainvoke(self, inputs, config=None):
        self.inputs = inputs
        if self.usage:
            usage_cb = next(c for c in config["callbacks"] if isinstance(c, UsageCallback))
            usage_cb.on_llm_end(llm_result(*self.usage))
        return {"output": self.output, "intermediate_steps": self.steps}


def make_agent(monkeypatch, executor, cm=None):
    monkeypatch.setattr(agent_module.llm_factory, "make_agent_llm", lambda: None)
    a = agent_module.InvestigationAgent(context_manager=cm)

    async def tools():
        return []

    async def build(_tools):
        return executor

    monkeypatch.setattr(a, "_get_tools", tools)
    monkeypatch.setattr(a, "_build_executor", build)
    return a


def test_investigate_uses_real_api_usage_when_available(monkeypatch):
    steps = [(action("lookup_ip_reputation", ip="1.1.1.1"), ip_rep("1.1.1.1", 90))]
    cm = ContextManager(mode="pinned_evidence", window_size=1)
    a = make_agent(monkeypatch, FakeExecutor(report("MALICIOUS"), steps, usage=(1500, 100)), cm)
    res = asyncio.run(a.investigate("is 1.1.1.1 bad?"))
    assert res["verdict"] == "MALICIOUS" and res["tool_calls"] == 1
    assert (res["tokens_used"], res["tokens_source"], res["llm_calls"]) == (1600, "api", 1)
    assert res["parsed"].severity == "HIGH"
    assert cm.all_tasks == ["is 1.1.1.1 bad?"]  # context manager was updated


def test_investigate_falls_back_to_estimate_and_adds_summarizer_cost(monkeypatch, fake_summarizer):
    steps = [(action("lookup_ip_reputation", ip=f"1.1.1.{i}"), ip_rep(f"1.1.1.{i}", 90)) for i in range(3)]
    cm = ContextManager(mode="windowed_summary", window_size=1, summarizer=fake_summarizer)
    a = make_agent(monkeypatch, FakeExecutor(report("BENIGN"), steps, usage=None), cm)
    res = asyncio.run(a.investigate("t"))
    assert res["tokens_source"] == "estimate" and res["summarizer_tokens"] == 100
    assert res["tokens_used"] == res["agent_tokens"] + 100


def test_investigate_passes_managed_history_to_the_executor(monkeypatch):
    cm = ContextManager(mode="full")
    cm.update("earlier", [(action("lookup_cve", cve_id="CVE-1"), "{}")], report("ESCALATE"))
    ex = FakeExecutor(report("ESCALATE"), [])
    asyncio.run(make_agent(monkeypatch, ex, cm).investigate("now"))
    assert ex.inputs["input"] == "now" and len(ex.inputs["chat_history"]) == 3


def test_unparseable_report_is_scored_unknown(monkeypatch):
    res = asyncio.run(make_agent(monkeypatch, FakeExecutor("I refuse.", [])).investigate("t"))
    assert res["verdict"] == "UNKNOWN" and res["parsed"] is None


def test_prompt_version_is_selected_from_env(monkeypatch):
    monkeypatch.setenv("PROMPT_VERSION", "v2")
    a = make_agent(monkeypatch, FakeExecutor("", []))
    assert "EVIDENCE RULES" in a.system_prompt and a.prompt_version == "v2"
