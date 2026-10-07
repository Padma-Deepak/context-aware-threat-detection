# agent.py
#
# Person B's core deliverable — the investigation loop.
#
# What this file does:
#   1. Connects to MCP server and discovers the 5 security tools
#   2. Builds a tool-calling agent with a security-focused system prompt
#   3. Runs the investigation loop until VERDICT is produced
#   4. Returns a structured result for benchmark.py to measure
#
# What this file does NOT do:
#   - Manage context (context_manager.py)
#   - Run benchmarks (benchmark.py)
#   - Know anything about the database (MCP server's job)

import os
import time
import asyncio
from dotenv import load_dotenv

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_mcp_adapters.client import MultiServerMCPClient

import llm as llm_factory
from observability import TraceCallback, UsageCallback
from prompts import get_system_prompt
from schemas import extract_verdict, parse_report

load_dotenv()

class InvestigationAgent:

    def __init__(self, context_manager=None):
        """
        context_manager: instance of ContextManager (context_manager.py)
                         None = no context management (stateless, single investigation)
        """
        self.context_manager = context_manager

        # temperature=0 (deterministic-ish; repeats still vary), max_retries=8 so a
        # rate-limited benchmark backs off instead of crashing. Provider/model
        # come from llm.py (LLM_PROVIDER / OPENAI_MODEL / ANTHROPIC_MODEL).
        self.llm = llm_factory.make_agent_llm()
        self.prompt_version = os.getenv("PROMPT_VERSION", "v1").lower()
        self.system_prompt = get_system_prompt(self.prompt_version)
        self.max_iterations = int(os.getenv("MAX_ITERATIONS", "10"))

        # One line change swaps stub for Padma's real server
        self.mcp_server_url = os.getenv("MCP_SERVER_URL", "http://localhost:8000/mcp")

        # Lazily connected on first investigate() call and reused after
        # that -- a benchmark chain runs investigate() a dozen-plus times
        # back-to-back, and reconnecting to the same MCP server on every
        # single call added avoidable latency for no benefit (tool
        # definitions don't change mid-run).
        self._tools = None

    async def _get_tools(self):
        if self._tools is None:
            mcp_client = MultiServerMCPClient(
                {
                    "security-investigation-stub": {
                        "url": self.mcp_server_url,
                        "transport": "streamable_http",
                    }
                }
            )
            self._tools = await mcp_client.get_tools()
        return self._tools

    async def _build_executor(self, tools):
        """
        Builds the LangChain AgentExecutor.

        AgentExecutor is the investigation loop:
          while True:
            response = llm(messages + tools)
            if response has tool_call → execute tool → add result → repeat
            else → final answer, stop

        max_iterations (env MAX_ITERATIONS, default 10) prevents infinite loops.
        return_intermediate_steps=True gives benchmark.py the tool call count.
        """
        prompt = ChatPromptTemplate.from_messages([
            ("system", self.system_prompt),
            MessagesPlaceholder("chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder("agent_scratchpad"),
        ])

        agent = create_tool_calling_agent(self.llm, tools, prompt)

        return AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=True,
            max_iterations=self.max_iterations,
            return_intermediate_steps=True
        )

    async def investigate(self, task: str) -> dict:
        """
        Runs a full investigation for the given task.

        Args:
            task: e.g. "Determine whether 185.220.101.5 is malicious"

        Returns:
            {
                "task": str,
                "report": str,
                "verdict": str,          # MALICIOUS / BENIGN / ESCALATE / UNKNOWN
                "tool_calls": int,
                "tokens_used": int,
                "duration_seconds": float,
                "intermediate_steps": list
            }
        """
        start_time = time.time()

        tools = await self._get_tools()
        executor = await self._build_executor(tools)

        # Get managed history from context_manager
        # Empty list = no prior context (first investigation or full mode)
        chat_history = []
        if self.context_manager:
            chat_history = self.context_manager.get_history()

        usage = UsageCallback()
        response = await executor.ainvoke(
            {"input": task, "chat_history": chat_history},
            config={"callbacks": [usage, TraceCallback(run_label=task[:60])]},
        )

        # Update context manager with what just happened
        if self.context_manager:
            self.context_manager.update(
                task=task,
                steps=response.get("intermediate_steps", []),
                output=response["output"]
            )

        duration = time.time() - start_time
        report = response["output"]
        intermediate_steps = response.get("intermediate_steps", [])
        tool_call_count = len(intermediate_steps)
        verdict = self._extract_verdict(report)
        # Real usage reported by the API, summed over every LLM call in this
        # run (system prompt, injected history, scratchpad re-sends and all).
        # Falls back to the chars//4 estimate only if the provider reported none.
        if usage.llm_calls and usage.total_tokens:
            agent_tokens, tokens_source = usage.total_tokens, "api"
        else:
            agent_tokens, tokens_source = self._estimate_tokens(task, report, intermediate_steps), "estimate"

        # windowed_summary's update() above may have made a billed summarizer
        # call; fold its real usage in so windowing is not made to look free.
        summarizer_tokens = self.context_manager.pop_summarizer_tokens() if self.context_manager else 0
        tokens_used = agent_tokens + summarizer_tokens

        return {
            "task": task,
            "report": report,
            "verdict": verdict,
            "tool_calls": tool_call_count,
            "tokens_used": tokens_used,
            "agent_tokens": agent_tokens,
            "agent_input_tokens": usage.input_tokens if tokens_source == "api" else 0,
            "agent_output_tokens": usage.output_tokens if tokens_source == "api" else 0,
            "summarizer_tokens": summarizer_tokens,
            "tokens_source": tokens_source,
            "llm_calls": usage.llm_calls,
            "parsed": parse_report(report),
            "duration_seconds": round(duration, 2),
            "intermediate_steps": intermediate_steps
        }

    def _extract_verdict(self, report: str) -> str:
        """Last VERDICT line in the report, or UNKNOWN (see schemas.extract_verdict)."""
        return extract_verdict(report)

    def _estimate_tokens(self, task, report, steps) -> int:
        """
        Rough estimate of the main agent's own request: 1 token ≈ 4
        characters (LangChain's AgentExecutor doesn't surface OpenAI's
        real usage numbers here). investigate() adds the summarizer's
        exact token usage on top of this via
        context_manager.pop_summarizer_tokens().
        """
        total_chars = len(task) + len(report)
        for step in steps:
            action, observation = step
            total_chars += len(str(action)) + len(str(observation))
        return total_chars // 4


# ──────────────────────────────────────────────────────────────
# ENTRY POINT — test a single investigation manually
#
# Run stub server first:
#   cd mcp_server && python stub_server.py
#
# Then in a new terminal:
#   cd agent && python agent.py
# ──────────────────────────────────────────────────────────────

async def main():
    agent = InvestigationAgent()

    result = await agent.investigate(
        "Determine whether the IP 185.220.101.5 is malicious. "
        "Investigate thoroughly and produce a verdict."
    )

    print("\n" + "="*60)
    print("INVESTIGATION COMPLETE")
    print("="*60)
    print(result["report"])
    print(f"\nVerdict:      {result['verdict']}")
    print(f"Tool calls:   {result['tool_calls']}")
    print(f"Tokens used:  {result['tokens_used']}")
    print(f"Duration:     {result['duration_seconds']}s")


if __name__ == "__main__":
    asyncio.run(main())
