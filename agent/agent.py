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
import re
import time
import asyncio
from dotenv import load_dotenv

from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.callbacks import UsageMetadataCallbackHandler
from langchain_mcp_adapters.client import MultiServerMCPClient

load_dotenv()

# ──────────────────────────────────────────────────────────────
# SYSTEM PROMPT
#
# This turns a general LLM into a security analyst.
# Key design decisions:
#   1. Enforces investigation order (reputation first, logs second)
#   2. Tells the LLM to cross-reference across tools
#   3. Enforces exact VERDICT format so our parser can extract it
#   4. temperature=0 means deterministic — same input = same verdict
# ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert security analyst investigating potential threats.

You have access to 5 tools. Use them to investigate thoroughly:

  lookup_ip_reputation  — threat score + which sources flagged it
  geolocate_ip          — country, ASN, hosting provider
  query_logs            — what this IP/domain actually did on our network
  lookup_cve            — severity of any vulnerabilities exploited
  check_domain_reputation — whether associated domains are malicious

INVESTIGATION PROTOCOL:
1. Start with lookup_ip_reputation for any IP in the task.
2. If score > 30, call geolocate_ip and query_logs.
3. If logs mention a CVE ID, call lookup_cve.
4. If logs mention a domain, call check_domain_reputation.
5. Cross-reference everything — the same IP appearing in reputation,
   logs, AND domain reputation is much stronger evidence than any one alone.

REPORT FORMAT — your final response must follow this exactly:

## Investigation Report

**Target:** [IP or domain investigated]
**Date:** [today]

### Findings
[Each tool's key finding in 1-2 sentences. Be specific — include IPs, scores, countries, event counts.]

### Evidence Summary
[How the findings connect. What pattern do they form together?]

### Risk Assessment
**Severity:** [CRITICAL / HIGH / MEDIUM / LOW]
**Confidence:** [HIGH / MEDIUM / LOW]

### Recommended Actions
[Numbered list of concrete next steps]

VERDICT: [MALICIOUS / BENIGN / ESCALATE]

RULES:
- VERDICT must be on its own line, exactly as shown.
- MALICIOUS = confirmed threat. BENIGN = no threat. ESCALATE = ambiguous, needs human review.
- Never produce a verdict without calling at least 2 tools.
- Never guess — only conclude from tool evidence.
"""


class InvestigationAgent:

    def __init__(self, context_manager=None):
        """
        context_manager: instance of ContextManager (context_manager.py)
                         None = no context management (stateless, single investigation)
        """
        self.context_manager = context_manager

        # temperature=0 — deterministic output
        # Security verdicts must be consistent across runs
        # max_retries: the OpenAI SDK backs off and retries on 429s
        # (rate limit) automatically. Default of 2 isn't enough headroom
        # for a benchmark hammering a low-TPM-tier org back-to-back.
        # stream_usage=True: AgentExecutor streams the model, and without
        # this OpenAI omits usage from streamed responses, so the real
        # token counts investigate() relies on would silently be 0.
        self.llm = ChatOpenAI(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            temperature=0,
            api_key=os.getenv("OPENAI_API_KEY"),
            max_retries=8,
            timeout=120,
            stream_usage=True
        )

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

        max_iterations=10 prevents infinite loops.
        return_intermediate_steps=True gives benchmark.py the tool call count.
        """
        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            MessagesPlaceholder("chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder("agent_scratchpad"),
        ])

        agent = create_tool_calling_agent(self.llm, tools, prompt)

        return AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=True,
            max_iterations=10,
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
                "tokens_used": int,          # real agent tokens + summarizer tokens
                "agent_input_tokens": int,   # prompt tokens across the agent loop
                "summarizer_tokens": int,
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

        # Real usage reported by OpenAI for every LLM call in the loop. Each
        # call re-sends the system prompt, tool schemas, AND chat_history,
        # so this is where the cost of carrying history actually shows up.
        usage = UsageMetadataCallbackHandler()
        response = await executor.ainvoke(
            {"input": task, "chat_history": chat_history},
            config={"callbacks": [usage]},
        )
        agent_tokens = sum(u.get("total_tokens", 0) for u in usage.usage_metadata.values())
        input_tokens = sum(u.get("input_tokens", 0) for u in usage.usage_metadata.values())

        # Update context manager with what just happened
        summarizer_tokens = 0
        if self.context_manager:
            self.context_manager.update(
                task=task,
                steps=response.get("intermediate_steps", []),
                output=response["output"]
            )
            summarizer_tokens = self.context_manager.pop_summarizer_tokens()

        duration = time.time() - start_time
        report = response["output"]
        intermediate_steps = response.get("intermediate_steps", [])

        return {
            "task": task,
            "report": report,
            "verdict": self._extract_verdict(report),
            "tool_calls": len(intermediate_steps),
            "tokens_used": agent_tokens + summarizer_tokens,
            "agent_input_tokens": input_tokens,
            "summarizer_tokens": summarizer_tokens,
            "duration_seconds": round(duration, 2),
            "intermediate_steps": intermediate_steps
        }

    def _extract_verdict(self, report: str) -> str:
        """
        Extracts VERDICT line from the report.
        Regex handles extra whitespace or formatting.
        Returns UNKNOWN if agent failed to produce a verdict.
        """
        match = re.search(r"VERDICT:\s*(MALICIOUS|BENIGN|ESCALATE)", report)
        if match:
            return match.group(1)
        return "UNKNOWN"


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