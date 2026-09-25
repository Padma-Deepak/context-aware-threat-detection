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
        self.llm = ChatOpenAI(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            temperature=0,
            api_key=os.getenv("OPENAI_API_KEY"),
            max_retries=8,
            timeout=120
        )

        # One line change swaps stub for Padma's real server
        self.mcp_server_url = os.getenv("MCP_SERVER_URL", "http://localhost:8000/mcp")

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
                "tokens_used": int,
                "duration_seconds": float,
                "intermediate_steps": list
            }
        """
        start_time = time.time()

        mcp_client = MultiServerMCPClient(
            {
                "security-investigation-stub": {
                    "url": self.mcp_server_url,
                    "transport": "streamable_http",
                }
            }
        )

        tools = await mcp_client.get_tools()
        executor = await self._build_executor(tools)

        # Get managed history from context_manager
        # Empty list = no prior context (first investigation or full mode)
        chat_history = []
        if self.context_manager:
            chat_history = self.context_manager.get_history()

        response = await executor.ainvoke({
            "input": task,
            "chat_history": chat_history
        })

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
        tokens_used = self._estimate_tokens(task, report, intermediate_steps)

        # In windowed_summary mode, the update() call above may have just
        # triggered a real (billed) summarizer API call. Fold its actual
        # token cost in here so tokens_used reflects the true cost of this
        # investigation, not just the main agent's own request.
        if self.context_manager:
            tokens_used += self.context_manager.pop_summarizer_tokens()

        return {
            "task": task,
            "report": report,
            "verdict": verdict,
            "tool_calls": tool_call_count,
            "tokens_used": tokens_used,
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