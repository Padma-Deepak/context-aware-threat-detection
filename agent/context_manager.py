# context_manager.py
#
# THIS IS THE RESEARCH CONTRIBUTION OF THIS PROJECT.
#
# The paper we're implementing:
#   "Less Context, Better Agents: Efficient Context Engineering
#    for Long-Horizon Tool-Using LLM Agents" (Lodha et al., arXiv:2606.10209)
#
# The core research question:
#   Can we reduce how much context we give the LLM on each turn
#   without reducing its ability to correctly investigate a threat?
#
# This file implements two strategies and lets benchmark.py
# compare them experimentally.
#
# HOW IT PLUGS INTO agent.py:
#   agent.py calls context_manager.get_history() before each investigation
#   agent.py calls context_manager.update() after each investigation
#   The agent itself never changes — only what history it receives changes.

import os
from typing import Literal
from openai import OpenAI
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage

# ──────────────────────────────────────────────────────────────
# WHAT IS A "STEP"?
#
# LangChain's AgentExecutor returns intermediate_steps as a list of:
#   (AgentAction, observation)
# where:
#   AgentAction.tool       = name of tool called e.g. "get_employee_profile"
#   AgentAction.tool_input = arguments passed    e.g. {"employee_id": 42}
#   observation            = what the tool returned (string or dict)
#
# Each (action, observation) pair = one tool call + its result.
# This is what we window and summarize.
# ──────────────────────────────────────────────────────────────


class ContextManager:
    """
    Manages conversation history for the investigation agent.

    Two modes:
      "full"             — keep everything, send everything every turn (baseline)
      "windowed_summary" — keep last N tool pairs verbatim, summarize the rest

    Usage:
        # Full history (baseline)
        cm = ContextManager(mode="full")

        # Windowed + rolling summary (experimental)
        cm = ContextManager(mode="windowed_summary", window_size=5)

        # Plug into agent
        agent = InvestigationAgent(context_manager=cm)
        result = await agent.investigate("Investigate employee 42")
    """

    def __init__(
        self,
        mode: Literal["full", "windowed_summary"] = "full",
        window_size: int = 5
    ):
        """
        Args:
            mode:        "full" or "windowed_summary"
            window_size: how many recent tool call/result pairs to keep
                         verbatim in windowed mode. Paper uses 5.
        """
        self.mode = mode
        self.window_size = window_size

        # ── INTERNAL STATE ─────────────────────────────────────
        # all_steps: every (action, observation) pair from every
        #            investigation run so far, in order.
        #            This is the ground truth — never compressed.
        self.all_steps: list[tuple] = []

        # step_task_index: parallel to all_steps -- step_task_index[i] is
        # the index into all_tasks/all_outputs that all_steps[i] belongs
        # to. Lets us attribute any slice of all_steps (e.g. the last
        # window_size steps) back to the task(s) that produced them.
        self.step_task_index: list[int] = []

        # all_tasks: every user task string in order
        self.all_tasks: list[str] = []

        # all_outputs: every final agent report in order
        self.all_outputs: list[str] = []

        # rolling_summary: the compressed representation of old steps.
        # Only used in windowed_summary mode.
        # Updated before every API call.
        self.rolling_summary: str = ""

        # ── CHEAP MODEL FOR SUMMARIZATION ──────────────────────
        # WHY A SEPARATE CHEAP MODEL?
        # The main agent uses gpt-4o — expensive, slow, high quality.
        # Summarizing old tool results doesn't need that quality.
        # gpt-4o-mini costs ~10x less and is fast.
        # This is a deliberate architectural choice from the paper:
        # use the cheap model to compress, expensive model to reason.
        self.summarizer = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.summarizer_model = "gpt-4o-mini"

    # ──────────────────────────────────────────────────────────────
    # PUBLIC API — called by agent.py
    # ──────────────────────────────────────────────────────────────

    def get_history(self) -> list[BaseMessage]:
        """
        Returns the chat history to inject into the agent's prompt.

        agent.py calls this before every investigation.
        The agent doesn't know or care which mode is active —
        it just receives a list of LangChain messages.

        Returns:
            List of LangChain BaseMessage objects representing
            the managed history. Empty list on first investigation.
        """
        if not self.all_steps:
            # No history yet — first investigation
            return []

        if self.mode == "full":
            return self._build_full_history()
        else:
            return self._build_windowed_history()

    def update(self, task: str, steps: list[tuple], output: str):
        """
        Called by agent.py after each investigation completes.
        Stores the new steps and updates the rolling summary
        if in windowed_summary mode.

        Args:
            task:   The original user question
            steps:  intermediate_steps from AgentExecutor
                    list of (AgentAction, observation) tuples
            output: The final report string from the agent
        """
        task_index = len(self.all_tasks)
        self.all_tasks.append(task)
        self.all_steps.extend(steps)
        self.step_task_index.extend([task_index] * len(steps))
        self.all_outputs.append(output)

        # In windowed mode, refresh the rolling summary now
        # so it's ready for the next investigation.
        # WHY REFRESH HERE AND NOT IN get_history()?
        # Because summarization is a slow API call.
        # We do it after the investigation (when the user is reading
        # the report) rather than before (when they're waiting for
        # the agent to start). Better UX.
        if self.mode == "windowed_summary":
            self._refresh_rolling_summary()

    # ──────────────────────────────────────────────────────────────
    # MODE 1 — FULL HISTORY
    # ──────────────────────────────────────────────────────────────

    def _build_full_history(self) -> list[BaseMessage]:
        """
        Builds history by converting every stored step into
        LangChain messages. Nothing is dropped or compressed.

        Structure sent to LLM each turn:
            [HumanMessage(task_1),
             AIMessage(tool_call_1 + result_1),
             AIMessage(tool_call_2 + result_2),
             ...
             AIMessage(final_report_1),
             HumanMessage(task_2),
             ...]

        WHY AIMESSAGE FOR TOOL RESULTS?
        Tool calls and their results are part of the assistant's
        reasoning trace. Wrapping them as AIMessages keeps the
        conversation structure valid for the LLM.
        """
        messages = []

        # Interleave tasks, steps, and outputs in order
        step_index = 0
        for i, task in enumerate(self.all_tasks):
            # The user's question
            messages.append(HumanMessage(content=task))

            # All tool calls made during this investigation
            # Each step is (AgentAction, observation)
            investigation_steps = self._get_steps_for_investigation(i)
            for action, observation in investigation_steps:
                tool_message = self._format_step_as_message(action, observation)
                messages.append(AIMessage(content=tool_message))

            # The final report
            if i < len(self.all_outputs):
                messages.append(AIMessage(content=self.all_outputs[i]))

        return messages

    # ──────────────────────────────────────────────────────────────
    # MODE 2 — WINDOWED + ROLLING SUMMARY
    # ──────────────────────────────────────────────────────────────

    def _build_windowed_history(self) -> list[BaseMessage]:
        """
        Builds history with two parts:

        PART 1 — Rolling summary (SystemMessage)
            Everything older than the last window_size steps,
            compressed into a compact text block.

        PART 2 — Recent verbatim steps (AIMessages)
            The last window_size tool call/result pairs, exactly
            as they happened. Not compressed.

        Structure sent to LLM each turn:
            [SystemMessage(rolling_summary),
             HumanMessage(task_for_earliest_step_in_window),
             AIMessage(tool_call_N-4 + result),
             AIMessage(tool_call_N-3 + result),
             HumanMessage(task_for_next_step_in_window),   # only if it changed
             AIMessage(tool_call_N-2 + result),
             AIMessage(tool_call_N-1 + result),
             AIMessage(tool_call_N   + result)]

        WHY SYSTEMMESSAGE FOR THE SUMMARY?
        The summary is background context, not a user turn or
        an assistant turn. SystemMessage puts it in the system
        position where the LLM treats it as ground truth context
        rather than conversational history.

        WHY HUMANMESSAGE BOUNDARIES BEFORE EACH TASK'S STEPS?
        Without them, the window is just an undifferentiated blob of
        past tool results with no indication of which question each
        one answered -- _build_full_history() doesn't have this problem
        because it always interleaves HumanMessage(task) per
        investigation. Omitting it here let the model silently conflate
        an old investigation with the current one when the window
        spanned a task boundary (confirmed: with two adjacent chain
        scenarios referencing the same domain, windowed_summary
        re-investigated the OLDER scenario's IP instead of answering the
        newer scenario's actual question).
        """
        messages = []

        # ── PART 1: ROLLING SUMMARY ────────────────────────────
        if self.rolling_summary:
            summary_text = (
                "## Investigation Context (Summary of Prior Activity)\n\n"
                + self.rolling_summary
                + "\n\n---\n"
                "The following are the most recent tool interactions verbatim:"
            )
            messages.append(SystemMessage(content=summary_text))

        # ── PART 2: RECENT VERBATIM STEPS, WITH TASK BOUNDARIES ─
        # Take only the last window_size steps, and their originating
        # task indices, from all_steps / step_task_index.
        recent_steps = self.all_steps[-self.window_size:]
        recent_task_indices = self.step_task_index[-self.window_size:]

        last_task_index = None
        for (action, observation), task_index in zip(recent_steps, recent_task_indices):
            if task_index != last_task_index:
                messages.append(HumanMessage(content=self.all_tasks[task_index]))
                last_task_index = task_index
            tool_message = self._format_step_as_message(action, observation)
            messages.append(AIMessage(content=tool_message))

        return messages

    def _refresh_rolling_summary(self):
        """
        Compresses everything older than the last window_size steps
        into a rolling summary using the cheap model.

        Called after every investigation in windowed_summary mode.

        WHY "ROLLING"?
        Because it accumulates across investigations.
        Investigation 1 → summary of steps 1-2 (older than window)
        Investigation 2 → summary of steps 1-7 (older than window)
        The summary grows to cover more ground, but stays compact
        because the LLM is asked to compress, not transcribe.

        WHAT IF THERE'S NOTHING TO SUMMARIZE?
        If total steps <= window_size, everything fits in the window.
        Nothing needs to be summarized yet.
        """
        # Steps that fall outside the window
        steps_to_summarize = self.all_steps[:-self.window_size] if len(self.all_steps) > self.window_size else []

        if not steps_to_summarize:
            # Everything fits in the window — no summary needed yet
            self.rolling_summary = ""
            return

        # Build a text representation of the steps to summarize
        steps_text = self._steps_to_text(steps_to_summarize)

        # Ask the cheap model to compress them
        # WHY THIS PROMPT STRUCTURE?
        # We explicitly tell it to preserve:
        #   - Employee identity (who we're investigating)
        #   - Concrete evidence (IPs, timestamps, bytes, locations)
        #   - Flags already raised (what's suspicious)
        #   - What tools have already been called (so we don't repeat)
        # Generic summarization ("IP appears suspicious") loses evidence.
        # Security investigations need the specific numbers.
        prompt = f"""You are summarizing the history of a security investigation for an AI agent.

The agent is mid-investigation and needs a compact summary of what has been found so far.

CRITICAL: Preserve all concrete evidence:
- Specific IP addresses
- Exact timestamps and time gaps
- Byte counts and record counts  
- City/country names for geolocation
- Role names and permission actions
- Which tools have already been called

Do NOT write vague summaries like "the IP appeared suspicious."
Write specific summaries like "IP 185.220.101.5 scored 92/100, flagged by VirusTotal and AbuseIPDB, geolocated to Russia (AS45102)."

Investigation steps to summarize:
{steps_text}

Existing summary to update (if any):
{self.rolling_summary if self.rolling_summary else "None — this is the first summary."}

Write a concise but evidence-rich summary paragraph (max 300 words):"""

        response = self.summarizer.chat.completions.create(
            model=self.summarizer_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,      # deterministic — same input = same summary
            max_tokens=400
        )

        self.rolling_summary = response.choices[0].message.content.strip()

    # ──────────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────────

    def _format_step_as_message(self, action, observation) -> str:
        """
        Formats a single (AgentAction, observation) pair as a
        readable string for injection into LangChain messages.

        Example output:
            [Tool Call] detect_impossible_travel
            Input: {"employee_id": 42}
            Result: {"suspicious": true, "gap_hours": 2.25, ...}
        """
        tool_name = getattr(action, 'tool', str(action))
        tool_input = getattr(action, 'tool_input', {})
        return (
            f"[Tool Call] {tool_name}\n"
            f"Input: {tool_input}\n"
            f"Result: {observation}"
        )

    def _steps_to_text(self, steps: list[tuple]) -> str:
        """
        Converts a list of steps to a numbered text block
        for the summarizer prompt.
        """
        lines = []
        for i, (action, observation) in enumerate(steps, 1):
            lines.append(f"Step {i}: {self._format_step_as_message(action, observation)}")
            lines.append("")  # blank line between steps
        return "\n".join(lines)

    def _get_steps_for_investigation(self, investigation_index: int) -> list[tuple]:
        """
        Returns only the steps that belong to a specific investigation,
        using step_task_index (parallel to all_steps) to filter.
        Used by _build_full_history to group steps by task.
        """
        return [
            step for step, task_idx in zip(self.all_steps, self.step_task_index)
            if task_idx == investigation_index
        ]

    # ──────────────────────────────────────────────────────────────
    # INTROSPECTION — useful for benchmark.py
    # ──────────────────────────────────────────────────────────────

    def get_token_estimate(self) -> int:
        """
        Estimates how many tokens the current history would consume.
        Used by benchmark.py to compare token usage across modes.
        1 token ≈ 4 characters (rough estimate).
        """
        history = self.get_history()
        total_chars = sum(len(msg.content) for msg in history)
        return total_chars // 4

    def get_stats(self) -> dict:
        """
        Returns current state for debugging and benchmarking.
        """
        return {
            "mode": self.mode,
            "window_size": self.window_size,
            "total_steps": len(self.all_steps),
            "total_investigations": len(self.all_tasks),
            "steps_in_window": min(len(self.all_steps), self.window_size),
            "steps_summarized": max(0, len(self.all_steps) - self.window_size),
            "rolling_summary_length": len(self.rolling_summary),
            "estimated_tokens": self.get_token_estimate()
        }

    def reset(self):
        """
        Clears all history. Call between benchmark runs to ensure
        each run starts from a clean state.
        """
        self.all_steps = []
        self.step_task_index = []
        self.all_tasks = []
        self.all_outputs = []
        self.rolling_summary = ""