# benchmark.py
#
# Runner for the v1 synthetic context-management benchmark.
#
# What this does:
#   Groups scenarios from scenarios.json into chains of related scenarios.
#   Each chain runs through ONE shared ContextManager, so history actually
#   accumulates across scenarios within a chain — RUNS_PER_CHAIN times,
#   through both context modes, records metrics, and prints a comparison
#   table.
#
# WHY CHAINS, NOT INDEPENDENT SCENARIOS?
#   The original design created a fresh ContextManager per scenario and
#   called agent.investigate() exactly once against it. get_history() was
#   therefore always called on an empty ContextManager -- windowed_summary
#   and full_history could never differ, because there was never more than
#   zero prior steps to window or summarize. Chaining scenarios through a
#   shared ContextManager is what actually exercises the compression logic.
#
# What it measures:
#   - Verdict accuracy (did the agent get it right?)
#   - Average tokens used
#   - Average wall-clock time
#   - Average tool call count
#   - history_pairs_at_call: how many (action, observation) pairs were
#     already in context_manager.all_steps right before each investigate()
#     call -- lets you confirm compression is actually triggering.
#
# The research question it answers:
#   Can windowed+summary match full_history on accuracy
#   while using fewer tokens and less time?

import json
import asyncio
import time
import os
import traceback
from pathlib import Path
from dotenv import load_dotenv

from agent import InvestigationAgent
from context_manager import ContextManager

load_dotenv()

# ──────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────

RUNS_PER_CHAIN = int(os.getenv("RUNS_PER_CHAIN", "3"))   # repeats of each chain per mode
# LONG_CHAIN=1 runs every scenario in the file as ONE chain through one ContextManager, so history keeps
# accumulating for the whole file: the long-horizon setting context compression is meant for.
LONG_CHAIN = os.getenv("LONG_CHAIN") == "1"
WINDOW_SIZE = int(os.getenv("WINDOW_SIZE", "2"))          # lowered from 5: real scenarios cap at 4 tool
                             # calls, so window_size=5 never triggered summarization

# SCENARIOS_FILE / RESULTS_FILE are env-overridable so the held-out set
# (scenarios_holdout.json) can be run through this same script -- e.g.
# for a final, one-time evaluation -- without editing this file or
# clobbering the dev-set results:
#   SCENARIOS_FILE=../scenarios_holdout.json \
#   RESULTS_FILE=benchmark_results_holdout.json \
#   python benchmark.py
SCENARIOS_FILE = Path(os.getenv("SCENARIOS_FILE", str(Path(__file__).parent.parent / "scenarios.json")))
RESULTS_FILE = Path(os.getenv("RESULTS_FILE", str(Path(__file__).parent / "benchmark_results.json")))

# Which context strategies to run (comma-separated, in order). Default keeps the
# original two-way comparison; add pinned_evidence for the third strategy.
MODES = [m.strip() for m in os.getenv("MODES", "full,windowed_summary").split(",") if m.strip()]
# Hard spending cap. Cost is computed from REAL token usage after every run; when the running total
# reaches MAX_COST_USD the benchmark stops, checkpoints, and says so. Unset = no cap.
MAX_COST_USD = float(os.environ["MAX_COST_USD"]) if os.getenv("MAX_COST_USD") else None
# USD per 1M tokens (input, output). VERIFY against your provider's current price list: these are
# set from memory and prices change. Override with PRICE_IN_PER_M / PRICE_OUT_PER_M.
PRICES = {"gpt-4o": (2.50, 10.00), "gpt-4o-mini": (0.15, 0.60)}
SUMMARIZER_PRICE_PER_M = 0.60   # summarizer usage is reported as one total; price it at the (higher) output rate


class BudgetExceeded(RuntimeError):
    pass


def agent_price(model: str) -> tuple:
    if os.getenv("PRICE_IN_PER_M") and os.getenv("PRICE_OUT_PER_M"):
        return float(os.environ["PRICE_IN_PER_M"]), float(os.environ["PRICE_OUT_PER_M"])
    return PRICES.get(model, PRICES["gpt-4o"])   # unknown model: assume the dearer known price


def run_cost(result) -> float:
    """USD for one investigation, from real usage. Estimated-only runs (no API usage) cost 0 here,
    which is why the guard also refuses to run when a provider reports no usage (see run_chain)."""
    import llm as llm_factory
    p_in, p_out = agent_price(llm_factory.agent_model_name())
    return (result.get("agent_input_tokens", 0) * p_in + result.get("agent_output_tokens", 0) * p_out
            + result.get("summarizer_tokens", 0) * SUMMARIZER_PRICE_PER_M) / 1_000_000


SPENT_USD = 0.0

INCLUDE_REPORTS = int(os.getenv("INCLUDE_REPORTS", "0"))   # replay last K prior reports in compressed modes
SUMMARY_PROMPT = os.getenv("SUMMARY_PROMPT", "v3")   # v3 = per-investigation incremental log (default); v1 = legacy wording
# native = real tool_calls + ToolMessage history (default); text = the original text rendering, only to reproduce early runs
HISTORY_FORMAT = os.getenv("HISTORY_FORMAT", "native")

# Chains group related scenarios so they can share one ContextManager and
# actually build up history. Grouped by:
#   1. Keeping entity-linked pairs in the same chain, later scenario after
#      earlier one, so accumulated context has something concrete to help
#      with: S09 + S12 both reference the C2 domain cdn-analytics-node7.info;
#      S15 + S17 both reference cloudmetrics-stats.io.
#   2. Balancing total tool-call load per chain (~12-15 each, measured from
#      a prior full_history run) so no chain is trivially short.
CHAIN_SCENARIO_IDS = [
    ["S06", "S03", "S10", "S09", "S12", "S16"],
    ["S02", "S11", "S07", "S08", "S15", "S17"],
    ["S04", "S05", "S01", "S13", "S14", "S18"],
]



# ──────────────────────────────────────────────────────────────
# RESULT DATACLASS
#
# WHY NOT JUST A DICT?
# A typed structure makes the code more readable and prevents
# typos when accessing fields. We're doing a lot of averaging
# and the field names matter.
# ──────────────────────────────────────────────────────────────

class RunResult:
    def __init__(self, scenario_id, mode, run_number, verdict,
                 ground_truth, tokens, duration, tool_calls,
                 history_pairs_at_call, agent_tokens=None, summarizer_tokens=0,
                 tokens_source="estimate", llm_calls=0, leaked=False, archetype=None,
                 input_tokens=0, output_tokens=0):
        self.scenario_id = scenario_id
        self.mode = mode                    # "full" or "windowed_summary"
        self.run_number = run_number        # which repeat of the chain this came from
        self.verdict = verdict              # what the agent returned
        self.ground_truth = ground_truth    # what it should have returned
        self.correct = (verdict == ground_truth)
        self.tokens = tokens
        self.duration = duration
        self.tool_calls = tool_calls
        # len(context_manager.all_steps) immediately before this scenario's
        # investigate() call -- how much accumulated history was in play.
        self.history_pairs_at_call = history_pairs_at_call
        self.agent_tokens = tokens if agent_tokens is None else agent_tokens
        self.summarizer_tokens = summarizer_tokens
        self.tokens_source = tokens_source    # "api" (real usage) or "estimate" (chars//4)
        self.llm_calls = llm_calls
        self.leaked = leaked                  # report contained a scenario's must_not_contain text
        self.archetype = archetype            # generated scenarios only; enables per-archetype accuracy
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens

    def __repr__(self):
        status = "✓" if self.correct else "✗"
        return (f"[{status}] {self.scenario_id} run{self.run_number} "
                f"| {self.mode} | verdict={self.verdict} "
                f"| tokens={self.tokens} | {self.duration}s | tools={self.tool_calls} "
                f"| history_pairs={self.history_pairs_at_call}")


# ──────────────────────────────────────────────────────────────
# LOAD SCENARIOS
# ──────────────────────────────────────────────────────────────

def load_scenarios() -> list[dict]:
    """
    Loads scenarios from SCENARIOS_FILE (default scenarios.json).
    Falls back to hardcoded scenarios if file doesn't exist.

    WHY FALLBACK?
    So you can run and test benchmark.py right now,
    when no scenarios file exists.
    When she's done, drop scenarios.json in the repo root
    and the fallback is never used.
    """
    if SCENARIOS_FILE.exists():
        with open(SCENARIOS_FILE) as f:
            scenarios = json.load(f)
        print(f"Loaded {len(scenarios)} scenarios from {SCENARIOS_FILE}")
        return scenarios
    else:
        raise FileNotFoundError(f"Scenario file not found: {SCENARIOS_FILE}")


# ──────────────────────────────────────────────────────────────
# BUILD CHAINS
# ──────────────────────────────────────────────────────────────

def build_chains(scenarios: list[dict]) -> list[list[dict]]:
    """
    Groups scenarios into chains that will share one ContextManager.

    Priority:
      0. LONG_CHAIN=1: everything in the file is one chain.
      1. If scenarios carry a "chain" key, group by it (file order preserved).
      2. If the loaded scenarios match CHAIN_SCENARIO_IDS (the 18-scenario dev
         set), use that hand-picked grouping.
      3. Otherwise a single chain of everything in file order. NOTE: this is what
         the original held-out run (scenarios_holdout.json) used, so it ran as
         ONE chain of 8, not three chains of 6 like the dev set.
    """
    if LONG_CHAIN:
        return [scenarios]
    if any("chain" in s for s in scenarios):
        groups: dict = {}
        for s in scenarios:
            groups.setdefault(s.get("chain", "default"), []).append(s)
        return list(groups.values())

    by_id = {s["id"]: s for s in scenarios}
    ids_needed = [sid for group in CHAIN_SCENARIO_IDS for sid in group]
    if all(sid in by_id for sid in ids_needed):
        return [[by_id[sid] for sid in group] for group in CHAIN_SCENARIO_IDS]
    return [scenarios]


# ──────────────────────────────────────────────────────────────
# RUN ONE CHAIN IN ONE MODE
# ──────────────────────────────────────────────────────────────

async def run_chain(chain: list[dict], mode: str, run_number: int, all_results: list, summaries: list = None) -> None:
    """
    Runs every scenario in `chain` in sequence through ONE shared
    ContextManager + InvestigationAgent, so history actually accumulates
    across scenarios. This is the core fix: previously every scenario got
    its own fresh ContextManager, so get_history() was always empty and
    windowed_summary vs full_history could never differ.

    Appends into all_results (shared across chains/modes) and checkpoints
    to disk after every scenario, so a crash mid-chain doesn't lose
    already-completed turns.
    """
    context_manager = ContextManager(mode=mode, window_size=WINDOW_SIZE, summary_prompt=SUMMARY_PROMPT,
                                     include_reports=INCLUDE_REPORTS, history_format=HISTORY_FORMAT)
    agent = InvestigationAgent(context_manager=context_manager)

    for position, scenario in enumerate(chain, start=1):
        # Snapshot BEFORE investigate() calls context_manager.update() --
        # this is how much accumulated history the agent actually saw.
        history_pairs_at_call = len(context_manager.all_steps)

        print(f"  [{mode}] run {run_number}/{RUNS_PER_CHAIN}: "
              f"{scenario['id']} (turn {position}/{len(chain)}, "
              f"history_pairs={history_pairs_at_call})...", end=" ", flush=True)

        result = await agent.investigate(scenario["task"])

        global SPENT_USD
        SPENT_USD += run_cost(result)
        if MAX_COST_USD is not None and result.get("tokens_source") != "api":
            raise BudgetExceeded("MAX_COST_USD is set but the provider reported no token usage; cannot enforce the cap")

        # Prompt-injection scenarios list text that must never appear in a report
        # (e.g. fragments of the system prompt the hostile log line asks to reveal).
        leaked = any(t.lower() in result["report"].lower() for t in scenario.get("must_not_contain", []))
        status = "✓" if result["verdict"] == scenario["ground_truth"] else "✗"
        print(f"{status} verdict={result['verdict']} tokens={result['tokens_used']} time={result['duration_seconds']}s")

        all_results.append(RunResult(
            scenario_id=scenario["id"],
            mode=mode,
            run_number=run_number,
            verdict=result["verdict"],
            ground_truth=scenario["ground_truth"],
            tokens=result["tokens_used"],
            duration=result["duration_seconds"],
            tool_calls=result["tool_calls"],
            history_pairs_at_call=history_pairs_at_call,
            agent_tokens=result.get("agent_tokens"),
            summarizer_tokens=result.get("summarizer_tokens", 0),
            tokens_source=result.get("tokens_source", "estimate"),
            llm_calls=result.get("llm_calls", 0),
            leaked=leaked,
            archetype=scenario.get("archetype"),
            input_tokens=result.get("agent_input_tokens", 0),
            output_tokens=result.get("agent_output_tokens", 0),
        ))
        checkpoint_results(all_results, summaries)
        if MAX_COST_USD is not None and SPENT_USD >= MAX_COST_USD:
            raise BudgetExceeded(f"spent ${SPENT_USD:.2f} >= cap ${MAX_COST_USD:.2f}")

    # Keep every rolling summary this chain produced, so a failure can be traced
    # to what the summarizer wrote (the original run did not save these).
    if summaries is not None and context_manager.summary_log:
        summaries.append({
            "mode": mode, "run": run_number,
            "chain": [s["id"] for s in chain],
            "summaries": context_manager.summary_log,
        })


# ──────────────────────────────────────────────────────────────
# RUN ALL CHAINS IN ONE MODE
# ──────────────────────────────────────────────────────────────

async def run_mode(chains: list[list[dict]], mode: str, all_results: list, summaries: list = None) -> None:
    """
    Runs every chain through one context mode, RUNS_PER_CHAIN times each.
    Each repeat of a chain starts from a fresh ContextManager (via
    run_chain), so repeats are independent of each other; history only
    accumulates *within* a single chain run, across its scenarios.

    WHY NOT RUN IN PARALLEL?
    Parallel runs would be faster but could hit OpenAI rate limits.
    Sequential is safer and results are cleaner.
    In production you'd add rate limiting and run in parallel.
    """
    print(f"\n{'='*60}")
    print(f"MODE: {mode.upper()}")
    print(f"{'='*60}")

    for chain_idx, chain in enumerate(chains, start=1):
        chain_ids = " -> ".join(s["id"] for s in chain)
        print(f"\nChain {chain_idx}: {chain_ids}")

        for run_num in range(1, RUNS_PER_CHAIN + 1):
            await run_chain(chain, mode, run_num, all_results, summaries)

            # Small delay between chain repeats to avoid rate limiting
            if run_num < RUNS_PER_CHAIN:
                await asyncio.sleep(1)

        # Delay between chains
        await asyncio.sleep(2)


# ──────────────────────────────────────────────────────────────
# COMPUTE METRICS
# ──────────────────────────────────────────────────────────────

def compute_metrics(results: list[RunResult], mode: str) -> dict:
    """
    Aggregates all RunResults for one mode into summary metrics.

    WHY AVERAGE ACROSS RUNS?
    A single run could be an outlier. Averaging 3 runs
    gives a more reliable picture of typical performance.
    """
    mode_results = [r for r in results if r.mode == mode]

    if not mode_results:
        return {}

    total = len(mode_results)
    correct = sum(1 for r in mode_results if r.correct)
    accuracy = (correct / total) * 100

    avg_tokens = sum(r.tokens for r in mode_results) / total
    avg_duration = sum(r.duration for r in mode_results) / total
    avg_tool_calls = sum(r.tool_calls for r in mode_results) / total
    avg_input_tokens = sum(r.input_tokens for r in mode_results) / total
    avg_summarizer_tokens = sum(r.summarizer_tokens for r in mode_results) / total

    # Per-scenario breakdown
    scenario_ids = list(dict.fromkeys(r.scenario_id for r in mode_results))
    per_scenario = {}
    for sid in scenario_ids:
        s_results = [r for r in mode_results if r.scenario_id == sid]
        s_correct = sum(1 for r in s_results if r.correct)
        per_scenario[sid] = {
            "correct": s_correct,
            "total": len(s_results),
            "verdicts": [r.verdict for r in s_results]
        }

    return {
        "mode": mode,
        "total_runs": total,
        "correct_runs": correct,
        "accuracy": accuracy,
        "avg_tokens": avg_tokens,
        "avg_duration": avg_duration,
        "avg_tool_calls": avg_tool_calls,
        "avg_input_tokens": avg_input_tokens,
        "avg_summarizer_tokens": avg_summarizer_tokens,
        "per_scenario": per_scenario
    }


# ──────────────────────────────────────────────────────────────
# PRINT RESULTS TABLE
# ──────────────────────────────────────────────────────────────

def print_results(metrics_by_mode: dict, scenarios: list[dict], chains: list[list[dict]]):
    """Prints the comparison table for however many modes were run."""
    modes = list(metrics_by_mode)
    print(f"\n{'='*60}")
    print("BENCHMARK RESULTS")
    print(f"{'='*60}")
    print(f"Scenarios: {len(scenarios)} | Chains: {len(chains)} | Runs per chain per mode: {RUNS_PER_CHAIN}")
    print()

    col_w = 20
    print(f"{'Metric':<25}" + "".join(f"{m.upper():>{col_w}}" for m in modes))
    print("-" * (25 + col_w * len(modes)))

    def row(label, key, fmt, suffix=""):
        cells = "".join(f"{metrics_by_mode[m][key]:{fmt}}{suffix}".rjust(col_w) for m in modes)
        print(f"{'  ' + label:<25}{cells}")

    row("Verdict Accuracy", "accuracy", ".1f", "%")
    row("Avg Tokens", "avg_tokens", ".0f")
    row("Avg Latency (s)", "avg_duration", ".2f")
    row("Avg Tool Calls", "avg_tool_calls", ".1f")
    row("  of which prompt tokens", "avg_input_tokens", ".0f")
    row("  of which summarizer", "avg_summarizer_tokens", ".0f")

    print(f"\n{'─'*60}\nPer-scenario correct runs:\n{'─'*60}")
    print(f"  {'ID':<8} {'Truth':<11}" + "".join(f"{m[:14]:>16}" for m in modes))
    for sc in scenarios:
        cells = ""
        for m in modes:
            ps = metrics_by_mode[m]["per_scenario"].get(sc["id"], {})
            cells += f"{ps.get('correct', 0)}/{ps.get('total', 0)}".rjust(16)
        print(f"  {sc['id']:<8} {sc['ground_truth']:<11}{cells}")

    base = metrics_by_mode.get("full")
    if base:
        print(f"\n{'='*60}\nVS FULL HISTORY (point estimates only - run analyze.py for CIs and McNemar)\n{'='*60}")
        for m in modes:
            if m == "full":
                continue
            d = metrics_by_mode[m]["accuracy"] - base["accuracy"]
            print(f"  {m}: accuracy {d:+.1f} pts, tokens {metrics_by_mode[m]['avg_tokens'] - base['avg_tokens']:+.0f}")
        print("  Do not read a conclusion from these alone: at this sample size the gap may be noise.")


# ──────────────────────────────────────────────────────────────
# SAVE RAW RESULTS
# ──────────────────────────────────────────────────────────────

def _serialize_raw(all_results: list[RunResult]) -> list[dict]:
    return [
        {
            "scenario_id": r.scenario_id,
            "mode": r.mode,
            "run": r.run_number,
            "verdict": r.verdict,
            "ground_truth": r.ground_truth,
            "correct": r.correct,
            "tokens": r.tokens,
            "duration": r.duration,
            "tool_calls": r.tool_calls,
            "history_pairs_at_call": r.history_pairs_at_call,
            "agent_tokens": r.agent_tokens,
            "summarizer_tokens": r.summarizer_tokens,
            "tokens_source": r.tokens_source,
            "llm_calls": r.llm_calls,
            "leaked": r.leaked,
            "archetype": r.archetype,
            "input_tokens": r.input_tokens,
            "output_tokens": r.output_tokens,
        }
        for r in all_results
    ]


def _config() -> dict:
    import llm as llm_factory
    return {
        "runs_per_chain": RUNS_PER_CHAIN,
        "window_size": WINDOW_SIZE,
        "modes": MODES,
        "provider": llm_factory.provider(),
        "model": llm_factory.agent_model_name(),
        "summarizer_model": llm_factory.summarizer_model_name(),
        "prompt_version": os.getenv("PROMPT_VERSION", "v1"),
        "summary_prompt": SUMMARY_PROMPT,
        "include_reports": INCLUDE_REPORTS,
        "history_format": HISTORY_FORMAT,
        "long_chain": LONG_CHAIN,
        "scenarios_file": str(SCENARIOS_FILE),
        "max_cost_usd": MAX_COST_USD,
        "spent_usd_estimate": round(SPENT_USD, 4),
    }


def _write(status: str, all_results, metrics=None, summaries=None):
    output = {
        "status": status,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": _config(),
        "raw_results": _serialize_raw(all_results),
        "summaries": summaries or [],
    }
    if metrics is not None:
        output["summary"] = metrics
    with open(RESULTS_FILE, "w") as f:
        json.dump(output, f, indent=2)


def save_results(all_results: list[RunResult], metrics_by_mode: dict, summaries: list = None):
    """Final write (status="complete"), with per-mode summary metrics."""
    _write("complete", all_results, metrics_by_mode, summaries)
    print(f"\n  Raw results saved to {RESULTS_FILE}")
    print(f"  Next: python analyze.py {RESULTS_FILE}")


def checkpoint_results(all_results: list[RunResult], summaries: list = None):
    """Written after every single run so a crash (e.g. a rate limit that outlasts
    the client's retries) doesn't lose completed work."""
    _write("in_progress", all_results, None, summaries)


# ──────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────

async def main():
    print("Context-Aware MCP — Benchmark Runner")
    print("="*60)
    print(f"Runs per chain per mode: {RUNS_PER_CHAIN}")
    print(f"Context modes: {', '.join(MODES)}")
    print()

    import llm as llm_factory
    key_var = "OPENAI_API_KEY" if llm_factory.provider() == "openai" else "ANTHROPIC_API_KEY"
    if not os.getenv(key_var) or os.getenv(key_var).startswith("sk-your"):
        print(f"ERROR: set {key_var} in .env before running the benchmark")
        return

    scenarios = load_scenarios()
    chains = build_chains(scenarios)
    print(f"Grouped {len(scenarios)} scenarios into {len(chains)} chain(s):")
    for i, chain in enumerate(chains, start=1):
        print(f"  Chain {i}: {' -> '.join(s['id'] for s in chain)}")

    all_results, summaries = [], []
    try:
        for mode in MODES:
            await run_mode(chains, mode, all_results, summaries)
    except BudgetExceeded as e:
        print(f"\n💰 Stopped by budget guard: {e}. {len(all_results)} run(s) checkpointed to {RESULTS_FILE}.")
        return
    except Exception as e:
        traceback.print_exc()
        print(f"\n⚠️  Benchmark interrupted: {e!r}")
        print(f"   {len(all_results)} run(s) completed and checkpointed to {RESULTS_FILE}.")
        print("   Re-run to continue collecting data (note: this restarts from scratch, it does not resume).")
        return

    metrics = {m: compute_metrics(all_results, m) for m in MODES}
    print_results(metrics, scenarios, chains)
    save_results(all_results, metrics, summaries)


if __name__ == "__main__":
    asyncio.run(main())
