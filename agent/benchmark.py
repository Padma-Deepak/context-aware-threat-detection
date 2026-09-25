# benchmark.py
#
# Person B's third deliverable.
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
from pathlib import Path
from dotenv import load_dotenv

from agent import InvestigationAgent
from context_manager import ContextManager

load_dotenv()

# ──────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────

RUNS_PER_CHAIN = 3          # how many times to run each chain per mode.
WINDOW_SIZE = 2              # lowered from 5: real scenarios cap at 4 tool
                             # calls, so window_size=5 never triggered summarization
SCENARIOS_FILE = Path(__file__).parent.parent / "scenarios.json"

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

# Fallback scenarios if scenarios.json doesn't exist yet
# (so you can test benchmark.py before Padma finishes scenarios.json)
FALLBACK_SCENARIOS = [
    {
        "id": "s01",
        "task": "Determine whether the IP 185.220.101.5 is malicious. Investigate thoroughly.",
        "ground_truth": "MALICIOUS"
    },
    {
        "id": "s02",
        "task": "Check if 8.8.8.8 poses any security threat to our network.",
        "ground_truth": "BENIGN"
    },
    {
        "id": "s03",
        "task": "Investigate 185.220.101.5. Cross-reference with domain malware-drop.xyz. Assess combined risk.",
        "ground_truth": "MALICIOUS"
    }
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
                 history_pairs_at_call):
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
    Loads scenarios from scenarios.json (Padma's file).
    Falls back to hardcoded scenarios if file doesn't exist.

    WHY FALLBACK?
    So you can run and test benchmark.py right now,
    before Padma has finished writing scenarios.json.
    When she's done, drop scenarios.json in the repo root
    and the fallback is never used.
    """
    if SCENARIOS_FILE.exists():
        with open(SCENARIOS_FILE) as f:
            scenarios = json.load(f)
        print(f"Loaded {len(scenarios)} scenarios from {SCENARIOS_FILE}")
        return scenarios
    else:
        print(f"scenarios.json not found at {SCENARIOS_FILE}")
        print(f"Using {len(FALLBACK_SCENARIOS)} fallback scenarios for testing")
        return FALLBACK_SCENARIOS


# ──────────────────────────────────────────────────────────────
# BUILD CHAINS
# ──────────────────────────────────────────────────────────────

def build_chains(scenarios: list[dict]) -> list[list[dict]]:
    """
    Groups scenarios into chains that will share one ContextManager.

    If the loaded scenarios match CHAIN_SCENARIO_IDS exactly (the real
    18-scenario file), use that hand-picked grouping. Otherwise (e.g. the
    3-scenario FALLBACK_SCENARIOS, which don't have S01-style ids) degrade
    to a single chain containing everything, in file order — still
    exercises the shared-ContextManager chaining, just without the
    hand-picked entity pairing.
    """
    by_id = {s["id"]: s for s in scenarios}
    ids_needed = [sid for group in CHAIN_SCENARIO_IDS for sid in group]

    if all(sid in by_id for sid in ids_needed):
        return [[by_id[sid] for sid in group] for group in CHAIN_SCENARIO_IDS]

    return [scenarios]


# ──────────────────────────────────────────────────────────────
# RUN ONE CHAIN IN ONE MODE
# ──────────────────────────────────────────────────────────────

async def run_chain(chain: list[dict], mode: str, run_number: int, all_results: list) -> None:
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
    context_manager = ContextManager(mode=mode, window_size=WINDOW_SIZE)
    agent = InvestigationAgent(context_manager=context_manager)

    for position, scenario in enumerate(chain, start=1):
        # Snapshot BEFORE investigate() calls context_manager.update() --
        # this is how much accumulated history the agent actually saw.
        history_pairs_at_call = len(context_manager.all_steps)

        print(f"  [{mode}] run {run_number}/{RUNS_PER_CHAIN}: "
              f"{scenario['id']} (turn {position}/{len(chain)}, "
              f"history_pairs={history_pairs_at_call})...", end=" ", flush=True)

        result = await agent.investigate(scenario["task"])

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
            history_pairs_at_call=history_pairs_at_call
        ))
        checkpoint_results(all_results)


# ──────────────────────────────────────────────────────────────
# RUN ALL CHAINS IN ONE MODE
# ──────────────────────────────────────────────────────────────

async def run_mode(chains: list[list[dict]], mode: str, all_results: list) -> None:
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
            await run_chain(chain, mode, run_num, all_results)

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
        "per_scenario": per_scenario
    }


# ──────────────────────────────────────────────────────────────
# PRINT RESULTS TABLE
# ──────────────────────────────────────────────────────────────

def print_results(full_metrics: dict, windowed_metrics: dict, scenarios: list[dict], chains: list[list[dict]]):
    """
    Prints the final comparison table.
    This is the deliverable — what we show in the project demo.
    """
    print(f"\n{'='*60}")
    print("BENCHMARK RESULTS")
    print(f"{'='*60}")
    print(f"Scenarios: {len(scenarios)} | Chains: {len(chains)} | Runs per chain per mode: {RUNS_PER_CHAIN}")
    print()

    # Main comparison table
    col_w = 20
    print(f"{'Metric':<25} {'FULL_HISTORY':>{col_w}} {'WINDOWED_SUMMARY':>{col_w}}")
    print("-" * (25 + col_w * 2 + 2))

    def row(label, full_val, wind_val, fmt=".1f", suffix=""):
        fv = f"{full_val:{fmt}}{suffix}"
        wv = f"{wind_val:{fmt}}{suffix}"
        # Mark if windowed is better
        better = ""
        if isinstance(full_val, float) and isinstance(wind_val, float):
            if label == "Verdict Accuracy":
                better = " ✓" if wind_val >= full_val else " ✗"
            elif label in ("Avg Tokens", "Avg Latency (s)"):
                better = " ✓" if wind_val < full_val else ""
        print(f"{'  ' + label:<25} {fv:>{col_w}} {wv + better:>{col_w}}")

    row("Verdict Accuracy",
        full_metrics["accuracy"], windowed_metrics["accuracy"],
        fmt=".1f", suffix="%")
    row("Avg Tokens",
        full_metrics["avg_tokens"], windowed_metrics["avg_tokens"],
        fmt=".0f")
    row("Avg Latency (s)",
        full_metrics["avg_duration"], windowed_metrics["avg_duration"],
        fmt=".2f")
    row("Avg Tool Calls",
        full_metrics["avg_tool_calls"], windowed_metrics["avg_tool_calls"],
        fmt=".1f")

    # Token savings
    if full_metrics["avg_tokens"] > 0:
        token_reduction = (
            (full_metrics["avg_tokens"] - windowed_metrics["avg_tokens"])
            / full_metrics["avg_tokens"] * 100
        )
        print()
        print(f"  Token reduction:    {token_reduction:+.1f}%")

    # Per-scenario breakdown
    print(f"\n{'─'*60}")
    print("Per-scenario breakdown:")
    print(f"{'─'*60}")
    print(f"  {'ID':<8} {'Ground Truth':<15} {'Full':^12} {'Windowed':^12}")
    print(f"  {'-'*7} {'-'*14} {'-'*12} {'-'*12}")

    for scenario in scenarios:
        sid = scenario["id"]
        gt = scenario["ground_truth"]
        f_ps = full_metrics["per_scenario"].get(sid, {})
        w_ps = windowed_metrics["per_scenario"].get(sid, {})

        f_str = f"{f_ps.get('correct',0)}/{f_ps.get('total',0)} correct"
        w_str = f"{w_ps.get('correct',0)}/{w_ps.get('total',0)} correct"

        print(f"  {sid:<8} {gt:<15} {f_str:^12} {w_str:^12}")

    # Verdict
    print(f"\n{'='*60}")
    print("CONCLUSION")
    print(f"{'='*60}")

    accuracy_ok = windowed_metrics["accuracy"] >= full_metrics["accuracy"]
    token_ok = windowed_metrics["avg_tokens"] < full_metrics["avg_tokens"]
    speed_ok = windowed_metrics["avg_duration"] < full_metrics["avg_duration"]

    if accuracy_ok and (token_ok or speed_ok):
        print("  ✓ Windowed+summary matches or beats full history on accuracy")
        if token_ok:
            print(f"  ✓ Uses fewer tokens ({token_reduction:.1f}% reduction)")
        if speed_ok:
            savings = full_metrics['avg_duration'] - windowed_metrics['avg_duration']
            print(f"  ✓ Faster ({savings:.2f}s per investigation)")
        print("\n  RESULT: Context compression is EFFECTIVE for this workload.")
    elif not accuracy_ok:
        drop = full_metrics["accuracy"] - windowed_metrics["accuracy"]
        print(f"  ✗ Windowed+summary accuracy dropped by {drop:.1f}%")
        print("  RESULT: Context compression DEGRADED accuracy — not safe for this workload.")
        print("  Investigate: which scenarios failed? What evidence was lost in the summary?")
    else:
        print("  ~ Accuracy held but no meaningful efficiency gain.")
        print("  RESULT: INCONCLUSIVE — consider increasing window size or scenario complexity.")


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
            "history_pairs_at_call": r.history_pairs_at_call
        }
        for r in all_results
    ]


def save_results(all_results: list[RunResult], full_metrics: dict, windowed_metrics: dict):
    """
    Saves raw results to benchmark_results.json.
    Useful for analysis, charts, and the project report.
    """
    output = {
        "status": "complete",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {
            "runs_per_chain": RUNS_PER_CHAIN,
            "window_size": WINDOW_SIZE,
            "model": os.getenv("OPENAI_MODEL", "gpt-4o")
        },
        "summary": {
            "full_history": full_metrics,
            "windowed_summary": windowed_metrics
        },
        "raw_results": _serialize_raw(all_results)
    }

    output_path = Path(__file__).parent / "benchmark_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Raw results saved to {output_path}")


def checkpoint_results(all_results: list[RunResult]):
    """
    Writes progress so far to benchmark_results.json after every single run.

    WHY? A crash (e.g. an OpenAI rate limit that outlasts the client's own
    retries) partway through a long benchmark used to lose every completed
    run, since save_results() only ran once at the very end. Checkpointing
    means the file always reflects the latest known progress; save_results()
    overwrites it with status="complete" and full metrics once everything
    finishes.
    """
    output = {
        "status": "in_progress",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {
            "runs_per_chain": RUNS_PER_CHAIN,
            "window_size": WINDOW_SIZE,
            "model": os.getenv("OPENAI_MODEL", "gpt-4o")
        },
        "raw_results": _serialize_raw(all_results)
    }

    output_path = Path(__file__).parent / "benchmark_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)


# ──────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────

async def main():
    print("Context-Aware MCP — Benchmark Runner")
    print("="*60)
    print(f"Runs per chain per mode: {RUNS_PER_CHAIN}")
    print(f"Context modes: full_history vs windowed_summary")
    print()

    # Check API key
    if not os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY") == "sk-your-key-here":
        print("ERROR: Set OPENAI_API_KEY in .env before running benchmark")
        return

    # Load scenarios and group them into chains that will share a
    # ContextManager (see build_chains() for the grouping rationale).
    scenarios = load_scenarios()
    chains = build_chains(scenarios)
    print(f"Grouped {len(scenarios)} scenarios into {len(chains)} chain(s):")
    for i, chain in enumerate(chains, start=1):
        print(f"  Chain {i}: {' -> '.join(s['id'] for s in chain)}")

    # Run both modes. all_results is mutated in place by run_mode and
    # checkpointed to disk after every run, so if this gets interrupted
    # (e.g. a rate limit that outlasts the client's own retries), whatever
    # completed so far is still on disk in benchmark_results.json.
    all_results = []

    try:
        await run_mode(chains, "full", all_results)
        await run_mode(chains, "windowed_summary", all_results)
    except Exception as e:
        print(f"\n⚠️  Benchmark interrupted: {e}")
        print(f"   {len(all_results)} run(s) completed and checkpointed to benchmark_results.json.")
        print("   Re-run to continue collecting data (note: this restarts from scratch, it does not resume).")
        return

    # Compute metrics
    full_metrics = compute_metrics(all_results, "full")
    windowed_metrics = compute_metrics(all_results, "windowed_summary")

    # Print results table
    print_results(full_metrics, windowed_metrics, scenarios, chains)

    # Save raw results (overwrites the in-progress checkpoint with status="complete")
    save_results(all_results, full_metrics, windowed_metrics)


if __name__ == "__main__":
    asyncio.run(main())