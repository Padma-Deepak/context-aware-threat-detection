"""Analyse ExCyTIn benchmark results: accuracy, paired tests, memory effects, cost, conformal escalation.

    python -m triage.excytin.analyze results/excytin/main.jsonl [--baseline none] [--md report.md]

Statistics reuse the v1 benchmark's helpers (agent/analyze.py): a cluster bootstrap that resamples
questions (repeats of one question are not independent) and an exact McNemar test on paired runs.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from triage.conformal import agreement_scores, split_evaluation


def _v1_stats():
    """The v1 benchmark's statistics module (agent/analyze.py), loaded by path: 'agent' is both a folder
    and, on some sys.paths, the module agent/agent.py."""
    import importlib.util

    path = Path(__file__).resolve().parents[2] / "agent" / "analyze.py"
    spec = importlib.util.spec_from_file_location("v1_analyze", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_v1 = _v1_stats()
cluster_bootstrap_ci, paired_report = _v1.cluster_bootstrap_ci, _v1.paired_report


def load(path) -> list[dict]:
    """Read a results file. Runs made with ``--schema full`` get their mode suffixed ``+schema`` so they can sit
    beside the same mode without the schema (same question ids, so they pair)."""
    runs = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    for r in runs:
        if r.get("schema", "off") != "off" and not r["mode"].endswith("+schema"):
            r["mode"] = f"{r['mode']}+schema"
    return runs


def sql_error_rate(rs: list[dict]):
    """Share of run_sql calls that failed, from recorded counts or (older files) from saved tool calls."""
    calls = errors = 0
    for r in rs:
        if r.get("sql_calls") is not None:
            calls += r["sql_calls"]
            errors += r.get("sql_errors", 0)
        elif r.get("tool_calls"):
            sql = [c for c in r["tool_calls"] if c["tool"] == "run_sql"]
            calls += len(sql)
            errors += sum(c["output"].startswith("SQL error") for c in sql)
    return errors / calls if calls else None


def _mean(v):
    return sum(v) / len(v) if v else 0.0


def summarise(runs: list[dict], baseline: str = "none") -> dict:
    by_mode = defaultdict(list)
    for r in runs:
        by_mode[r["mode"]].append(r)
    out = {"modes": {}, "paired": {}, "position": {}, "incident": {}, "conformal": {}, "injection": {}}
    for mode, rs in sorted(by_mode.items()):
        lo, hi = cluster_bootstrap_ci(rs, resamples=2000)
        out["modes"][mode] = {
            "n": len(rs), "accuracy": _mean([r["correct"] for r in rs]), "ci": (lo, hi),
            "avg_steps": _mean([r["steps"] for r in rs]),
            "avg_input_tokens": _mean([r["input_tokens"] for r in rs]),
            "avg_output_tokens": _mean([r["output_tokens"] for r in rs]),
            "cost_usd": sum(r["cost_usd"] for r in rs),
            "avg_seconds": _mean([r["wall_seconds"] for r in rs]),
            "recall_rate": _mean([r.get("recall_calls", 0) > 0 for r in rs]),
            "no_submit_rate": _mean([r.get("fallback") is not None for r in rs]),
            "error_rate": _mean([bool(r.get("error")) for r in rs]),
            "citation_valid_rate": _mean([bool(r.get("citations_valid")) for r in rs]),
            "judge_share": _mean([r.get("grade_method") == "judge" for r in rs]),
            "sql_error_rate": sql_error_rate(rs),
        }
        # Does memory help later questions more? Compare the first and second half of each chain.
        halves = defaultdict(list)
        for r in rs:
            n_in_chain = sum(1 for x in rs if x["incident"] == r["incident"] and x["run"] == r["run"])
            halves["early" if r["position"] < n_in_chain / 2 else "late"].append(r["correct"])
        out["position"][mode] = {k: (_mean(v), len(v)) for k, v in halves.items()}
        inc = defaultdict(list)
        for r in rs:
            inc[r["incident"]].append(r["correct"])
        out["incident"][mode] = {k: (_mean(v), len(v)) for k, v in sorted(inc.items())}
        conf = [r for r in rs if r.get("confidence") is not None and not r.get("error")]
        if len(conf) >= 20:
            entry = {"confidence": [split_evaluation([r["confidence"] / 100 for r in conf],
                                                     [r["correct"] for r in conf],
                                                     [r["scenario_id"] for r in conf], alpha=a)
                                    for a in (0.05, 0.10, 0.20)]}
            if len({r["run"] for r in conf}) >= 3:
                agree = agreement_scores(conf)
                entry["agreement"] = [split_evaluation(agree, [r["correct"] for r in conf],
                                                       [r["scenario_id"] for r in conf], alpha=a)
                                      for a in (0.05, 0.10, 0.20)]
            out["conformal"][mode] = entry
        inj = [r for r in rs if r.get("injected")]
        if inj:
            out["injection"][mode] = {"n": len(inj), "attack_success_rate": _mean([r["injection_success"] for r in inj]),
                                      "accuracy_under_attack": _mean([r["correct"] for r in inj])}
    if baseline in by_mode:
        for mode in by_mode:
            if mode != baseline:
                out["paired"][mode] = paired_report(runs, baseline, mode, resamples=2000)
    out["schema_effect"] = {}
    for mode in by_mode:
        if not mode.endswith("+schema") and f"{mode}+schema" in by_mode:
            out["schema_effect"][mode] = paired_report(runs, mode, f"{mode}+schema", resamples=2000)
    return out


def format_report(s: dict, baseline: str = "none") -> str:
    pct = lambda x: f"{x:.1%}"  # noqa: E731
    lines = ["## Accuracy by memory mode", "",
             "| Mode | n | Accuracy (95% CI) | Steps | Input tok | Cost | Sec | Used recall | No submit | Valid citations | SQL errors |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for m, d in s["modes"].items():
        lines.append(f"| {m} | {d['n']} | {pct(d['accuracy'])} ({pct(d['ci'][0])}–{pct(d['ci'][1])}) | "
                     f"{d['avg_steps']:.1f} | {d['avg_input_tokens']:.0f} | ${d['cost_usd']:.2f} | "
                     f"{d['avg_seconds']:.0f} | {pct(d['recall_rate'])} | {pct(d['no_submit_rate'])} | "
                     f"{pct(d['citation_valid_rate'])} | "
                     f"{pct(d['sql_error_rate']) if d.get('sql_error_rate') is not None else 'n/a'} |")
    if s["paired"]:
        lines += ["", f"## Paired comparison against `{baseline}`", "",
                  "| Mode | Pairs | Difference (95% CI) | Only baseline right | Only this right | McNemar p |",
                  "|---|---|---|---|---|---|"]
        for m, p in s["paired"].items():
            if p:
                lines.append(f"| {m} | {p['n_pairs']} | {p['diff']:+.1%} ({p['diff_ci'][0]:+.1%} to "
                             f"{p['diff_ci'][1]:+.1%}) | {p['baseline_only_correct']} | {p['other_only_correct']} | "
                             f"{p['mcnemar_p']:.3f} |")
        lines.append("\nCall a difference real only if its CI excludes 0.")
    if s.get("schema_effect"):
        lines += ["", "## Effect of giving the agent the schema up front", "",
                  "Same questions, same mode, with vs without every table's exact column names.", "",
                  "| Mode | Pairs | Change with schema (95% CI) | Only without right | Only with right | McNemar p |",
                  "|---|---|---|---|---|---|"]
        for m, p in s["schema_effect"].items():
            if p:
                lines.append(f"| {m} | {p['n_pairs']} | {p['diff']:+.1%} ({p['diff_ci'][0]:+.1%} to "
                             f"{p['diff_ci'][1]:+.1%}) | {p['baseline_only_correct']} | {p['other_only_correct']} | "
                             f"{p['mcnemar_p']:.3f} |")
    lines += ["", "## Early vs late questions in each incident", "",
              "Memory can only help questions that come after others in the same incident.", "",
              "| Mode | Early half | Late half |", "|---|---|---|"]
    for m, d in s["position"].items():
        e, late = d.get("early", (0, 0)), d.get("late", (0, 0))
        lines.append(f"| {m} | {pct(e[0])} (n={e[1]}) | {pct(late[0])} (n={late[1]}) |")
    if s["conformal"]:
        lines += ["", "## Conformal escalation (random 50/50 question splits)", "",
                  "| Mode | Score | Target error | Auto-answered | Error on auto-answered | Splits over target |",
                  "|---|---|---|---|---|---|"]
        for m, entry in s["conformal"].items():
            for score, rows in entry.items():
                for e in rows:
                    if e:
                        lines.append(f"| {m} | {score} | {pct(e['alpha'])} | {pct(e['coverage_mean'])} | "
                                     f"{pct(e['selective_error_mean'])} | {pct(e['violation_rate'])} |")
    if s["injection"]:
        lines += ["", "## Prompt injection", "", "| Mode | n | Attack success | Accuracy under attack |",
                  "|---|---|---|---|"]
        for m, d in s["injection"].items():
            lines.append(f"| {m} | {d['n']} | {pct(d['attack_success_rate'])} | {pct(d['accuracy_under_attack'])} |")
    lines += ["", "## Accuracy by incident", "", "| Mode | " + " | ".join(
        f"#{k}" for k in next(iter(s["incident"].values()), {})) + " |"]
    lines.append("|---|" + "---|" * len(next(iter(s["incident"].values()), {})))
    for m, d in s["incident"].items():
        lines.append(f"| {m} | " + " | ".join(f"{a:.0%} ({n})" for a, n in d.values()) + " |")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+")
    ap.add_argument("--baseline", default="none")
    ap.add_argument("--md", type=Path, help="also write the report here")
    args = ap.parse_args(argv)
    runs = [r for p in args.results for r in load(p)]
    report = format_report(summarise(runs, args.baseline), args.baseline)
    print(report)
    if args.md:
        args.md.write_text(report)


if __name__ == "__main__":
    main()
