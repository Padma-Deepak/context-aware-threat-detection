"""Statistical analysis and error taxonomy for benchmark result files.

Reads the JSON written by benchmark.py (``raw_results`` list) and reports, per
context mode:

  * accuracy with a *cluster* bootstrap 95% CI (resampling whole scenarios,
    because the repeats of one scenario are not independent samples),
  * a paired comparison against a baseline mode: exact McNemar test on
    discordant (scenario, run) pairs, plus a cluster-bootstrap CI on the
    accuracy difference,
  * a confusion matrix and a failure taxonomy (what kind of mistake, not just
    how many).

Usage:
    python analyze.py benchmark_results_holdout.json
    python analyze.py results.json --baseline full --seed 7 --resamples 10000

Pure standard library so it runs anywhere (including CI) without the LLM stack.
"""

import argparse
import json
import random
from collections import Counter, defaultdict
from math import comb

VERDICTS = ["MALICIOUS", "BENIGN", "ESCALATE", "UNKNOWN"]


def load_runs(path):
    with open(path) as f:
        data = json.load(f)
    runs = data["raw_results"] if isinstance(data, dict) else data
    if not runs:
        raise ValueError(f"{path} contains no runs")
    return runs


def accuracy(runs):
    return sum(1 for r in runs if r["correct"]) / len(runs) if runs else float("nan")


def _group_by_scenario(runs):
    groups = defaultdict(list)
    for r in runs:
        groups[r["scenario_id"]].append(r)
    return groups


def _percentile(sorted_vals, q):
    if not sorted_vals:
        return float("nan")
    idx = q * (len(sorted_vals) - 1)
    lo, hi = int(idx), min(int(idx) + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (idx - lo)


def cluster_bootstrap_ci(runs, resamples=5000, seed=0, alpha=0.05):
    """95% CI for accuracy, resampling scenarios (clusters) with replacement."""
    groups = list(_group_by_scenario(runs).values())
    rng = random.Random(seed)
    stats = []
    for _ in range(resamples):
        sample = [rng.choice(groups) for _ in groups]
        n = sum(len(g) for g in sample)
        stats.append(sum(r["correct"] for g in sample for r in g) / n)
    stats.sort()
    return _percentile(stats, alpha / 2), _percentile(stats, 1 - alpha / 2)


def mcnemar_exact(b, c):
    """Exact two-sided McNemar p-value from discordant counts.

    b = baseline correct & other wrong, c = baseline wrong & other correct.
    Under H0 the discordant pairs split 50/50 (binomial with p=0.5).
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = 2 * sum(comb(n, i) for i in range(k + 1)) / (2**n)
    return min(1.0, p)


def paired_runs(runs, baseline, other):
    """Pair runs of two modes on (scenario_id, run). Returns list of (a, b) dicts."""
    idx = {}
    for r in runs:
        idx[(r["mode"], r["scenario_id"], r["run"])] = r
    pairs = []
    for (mode, sid, run), r in idx.items():
        if mode != baseline:
            continue
        o = idx.get((other, sid, run))
        if o is not None:
            pairs.append((r, o))
    return pairs


def paired_report(runs, baseline, other, resamples=5000, seed=0):
    pairs = paired_runs(runs, baseline, other)
    if not pairs:
        return None
    b = sum(1 for a, o in pairs if a["correct"] and not o["correct"])
    c = sum(1 for a, o in pairs if not a["correct"] and o["correct"])
    diff = (sum(o["correct"] for _, o in pairs) - sum(a["correct"] for a, _ in pairs)) / len(pairs)

    by_scn = defaultdict(list)
    for a, o in pairs:
        by_scn[a["scenario_id"]].append(int(o["correct"]) - int(a["correct"]))
    clusters = list(by_scn.values())
    rng = random.Random(seed)
    boots = []
    for _ in range(resamples):
        sample = [rng.choice(clusters) for _ in clusters]
        n = sum(len(g) for g in sample)
        boots.append(sum(sum(g) for g in sample) / n)
    boots.sort()
    return {
        "n_pairs": len(pairs),
        "baseline_only_correct": b,
        "other_only_correct": c,
        "diff": diff,
        "diff_ci": (_percentile(boots, 0.025), _percentile(boots, 0.975)),
        "mcnemar_p": mcnemar_exact(b, c),
    }


def confusion(runs):
    m = defaultdict(Counter)
    for r in runs:
        m[r["ground_truth"]][r["verdict"]] += 1
    return m


def classify_error(truth, verdict):
    """Map a wrong (truth, verdict) pair to a named failure category."""
    if truth == verdict:
        return None
    if verdict == "UNKNOWN":
        return "no_verdict"
    if truth == "MALICIOUS":
        return "missed_threat"  # said BENIGN or ESCALATE on a real threat
    if truth == "BENIGN":
        return "false_positive" if verdict == "MALICIOUS" else "over_escalation"
    if truth == "ESCALATE":
        return "overconfident_malicious" if verdict == "MALICIOUS" else "overconfident_benign"
    return "other"


def taxonomy(runs):
    counts = Counter()
    per_scenario = defaultdict(Counter)
    for r in runs:
        cat = classify_error(r["ground_truth"], r["verdict"])
        if cat:
            counts[cat] += 1
            per_scenario[r["scenario_id"]][cat] += 1
    return counts, per_scenario


def by_archetype(runs):
    """Accuracy per scenario archetype (generated sets only)."""
    groups = defaultdict(list)
    for r in runs:
        if r.get("archetype"):
            groups[r["archetype"]].append(r)
    return {k: (sum(x["correct"] for x in v), len(v)) for k, v in sorted(groups.items())}


def compare_files(runs_a, runs_b, mode, resamples=5000, seed=0):
    """Paired comparison of the SAME mode across two result files (e.g. prompt v1 vs v2,
    or model X vs model Y). Runs are paired on (scenario_id, run)."""
    tagged = [dict(r, mode="A") for r in runs_a if r["mode"] == mode] + [
        dict(r, mode="B") for r in runs_b if r["mode"] == mode
    ]
    return paired_report(tagged, "A", "B", resamples, seed)


def analyze(runs, baseline="full", resamples=5000, seed=0):
    modes = list(dict.fromkeys(r["mode"] for r in runs))
    out = {"modes": {}, "paired": {}}
    for m in modes:
        mr = [r for r in runs if r["mode"] == m]
        lo, hi = cluster_bootstrap_ci(mr, resamples, seed)
        counts, per_scn = taxonomy(mr)
        out["modes"][m] = {
            "n": len(mr),
            "correct": sum(r["correct"] for r in mr),
            "accuracy": accuracy(mr),
            "ci95": (lo, hi),
            "confusion": {t: dict(c) for t, c in confusion(mr).items()},
            "taxonomy": dict(counts),
            "taxonomy_by_scenario": {s: dict(c) for s, c in per_scn.items()},
            "leaks": sum(1 for r in mr if r.get("leaked")),
            "by_archetype": by_archetype(mr),
            "avg_tokens": sum(r["tokens"] for r in mr) / len(mr),
            "avg_duration": sum(r["duration"] for r in mr) / len(mr),
        }
    if baseline in modes:
        for m in modes:
            if m != baseline:
                out["paired"][m] = paired_report(runs, baseline, m, resamples, seed)
    return out


def format_report(result, baseline="full"):
    lines = []
    lines.append("| Mode | n | Correct | Accuracy | 95% CI (cluster bootstrap) |")
    lines.append("|---|---|---|---|---|")
    for m, s in result["modes"].items():
        lo, hi = s["ci95"]
        lines.append(f"| {m} | {s['n']} | {s['correct']} | {s['accuracy']:.1%} | {lo:.1%} – {hi:.1%} |")
    for m, p in result["paired"].items():
        if p is None:
            continue
        lo, hi = p["diff_ci"]
        lines.append("")
        lines.append(f"**{m} vs {baseline}** ({p['n_pairs']} paired runs)")
        lines.append(
            f"- accuracy difference: {p['diff']:+.1%} (95% CI {lo:+.1%} to {hi:+.1%})"
        )
        lines.append(
            f"- discordant pairs: {baseline}-only correct = {p['baseline_only_correct']}, "
            f"{m}-only correct = {p['other_only_correct']}; exact McNemar p = {p['mcnemar_p']:.3f}"
        )
    for m, s in result["modes"].items():
        lines.append("")
        if s["by_archetype"]:
            lines.append(f"**Accuracy by archetype — {m}**")
            for arch, (c, n) in s["by_archetype"].items():
                lines.append(f"- {arch}: {c}/{n}")
        if s["leaks"]:
            lines.append(f"**Prompt leaks — {m}: {s['leaks']} of {s['n']} runs contained forbidden text**")
        lines.append(f"**Failure taxonomy — {m}**")
        if not s["taxonomy"]:
            lines.append("- no errors")
        for cat, n in sorted(s["taxonomy"].items(), key=lambda kv: -kv[1]):
            lines.append(f"- {cat}: {n}")
        worst = sorted(s["taxonomy_by_scenario"].items(), key=lambda kv: -sum(kv[1].values()))
        for sid, cats in worst[:5]:
            lines.append(f"  - {sid}: " + ", ".join(f"{c}×{n}" for c, n in cats.items()))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("results", help="benchmark results JSON")
    ap.add_argument("--baseline", default="full")
    ap.add_argument("--resamples", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--compare", metavar="OTHER.json",
                    help="also pair the baseline mode of RESULTS (A) against the same mode of OTHER (B)")
    args = ap.parse_args()
    runs = load_runs(args.results)
    if args.compare:
        p = compare_files(runs, load_runs(args.compare), args.baseline, args.resamples, args.seed)
        if p is None:
            print("no paired runs: the two files share no (scenario_id, run) for that mode")
        else:
            lo, hi = p["diff_ci"]
            print(f"**B ({args.compare}) vs A ({args.results}), mode={args.baseline}, {p['n_pairs']} paired runs**")
            print(f"- accuracy difference B-A: {p['diff']:+.1%} (95% CI {lo:+.1%} to {hi:+.1%})")
            print(f"- A-only correct = {p['baseline_only_correct']}, B-only correct = {p['other_only_correct']}; "
                  f"exact McNemar p = {p['mcnemar_p']:.3f}\n")
    result = analyze(runs, args.baseline, args.resamples, args.seed)
    print(format_report(result, args.baseline))


if __name__ == "__main__":
    main()
