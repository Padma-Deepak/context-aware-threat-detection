"""Conformal escalation: answer automatically only where an error-rate guarantee holds; escalate the rest.

A SOC wants: "of the alerts the agent closes on its own, at most alpha are wrong", with that promise
holding on new data. This module picks the confidence threshold lambda that delivers it, using
Learn-then-Test (Angelopoulos et al., 2021) with a Bonferroni correction over a fixed grid:

    for each lambda in GRID (0.00, 0.05, ..., 1.00, fixed before seeing data):
        n = answers with score >= lambda,  k = wrong ones among them
        p = P(Binomial(n, alpha) <= k)          # small p => the true error rate is below alpha
        lambda is certified if p <= delta / len(GRID)

The loosest certified lambda gives the most automation. With probability >= 1 - delta over the draw of
the calibration set, every certified lambda (so the chosen one) has selective error <= alpha on new
exchangeable data. If nothing is certified, everything escalates: the safe default.

(Fixed-sequence testing from the strictest lambda is the other textbook choice, but it must stop at its
first failure, and the strictest thresholds cover so few answers that it usually fails immediately.)

Score sources (any number in [0, 1] where higher means "more likely right"):
    confidence   the agent's self-reported confidence / 100 (free, but often over-confident)
    agreement    fraction of repeated runs that gave the majority answer (needs --repeats >= 3)
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p), stable for n in the thousands."""
    if n == 0 or k >= n:
        return 1.0
    if k < 0:
        return 0.0
    if p <= 0:
        return 1.0
    if p >= 1:
        return 0.0
    total = 0.0
    for i in range(k + 1):
        total += math.exp(math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
                          + i * math.log(p) + (n - i) * math.log1p(-p))
    return min(1.0, total)


@dataclass
class Threshold:
    threshold: float | None  # None: escalate everything
    alpha: float
    delta: float
    calib_n: int
    calib_answered: int
    calib_errors: int

    def decide(self, score: float) -> str:
        return "auto" if self.threshold is not None and score >= self.threshold else "escalate"


GRID = tuple(round(i * 0.05, 2) for i in range(21))


def calibrate(scores: list[float], correct: list[bool], alpha: float = 0.1, delta: float = 0.1,
              grid: tuple = GRID) -> Threshold:
    if len(scores) != len(correct):
        raise ValueError("scores and correct must be the same length")
    best = Threshold(None, alpha, delta, len(scores), 0, 0)
    for lam in sorted(grid, reverse=True):
        answered = [c for s, c in zip(scores, correct) if s >= lam]
        n, k = len(answered), sum(not c for c in answered)
        if n and binom_cdf(k, n, alpha) <= delta / len(grid):
            best = Threshold(lam, alpha, delta, len(scores), n, k)  # loosest certified so far
    return best


def evaluate(th: Threshold, scores: list[float], correct: list[bool]) -> dict:
    auto = [c for s, c in zip(scores, correct) if th.decide(s) == "auto"]
    n = len(scores)
    return {
        "threshold": th.threshold,
        "coverage": len(auto) / n if n else 0.0,  # share answered automatically
        "escalation_rate": 1 - len(auto) / n if n else 1.0,
        "selective_error": (sum(not c for c in auto) / len(auto)) if auto else 0.0,
        "auto_n": len(auto),
        "n": n,
    }


def agreement_scores(records: list[dict], key=lambda r: r["scenario_id"], answer=lambda r: r["answer"]):
    """For repeated runs: score each record by how many runs agree with its answer (normalised)."""
    from triage.excytin.grade import normalise

    groups = defaultdict(list)
    for r in records:
        groups[key(r)].append(r)
    scores = {}
    for g in groups.values():
        counts = defaultdict(int)
        for r in g:
            counts[normalise(answer(r))] += 1
        for r in g:
            scores[id(r)] = counts[normalise(answer(r))] / len(g)
    return [scores[id(r)] for r in records]


def split_evaluation(scores, correct, groups, alpha=0.1, delta=0.1, trials=200, seed=0) -> dict:
    """Repeated random 50/50 splits *by group* (question), calibrate on one half, test on the other.
    Reports the mean and spread of test coverage and selective error, plus how often the guarantee
    was violated (should be at most about delta)."""
    rng = random.Random(seed)
    by_group = defaultdict(list)
    for s, c, g in zip(scores, correct, groups):
        by_group[g].append((s, c))
    keys = sorted(by_group)
    if len(keys) < 4:
        return {}
    covs, errs, violations = [], [], 0
    for _ in range(trials):
        rng.shuffle(keys)
        cal, test = keys[: len(keys) // 2], keys[len(keys) // 2:]
        cs = [x for k in cal for x in by_group[k]]
        ts = [x for k in test for x in by_group[k]]
        th = calibrate([s for s, _ in cs], [c for _, c in cs], alpha, delta)
        ev = evaluate(th, [s for s, _ in ts], [c for _, c in ts])
        covs.append(ev["coverage"])
        errs.append(ev["selective_error"])
        violations += ev["selective_error"] > alpha
    mean = lambda v: sum(v) / len(v)  # noqa: E731
    return {
        "alpha": alpha, "delta": delta, "trials": trials,
        "coverage_mean": mean(covs), "coverage_min": min(covs), "coverage_max": max(covs),
        "selective_error_mean": mean(errs), "violation_rate": violations / trials,
    }
