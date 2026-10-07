import random
from math import comb

import pytest
from fakes import ScriptedChat, text

from triage.conformal import agreement_scores, binom_cdf, calibrate, evaluate, split_evaluation
from triage.excytin.grade import Grader, match
from triage.llm import Budget, ChatClient, ResponseCache


@pytest.mark.parametrize("golden,submitted", [
    ("198.43.121.209", "The IP is `198.43.121.209`."),
    ("powershell.exe", "PowerShell.exe"),
    ("notepad.exe", "notepad"),
    ("http://vectorsandarrows.com/", "https://www.vectorsandarrows.com"),
    ("santiago@vnevado.alpineskihouse.co", "santiago"),
    ("vnevado-win11u", "vnevado-win10s, vnevado-win10r, vnevado-win11u"),
])
def test_match_accepts(golden, submitted):
    assert match(golden, submitted)


@pytest.mark.parametrize("golden,submitted", [
    ("198.43.121.20", "198.43.121.209"),          # prefix of a different IP
    ("vnevado-win10", "vnevado-win10r"),          # prefix of a different host
    ("72.153.24.3", ", ".join(f"10.0.0.{i}" for i in range(12)) + ", 72.153.24.3"),  # long enumeration
    ("rubeus.exe", ""),
])
def test_match_rejects(golden, submitted):
    assert not match(golden, submitted)


def test_judge_used_only_when_match_fails():
    judge = ChatClient(provider="ollama", model="j", cache=ResponseCache(":memory:", "off"), budget=Budget(1),
                       backend=ScriptedChat(lambda m, t: text("Analysis: same time.\nIs_Answer_Correct: True")))
    g = Grader(judge)
    q = {"question": "When?", "answer": "2024-06-20t09:10:48.04z", "context": ""}
    assert g.grade(q, "June 20 2024 09:10:48 UTC") == {"correct": True, "method": "judge",
                                                       "judge_text": "Analysis: same time.\nIs_Answer_Correct: True"}
    assert g.grade(q, "2024-06-20T09:10:48.04Z")["method"] == "match"
    assert Grader(None).grade(q, "June 20")["correct"] is False


def test_binom_cdf_matches_exact_sum():
    for n, k, p in [(10, 3, 0.2), (25, 0, 0.1), (40, 12, 0.3), (7, 7, 0.5)]:
        exact = sum(comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k + 1))
        assert binom_cdf(k, n, p) == pytest.approx(exact, rel=1e-9)
    assert binom_cdf(3, 0, 0.1) == 1.0


def test_calibrate_escalates_everything_when_the_model_is_unreliable():
    rng = random.Random(0)
    scores = [rng.random() for _ in range(200)]
    correct = [rng.random() < 0.5 for _ in scores]  # confidence carries no signal
    th = calibrate(scores, correct, alpha=0.05, delta=0.1)
    assert th.threshold is None and th.decide(0.99) == "escalate"


def test_calibrate_finds_a_threshold_when_confidence_is_informative():
    rng = random.Random(1)
    scores = [rng.random() for _ in range(400)]
    correct = [rng.random() < (0.99 if s > 0.8 else 0.5) for s in scores]  # confident answers are reliable
    th = calibrate(scores, correct, alpha=0.1, delta=0.1)
    assert th.threshold == 0.8
    ev = evaluate(th, scores, correct)
    assert 0.1 < ev["coverage"] < 0.3 and ev["selective_error"] <= 0.1


def test_split_evaluation_keeps_violations_rare():
    rng = random.Random(2)
    scores = [rng.random() for _ in range(600)]
    correct = [rng.random() < s for s in scores]
    out = split_evaluation(scores, correct, list(range(600)), alpha=0.1, delta=0.1, trials=60)
    assert out["violation_rate"] <= 0.3 and out["selective_error_mean"] <= 0.12


def test_agreement_scores():
    recs = [{"scenario_id": "a", "answer": x} for x in ("1.2.3.4", "1.2.3.4", "5.6.7.8")]
    assert agreement_scores(recs) == pytest.approx([2 / 3, 2 / 3, 1 / 3])
