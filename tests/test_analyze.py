import json

import pytest
from analyze import (analyze, classify_error, cluster_bootstrap_ci, format_report,
                     load_runs, mcnemar_exact, paired_runs)


def run(mode, sid, n, verdict, truth):
    return {"mode": mode, "scenario_id": sid, "run": n, "verdict": verdict,
            "ground_truth": truth, "correct": verdict == truth, "tokens": 100, "duration": 1.0}


def test_mcnemar_known_values():
    assert mcnemar_exact(6, 1) == pytest.approx(0.125)  # your held-out discordant pairs
    assert mcnemar_exact(4, 2) == pytest.approx(0.6875)  # your dev-set discordant pairs
    assert mcnemar_exact(3, 3) == 1.0
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(10, 0) == pytest.approx(2 / 1024)


@pytest.mark.parametrize("truth,verdict,cat", [
    ("MALICIOUS", "MALICIOUS", None),
    ("MALICIOUS", "BENIGN", "missed_threat"),
    ("MALICIOUS", "ESCALATE", "missed_threat"),
    ("BENIGN", "MALICIOUS", "false_positive"),
    ("BENIGN", "ESCALATE", "over_escalation"),
    ("ESCALATE", "MALICIOUS", "overconfident_malicious"),
    ("ESCALATE", "BENIGN", "overconfident_benign"),
    ("BENIGN", "UNKNOWN", "no_verdict"),
])
def test_error_taxonomy(truth, verdict, cat):
    assert classify_error(truth, verdict) == cat


def make_runs():
    runs = []
    for sid, truth in [("A", "MALICIOUS"), ("B", "BENIGN"), ("C", "ESCALATE"), ("D", "MALICIOUS")]:
        for n in (1, 2, 3):
            runs.append(run("full", sid, n, truth, truth))
            runs.append(run("win", sid, n, "MALICIOUS" if sid == "B" else truth, truth))
    return runs


def test_cluster_bootstrap_is_deterministic_and_brackets_the_estimate():
    runs = [r for r in make_runs() if r["mode"] == "win"]
    lo, hi = cluster_bootstrap_ci(runs, resamples=2000, seed=1)
    assert (lo, hi) == cluster_bootstrap_ci(runs, resamples=2000, seed=1)
    assert lo <= 0.75 <= hi and 0 <= lo and hi <= 1


def test_paired_analysis_end_to_end():
    result = analyze(make_runs(), baseline="full", resamples=1000)
    assert result["modes"]["full"]["accuracy"] == 1.0
    assert result["modes"]["win"]["accuracy"] == 0.75
    p = result["paired"]["win"]
    assert (p["n_pairs"], p["baseline_only_correct"], p["other_only_correct"]) == (12, 3, 0)
    assert p["diff"] == pytest.approx(-0.25) and p["mcnemar_p"] == pytest.approx(0.25)
    assert result["modes"]["win"]["taxonomy"] == {"false_positive": 3}
    assert "false_positive: 3" in format_report(result)


def test_pairing_ignores_unmatched_runs():
    runs = make_runs()[:-1]  # drop one windowed run
    assert len(paired_runs(runs, "full", "win")) == 11


def test_load_runs_accepts_dict_or_list_and_rejects_empty(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"raw_results": make_runs()}))
    assert len(load_runs(p)) == 24
    p.write_text(json.dumps(make_runs()))
    assert len(load_runs(p)) == 24
    p.write_text(json.dumps({"raw_results": []}))
    with pytest.raises(ValueError):
        load_runs(p)


def test_compare_files_pairs_the_same_mode_across_two_result_sets():
    from analyze import compare_files

    a = [run("full", s, n, "BENIGN", "ESCALATE") for s in "XY" for n in (1, 2)]  # v1: always wrong
    b = [run("full", s, n, "ESCALATE", "ESCALATE") for s in "XY" for n in (1, 2)]  # v2: always right
    p = compare_files(a, b, "full", resamples=500)
    assert p["n_pairs"] == 4 and p["diff"] == 1.0 and (p["baseline_only_correct"], p["other_only_correct"]) == (0, 4)
    assert p["mcnemar_p"] == pytest.approx(0.125)
    assert compare_files(a, [], "full") is None


def test_by_archetype_breakdown_appears_in_the_report():
    from analyze import by_archetype

    runs = [dict(run("full", "A", 1, "ESCALATE", "ESCALATE"), archetype="unseeded_ip"),
            dict(run("full", "B", 1, "BENIGN", "ESCALATE"), archetype="unseeded_ip"),
            dict(run("full", "C", 1, "BENIGN", "BENIGN"), archetype="benign_ip")]
    assert by_archetype(runs) == {"benign_ip": (1, 1), "unseeded_ip": (1, 2)}
    assert "unseeded_ip: 1/2" in format_report(analyze(runs, resamples=200))
