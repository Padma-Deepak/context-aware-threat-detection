import benchmark


def sc(i, truth="BENIGN", **kw):
    return {"id": i, "task": f"task {i}", "ground_truth": truth, **kw}


def test_chains_group_by_chain_key_and_keep_order():
    chains = benchmark.build_chains([sc("a", chain="x"), sc("b", chain="y"), sc("c", chain="x")])
    assert [[s["id"] for s in c] for c in chains] == [["a", "c"], ["b"]]


def test_chains_fall_back_to_one_chain_when_ids_unknown():
    scenarios = [sc("H01"), sc("H02")]
    assert benchmark.build_chains(scenarios) == [scenarios]


def test_chains_use_hand_picked_dev_grouping_when_all_ids_present():
    ids = [i for grp in benchmark.CHAIN_SCENARIO_IDS for i in grp]
    chains = benchmark.build_chains([sc(i) for i in ids])
    assert [[s["id"] for s in c] for c in chains] == benchmark.CHAIN_SCENARIO_IDS


def make_result(mode, sid, correct=True, tokens=100):
    truth = "MALICIOUS"
    return benchmark.RunResult(sid, mode, 1, truth if correct else "BENIGN", truth, tokens, 2.0, 2, 0)


def test_compute_metrics_and_generic_table(capsys):
    results = [make_result(m, s, correct=(m == "full" or s == "A")) for m in benchmark.MODES for s in "AB"]
    metrics = {m: benchmark.compute_metrics(results, m) for m in benchmark.MODES}
    assert metrics["full"]["accuracy"] == 100.0 and metrics["windowed_summary"]["accuracy"] == 50.0
    benchmark.print_results(metrics, [sc("A", "MALICIOUS"), sc("B", "MALICIOUS")], [[sc("A")]])
    out = capsys.readouterr().out
    assert "WINDOWED_SUMMARY" in out and "-50.0 pts" in out and "may be noise" in out


def test_three_mode_table_prints_all_columns(capsys):
    modes = ["full", "windowed_summary", "pinned_evidence"]
    results = [make_result(m, "A") for m in modes]
    metrics = {m: benchmark.compute_metrics(results, m) for m in modes}
    benchmark.print_results(metrics, [sc("A", "MALICIOUS")], [[sc("A")]])
    assert "PINNED_EVIDENCE" in capsys.readouterr().out


def test_results_file_records_full_config_and_token_source(tmp_path, monkeypatch):
    monkeypatch.setattr(benchmark, "RESULTS_FILE", tmp_path / "r.json")
    r = make_result("full", "A")
    r.tokens_source, r.llm_calls = "api", 3
    benchmark.checkpoint_results([r], summaries=[{"mode": "windowed_summary"}])
    import json

    data = json.loads((tmp_path / "r.json").read_text())
    assert data["status"] == "in_progress"
    assert {"provider", "model", "prompt_version", "summary_prompt", "modes", "window_size"} <= set(data["config"])
    assert data["raw_results"][0]["tokens_source"] == "api" and data["summaries"] == [{"mode": "windowed_summary"}]
