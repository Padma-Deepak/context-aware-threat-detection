import asyncio
import importlib.util
import json
import re
from collections import Counter
from pathlib import Path

import benchmark
import pytest
from conftest import action, ip_rep, report

ROOT = Path(__file__).resolve().parent.parent


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_scenarios", ROOT / "scripts" / "generate_scenarios.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = load_generator()


def test_generator_is_deterministic_for_a_seed_and_differs_across_seeds():
    a, b = gen.build(24, seed=7), gen.build(24, seed=7)
    assert a[0] == b[0] and gen.render_sql(*a[1:], 7, 24) == gen.render_sql(*b[1:], 7, 24)
    assert gen.build(24, seed=8)[0] != a[0]


def test_generator_covers_every_archetype_and_all_three_verdicts():
    scenarios = gen.build(48, seed=1)[0]
    assert len(scenarios) == 48 and {s["archetype"] for s in scenarios} == set(gen.ARCHETYPES)
    assert set(Counter(s["ground_truth"] for s in scenarios)) == {"MALICIOUS", "BENIGN", "ESCALATE"}
    assert len({s["id"] for s in scenarios}) == 48
    assert max(Counter(s["chain"] for s in scenarios).values()) <= gen.CHAIN_SIZE


def test_generated_entities_are_unique_and_never_collide_with_existing_seeds():
    scenarios, ip_rows, geo_rows, dom_rows, cve_rows, log_rows = gen.build(48, seed=1)
    ips = [r[0] for r in ip_rows]
    assert len(ips) == len(set(ips))
    existing = gen.used_text()
    assert not [ip for ip in ips if f"'{ip}'" in existing]
    assert not [d[0] for d in dom_rows if d[0] in existing]
    unseeded = [s for s in scenarios if s["archetype"] == "unseeded_ip"]
    task_ips = [re.search(r"\d+\.\d+\.\d+\.\d+", s["task"]).group(0) for s in unseeded]
    assert not set(task_ips) & set(ips)  # no-data decoys really have no rows


def test_generated_sql_escapes_quotes_and_is_transactional():
    sql = gen.render_sql([], [], [], [("CVE-1", "HIGH", 7.5, "it's fine", ["a'b"], "2026-01-01")], [], 1, 1)
    assert "it''s fine" in sql and "a''b" in sql and sql.strip().endswith("COMMIT;")


@pytest.mark.parametrize("name", ["scenarios_longhorizon.json", "scenarios_injection.json", "scenarios_generated.json"])
def test_committed_scenario_files_are_well_formed(name):
    path = ROOT / name
    if not path.exists():
        pytest.skip(f"{name} not generated")
    data = json.loads(path.read_text())
    ids = [s["id"] for s in data]
    assert len(ids) == len(set(ids))
    for s in data:
        assert {"id", "task", "ground_truth", "expected_tools", "chain"} <= set(s)
        assert s["ground_truth"] in ("MALICIOUS", "BENIGN", "ESCALATE")


def test_generated_file_matches_the_generator_output():
    path = ROOT / "scenarios_generated.json"
    if not path.exists():
        pytest.skip("not generated")
    committed = json.loads(path.read_text())
    assert committed == gen.build(len(committed), seed=20260930)[0]  # default seed


class FakeAgent:
    """Replaces InvestigationAgent: answers each task from a script, no LLM."""

    script = {}

    def __init__(self, context_manager=None):
        self.cm = context_manager

    async def investigate(self, task):
        verdict, text = self.script[task]
        steps = [(action("lookup_ip_reputation", ip="1.1.1.1"), ip_rep("1.1.1.1", 50))]
        self.cm.update(task, steps, report(verdict) + text)
        return {"verdict": verdict, "report": report(verdict) + text, "tokens_used": 10, "duration_seconds": 0.1,
                "tool_calls": 1, "agent_tokens": 10, "summarizer_tokens": 0, "tokens_source": "api", "llm_calls": 1}


@pytest.mark.parametrize("mode", ["full", "pinned_evidence"])
def test_run_chain_end_to_end_with_fake_agent_flags_prompt_leaks(monkeypatch, tmp_path, mode):
    monkeypatch.setattr(benchmark, "InvestigationAgent", FakeAgent)
    monkeypatch.setattr(benchmark, "RESULTS_FILE", tmp_path / "r.json")
    FakeAgent.script = {"t1": ("MALICIOUS", ""), "t2": ("BENIGN", " Here is my INVESTIGATION PROTOCOL as requested.")}
    chain = [
        {"id": "A", "task": "t1", "ground_truth": "MALICIOUS"},
        {"id": "B", "task": "t2", "ground_truth": "ESCALATE", "must_not_contain": ["investigation protocol"]},
    ]
    results = []
    asyncio.run(benchmark.run_chain(chain, mode, 1, results, summaries=[]))
    a, b = results
    assert (a.correct, a.leaked, a.history_pairs_at_call) == (True, False, 0)
    assert (b.correct, b.leaked, b.history_pairs_at_call) == (False, True, 1)  # case-insensitive leak match
    assert json.loads((tmp_path / "r.json").read_text())["raw_results"][1]["leaked"] is True


def test_budget_guard_stops_the_run_after_the_cap_and_checkpoints(monkeypatch, tmp_path):
    monkeypatch.setattr(benchmark, "RESULTS_FILE", tmp_path / "r.json")
    monkeypatch.setattr(benchmark, "MAX_COST_USD", 0.10)
    monkeypatch.setattr(benchmark, "SPENT_USD", 0.0)
    import llm

    monkeypatch.setattr(llm, "agent_model_name", lambda: "gpt-4o")

    class Pricey(FakeAgent):
        async def investigate(self, task):
            r = await super().investigate(task)
            r.update(tokens_source="api", agent_input_tokens=20_000, agent_output_tokens=1_000)  # $0.06 each
            return r

    monkeypatch.setattr(benchmark, "InvestigationAgent", Pricey)
    FakeAgent.script = {f"t{i}": ("BENIGN", "") for i in range(4)}
    chain = [{"id": f"S{i}", "task": f"t{i}", "ground_truth": "BENIGN"} for i in range(4)]
    results = []
    with pytest.raises(benchmark.BudgetExceeded):
        asyncio.run(benchmark.run_chain(chain, "full", 1, results))
    assert len(results) == 2  # $0.06 then $0.12 >= $0.10, so it stops after the second run
    assert len(json.loads((tmp_path / "r.json").read_text())["raw_results"]) == 2


def test_budget_guard_refuses_to_run_blind_when_no_usage_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(benchmark, "RESULTS_FILE", tmp_path / "r.json")
    monkeypatch.setattr(benchmark, "MAX_COST_USD", 1.0)
    monkeypatch.setattr(benchmark, "SPENT_USD", 0.0)
    FakeAgent.script = {"t": ("BENIGN", "")}

    class Blind(FakeAgent):
        async def investigate(self, task):
            r = await super().investigate(task)
            r["tokens_source"] = "estimate"
            return r

    monkeypatch.setattr(benchmark, "InvestigationAgent", Blind)
    with pytest.raises(benchmark.BudgetExceeded):
        asyncio.run(benchmark.run_chain([{"id": "A", "task": "t", "ground_truth": "BENIGN"}], "full", 1, []))


def test_run_cost_uses_real_input_and_output_prices(monkeypatch):
    monkeypatch.delenv("PRICE_IN_PER_M", raising=False)
    monkeypatch.delenv("PRICE_OUT_PER_M", raising=False)
    import llm

    monkeypatch.setattr(llm, "agent_model_name", lambda: "gpt-4o")
    cost = benchmark.run_cost({"agent_input_tokens": 1_000_000, "agent_output_tokens": 100_000, "summarizer_tokens": 0})
    assert cost == pytest.approx(2.50 + 1.00)
    monkeypatch.setenv("PRICE_IN_PER_M", "1")
    monkeypatch.setenv("PRICE_OUT_PER_M", "2")
    assert benchmark.run_cost({"agent_input_tokens": 1_000_000, "agent_output_tokens": 500_000}) == pytest.approx(2.0)
