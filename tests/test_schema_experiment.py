import argparse
import json

import pytest
from fakes import call
from langchain_core.messages import ToolMessage
from triage_fixtures import incident_db, offline_client

from triage.excytin import run as bench
from triage.excytin.analyze import format_report, load, sql_error_rate, summarise
from triage.excytin.grade import Grader
from triage.excytin.task import SYSTEM_PROMPT, build_investigator, tables_block
from triage.memory import make_memory


def test_schema_off_prompt_is_byte_identical_to_the_main_runs_prompt():
    """The schema experiment only compares cleanly if 'off' reproduces the main run exactly."""
    db = incident_db()
    old_style = SYSTEM_PROMPT.replace("{tables_block}", "Tables: {tables}").format(
        tables=", ".join(db.tables()), memory_note="")
    agent = build_investigator(db, make_memory("none"), offline_client(lambda m, t: call("submit_answer", answer="x",
                                                                                         confidence=1)))
    assert agent.system_prompt == old_style


def test_full_schema_lists_every_table_with_exact_columns_and_is_cached():
    db = incident_db()
    text = db.schema_text()
    assert text.splitlines() == [db.describe(t) for t in db.tables()]
    assert "SecurityAlert: SystemAlertId, AlertName" in text and "DeviceProcessEvents: Timestamp, DeviceName" in text
    assert db.schema_text() is db.schema_text()  # computed once
    block = tables_block(db, "full")
    assert "exact column names" in block and text in block and "never guess" in block
    with pytest.raises(ValueError):
        tables_block(db, "partial")


def test_schema_reaches_the_model_and_only_when_asked():
    seen = {}

    def policy(messages, tools):
        seen["system"] = messages[0].content
        return call("submit_answer", answer="x", confidence=1)

    for schema, expect in (("off", False), ("full", True)):
        agent = build_investigator(incident_db(), make_memory("graph"), offline_client(policy), schema=schema)
        agent.investigate("q", "task")
        assert ("AlertName, AlertSeverity" in seen["system"]) is expect
        assert "Tables:" in seen["system"] or "Tables and their exact column names" in seen["system"]


def test_runner_records_schema_and_sql_error_counts_and_analysis_pairs_with_and_without(tmp_path):
    questions = [{"qid": f"i5-q{i}", "index": i, "question": "Which alert?", "answer": "Manatee", "context": ""}
                 for i in range(3)]

    def policy(messages, tools):
        tm = [m for m in messages if isinstance(m, ToolMessage)]
        has_schema = "exact column names" in messages[0].content
        if not tm:
            # without the schema the model guesses a column that doesn't exist
            col = "AlertName" if has_schema else "Id"
            return call("run_sql", query=f"SELECT {col} FROM SecurityAlert LIMIT 1")
        return call("submit_answer", answer="Manatee" if has_schema else "unknown", confidence=70)

    out = tmp_path / "r.jsonl"
    factory = lambda **kw: offline_client(policy)  # noqa: E731

    def write(rec):
        with open(out, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    for schema in ("off", "full"):
        args = argparse.Namespace(temperature=0.0, max_steps=5, inject=False, save_traces=True, schema=schema)
        bench.run_chain(5, questions, "none", 0, args, Grader(), set(), write, factory, incident_db())
    runs = load(out)
    assert {r["mode"] for r in runs} == {"none", "none+schema"}
    off = [r for r in runs if r["mode"] == "none"]
    on = [r for r in runs if r["mode"] == "none+schema"]
    assert all(r["sql_calls"] == 1 and r["sql_errors"] == 1 for r in off)
    assert all(r["sql_calls"] == 1 and r["sql_errors"] == 0 for r in on)
    assert sql_error_rate(off) == 1.0 and sql_error_rate(on) == 0.0
    s = summarise(runs, baseline="none")
    effect = s["schema_effect"]["none"]
    assert effect["n_pairs"] == 3 and effect["diff"] == 1.0
    report = format_report(s)
    assert "Effect of giving the agent the schema" in report and "SQL errors" in report


def test_old_result_files_without_a_schema_field_load_unchanged_and_derive_sql_errors(tmp_path):
    rec = {"scenario_id": "q", "incident": 5, "position": 0, "mode": "graph", "run": 0, "correct": True,
           "steps": 1, "input_tokens": 1, "output_tokens": 1, "cost_usd": 0, "wall_seconds": 1,
           "tool_calls": [{"tool": "run_sql", "output": "SQL error: Unknown column 'Id'"},
                          {"tool": "run_sql", "output": "1 rows."}]}
    p = tmp_path / "old.jsonl"
    p.write_text(json.dumps(rec) + "\n")
    runs = load(p)
    assert runs[0]["mode"] == "graph" and sql_error_rate(runs) == 0.5
