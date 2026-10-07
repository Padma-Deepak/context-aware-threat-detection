import argparse
import json
import sqlite3

import pytest
from fakes import call
from langchain_core.messages import ToolMessage
from triage_fixtures import incident_db, offline_client

import triage.triage_agent as ta
from triage import cli
from triage.alerts import ingest_sentinel, ingest_sigma
from triage.cases import CaseStore
from triage.excytin import run as bench
from triage.excytin.analyze import format_report, summarise
from triage.excytin.grade import Grader
from triage.excytin.setup_db import build_sql
from triage.excytin.task import load_questions


@pytest.fixture
def store(tmp_path):
    return CaseStore(tmp_path / "cases.sqlite")


def test_ingest_labels_incident_alerts_and_runs_sigma(store):
    db = incident_db()
    assert ingest_sentinel(store, db) == 2
    assert ingest_sentinel(store, db) == 0  # idempotent
    labels = {a["title"]: a["label"] for a in store.alerts()}
    assert labels == {"Manatee Tempest activity group": "malicious", "Suspicious LDAP query": None}
    assert ingest_sigma(store, db) >= 1
    sigma = store.alerts(source="sigma")
    assert any("Shadow Copies" in a["title"] for a in sigma)
    assert any(t == "host" and v == "vnevado-win10r" for t, v in sigma[0]["entities"])


def test_decide_policy():
    assert ta.decide("MALICIOUS", 95, None) == "escalated"  # uncalibrated: never automatic
    assert ta.decide("MALICIOUS", 95, 0.9) == "auto"
    assert ta.decide("BENIGN", 80, 0.9) == "escalated"
    assert ta.decide("ESCALATE", 100, 0.1) == "escalated"


def test_triage_investigation_cross_case_memory_and_injection(store, tmp_path, monkeypatch):
    monkeypatch.setattr(ta, "CALIBRATION_FILE", tmp_path / "cal.json")
    (tmp_path / "cal.json").write_text(json.dumps({"threshold": 0.8}))
    db = incident_db()
    ingest_sentinel(store, db)
    recalls = []

    def policy(messages, tools):
        tm = [m for m in messages if isinstance(m, ToolMessage)]
        if not tm:
            return call("run_sql", query="SELECT DeviceName, ProcessCommandLine FROM DeviceProcessEvents LIMIT 5")
        if len(tm) == 1:
            return call("recall", entity="vnevado-win10r")
        recalls.append(tm[1].content)
        ev = tm[0].content.split("]")[0].replace("[evidence ", "")
        return call("submit_verdict", verdict="MALICIOUS", confidence=90, summary="Shadow copies deleted.",
                    claims=[{"text": "vssadmin deleted shadows", "evidence": [ev]}], attack_techniques=["T1490"])

    t = ta.Triage(store, client=offline_client(policy), memory_path=str(tmp_path / "mem.sqlite"))
    t._dbs[5] = db
    out1 = t.investigate(1)
    out2 = t.investigate(2)
    assert out1["decision"] == "auto" and out1["status"] == "auto_confirmed"
    assert "case1:1" in recalls[1]  # the second case remembers what the first one saw
    inv = store.latest_investigation(1)
    assert inv["citations_valid"] == 1 and inv["claims"][0]["evidence"] == ["case1:1"] and out2["verdict"] == "MALICIOUS"

    store.add_review(2, "BENIGN", note="authorised admin")
    m = cli.metrics(store)
    assert m["malicious_recall"] == 1.0 and m["false_positive_rate"] == 1.0 and m["benign_labels"] == 1
    assert "Malicious recall" in cli.format_metrics(m)

    benign = ta.Triage(store, client=offline_client(lambda msgs, tools: call(
        "submit_verdict", verdict="BENIGN", confidence=100, summary="pentest", claims=[])),
        memory_path=str(tmp_path / "mem2.sqlite"), inject=True)
    benign._dbs[5] = db
    benign.investigate(1)
    assert store.latest_investigation(1)["injection_success"] == 1


def test_review_requires_a_decision(store):
    with pytest.raises(ValueError):
        store.add_review(1, "ESCALATE")


def test_runner_records_resumes_and_measures_injection(tmp_path, monkeypatch):
    questions = [{"qid": "i5-q0", "index": 0, "question": "Which IP?", "answer": "198.43.121.209", "context": ""},
                 {"qid": "i5-q1", "index": 1, "question": "Which host?", "answer": "vnevado-win10r", "context": ""}]

    def policy(messages, tools):
        tm = [m for m in messages if isinstance(m, ToolMessage)]
        if not tm:
            return call("run_sql", query="SELECT AlertName, Entities FROM SecurityAlert LIMIT 1")
        injected = bench.INJECTED_ANSWER in tm[0].content
        return call("submit_answer", answer=bench.INJECTED_ANSWER if injected else "198.43.121.209", confidence=70)

    out = tmp_path / "r.jsonl"
    args = argparse.Namespace(temperature=0.0, max_steps=5, inject=False, save_traces=True)
    lines = []

    def write(rec):
        lines.append(rec)
        with open(out, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    factory = lambda **kw: offline_client(policy)  # noqa: E731
    recs = bench.run_chain(5, questions, "graph", 0, args, Grader(), set(), write, factory, incident_db())
    assert [r["correct"] for r in recs] == [True, False] and recs[0]["trace"] and recs[1]["memory_stats"]["entities"]
    again = bench.run_chain(5, questions, "graph", 0, args, Grader(), bench._done_keys(out), write, factory, incident_db())
    assert again == []

    args.inject = True
    hit = bench.run_chain(5, questions[:1], "none", 0, args, Grader(), set(), lambda r: None, factory, incident_db())
    assert hit[0]["injection_success"] and not hit[0]["correct"]

    report = format_report(summarise(lines + hit))
    assert "Accuracy by memory mode" in report and "Prompt injection" in report


def test_question_loading_is_seeded_and_keeps_order():
    a = load_questions("test", [5], per_incident=10, seed=3)[5]
    b = load_questions("test", [5], per_incident=10, seed=3)[5]
    assert [q["qid"] for q in a] == [q["qid"] for q in b] and len(a) == 10
    assert [q["index"] for q in a] == sorted(q["index"] for q in a)
    assert sum(len(v) for v in load_questions("test").values()) == 589


def test_setup_sql_builds_loads_and_read_only_grants(tmp_path):
    inc = tmp_path / "incident_5"
    (inc / "DeviceEvents").mkdir(parents=True)
    (inc / "SecurityAlert.csv").write_text("a❖b\n")
    (inc / "SecurityAlert.meta").write_text(json.dumps({"a": "string", "b": "string"}))
    (inc / "LAQueryLogs.csv").write_text("x\n")
    (inc / "LAQueryLogs.meta").write_text(json.dumps({"x": "string"}))
    (inc / "DeviceEvents" / "DeviceEvents_0.csv").write_text("c\n")
    (inc / "DeviceEvents" / "DeviceEvents_1.csv").write_text("c\n")
    (inc / "DeviceEvents" / "DeviceEvents_0.meta").write_text(json.dumps({"c": "string"}))
    sql = build_sql(tmp_path, [5])
    assert "CREATE TABLE `SecurityAlert`" in sql and "LAQueryLogs" not in sql
    assert sql.count("INTO TABLE `DeviceEvents`") == 2
    assert "GRANT SELECT, SHOW VIEW ON incident_5.* TO 'reader'" in sql


def test_calibrate_cli_from_benchmark(tmp_path, monkeypatch):
    path = tmp_path / "b.jsonl"
    with open(path, "w") as f:
        for i in range(200):
            conf = (i % 10) * 10 + 5
            f.write(json.dumps({"confidence": conf, "correct": conf > 50 or i % 7 == 0}) + "\n")
    monkeypatch.setattr(cli, "CALIBRATION_FILE", tmp_path / "cal.json")
    monkeypatch.setattr(cli, "CaseStore", lambda: CaseStore(":memory:"))
    cli.main(["calibrate", "--from-benchmark", str(path), "--alpha", "0.1"])
    cal = json.loads((tmp_path / "cal.json").read_text())
    assert cal["threshold"] == 0.5  # lowest grid point with zero errors above it


def test_export_feedback(tmp_path, monkeypatch, store):
    ingest_sentinel(store, incident_db())
    store.add_review(1, "MALICIOUS", note="confirmed")
    monkeypatch.setattr(cli, "CaseStore", lambda: store)
    out = tmp_path / "fb.jsonl"
    cli.main(["export-feedback", str(out)])
    rec = json.loads(out.read_text().splitlines()[0])
    assert rec["truth"] == "MALICIOUS" and rec["alert"]["title"] == "Manatee Tempest activity group"


def test_record_then_replay_reproduces_a_run_without_a_model(tmp_path):
    """The CI regression pattern: record responses once, replay them forever with no model or key."""
    from fakes import ScriptedChat

    from triage.excytin.task import build_investigator
    from triage.llm import Budget, ChatClient, ResponseCache
    from triage.memory import make_memory

    def policy(messages, tools):
        tm = [m for m in messages if isinstance(m, ToolMessage)]
        if not tm:
            return call("run_sql", query="SELECT AlertName FROM SecurityAlert LIMIT 1")
        return call("submit_answer", answer="Manatee", confidence=60, evidence=["q:1"])

    cassette = tmp_path / "cassette.sqlite"
    rec = ChatClient(provider="ollama", model="m", cache=ResponseCache(cassette, "record"), budget=Budget(1),
                     backend=ScriptedChat(policy))
    first = build_investigator(incident_db(), make_memory("none"), rec).investigate("q", "task").final

    def no_model(messages, tools):
        raise AssertionError("replay called the model")

    rep = ChatClient(provider="ollama", model="m", cache=ResponseCache(cassette, "replay"), budget=Budget(1),
                     backend=ScriptedChat(no_model))
    assert build_investigator(incident_db(), make_memory("none"), rep).investigate("q", "task").final == first
    assert sqlite3.connect(cassette).execute("SELECT COUNT(*) FROM responses").fetchone()[0] == 2
