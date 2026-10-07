"""Database-backed tests. Skipped unless DATABASE_URL points at a Postgres that has
db/schema.sql and the db/seed*.sql files loaded (CI does this in a service container)."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="DATABASE_URL not set"),
]
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def data():
    import data as data_module

    return data_module


def test_unknown_entities_return_well_formed_no_data_records_not_errors(data):
    assert data.lookup_ip_reputation("203.0.113.5") == {
        "ip": "203.0.113.5", "found": False, "malicious": False, "score": None, "sources_flagging": [], "first_seen": None}
    assert data.geolocate_ip("203.0.113.5")["found"] is False
    assert data.check_domain_reputation("never-seen.example")["category"] == "unknown"
    assert data.lookup_cve("CVE-0000-0000")["found"] is False
    assert data.query_logs("203.0.113.5", 24) == {"src_ip": "203.0.113.5", "hours": 24, "count": 0, "logs": []}


def test_query_logs_is_newest_first_and_respects_the_window(data):
    logs = data.query_logs("203.0.113.10", 168)["logs"]
    stamps = [lg["timestamp"] for lg in logs]
    assert stamps == sorted(stamps, reverse=True) and len(logs) >= 2
    assert data.query_logs("203.0.113.10", 1)["count"] < len(logs)


def test_queries_are_parameterised_against_injection_strings(data):
    rec = data.lookup_ip_reputation("' OR '1'='1")
    assert rec["found"] is False and rec["first_seen"] is None
    assert data.query_logs("'; DROP TABLE security_logs;--", 24)["count"] == 0
    assert data.lookup_ip_reputation("203.0.113.88")["score"] == 100  # table still intact


def test_mcp_server_exposes_exactly_the_five_documented_tools():
    import asyncio

    import mcp_server

    tools = asyncio.run(mcp_server.mcp.list_tools())
    assert {t.name for t in tools} == {
        "lookup_ip_reputation", "geolocate_ip", "query_logs", "lookup_cve", "check_domain_reputation"}
    assert all(t.description and "Returns" in t.description for t in tools)  # the docstring is the prompt


@pytest.mark.parametrize("script,args", [
    ("verify_scenarios.py", []),
    ("verify_scenarios_holdout.py", []),
    ("verify_extended.py", ["all"]),
])
def test_scenario_labels_are_consistent_with_live_data(script, args):
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / script), *args],
                          capture_output=True, text=True, env=os.environ)
    assert proc.returncode == 0, proc.stdout[-1500:] + proc.stderr[-500:]
