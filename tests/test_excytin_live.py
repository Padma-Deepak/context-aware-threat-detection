"""Integration tests against the real ExCyTIn MySQL (docker-compose.excytin.yml). Skipped when it is not up.

    pytest -m excytin
"""

import pytest

from triage.excytin.db import IncidentDB
from triage.excytin.setup_db import INCIDENTS
from triage.sigma.compiler import load_rules

pytestmark = pytest.mark.excytin


def _db(n):
    db = IncidentDB(n)
    try:
        db.tables()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"ExCyTIn MySQL not reachable: {exc}")
    return db


@pytest.mark.parametrize("incident", INCIDENTS)
def test_every_incident_loaded_with_alert_layer(incident):
    tables = _db(incident).tables()
    assert {"SecurityAlert", "SecurityIncident", "AlertEvidence", "AlertInfo"} <= set(tables)
    assert "LAQueryLogs" not in tables and "AzureDiagnostics" not in tables


def test_known_answer_is_findable_and_agent_user_is_read_only():
    db = _db(5)
    res = db.run("SELECT AlertName FROM SecurityAlert WHERE Entities LIKE '%198.43.121.209%' LIMIT 1")
    assert res.rows and res.rows[0]["AlertName"] == "Manatee Tempest activity group"
    cur = db._conn().cursor()
    with pytest.raises(Exception, match="denied"):
        cur.execute("DELETE FROM SecurityAlert LIMIT 1")


def test_sigmahq_rules_detect_the_ransomware_incident():
    db = _db(5)
    rules, _ = load_rules("triage/sigma/rules")
    hits = {r.title for r in rules if db.run(r.sql(), r.params).rows}
    assert "Shadow Copies Deletion Using Operating Systems Utilities" in hits
    assert "HackTool - Mimikatz Execution" in hits
