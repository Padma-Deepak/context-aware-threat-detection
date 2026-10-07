"""MCP server exposing the triage tools to any MCP client (Claude Desktop, Cursor, other agents).

    python -m triage.mcp_server                 # streamable-http on :8001/mcp
    TRIAGE_MCP_TRANSPORT=stdio python -m triage.mcp_server

Tools are read-only: SQL goes through the same allow-list and read-only MySQL user as the agent.
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from triage.cases import DEFAULT_DIR, CaseStore
from triage.excytin.db import IncidentDB
from triage.excytin.setup_db import INCIDENTS
from triage.intel import enrich
from triage.memory import GraphMemory

mcp = FastMCP("soc-triage", host=os.getenv("TRIAGE_MCP_HOST", "127.0.0.1"),
              port=int(os.getenv("TRIAGE_MCP_PORT", "8001")))
_dbs: dict = {}


def _db(incident: int) -> IncidentDB:
    if incident not in INCIDENTS:
        raise ValueError(f"incident must be one of {INCIDENTS}")
    if incident not in _dbs:
        _dbs[incident] = IncidentDB(incident)
    return _dbs[incident]


@mcp.tool()
def run_sql(incident: int, query: str) -> str:
    """Run one read-only SQL query (SELECT/SHOW/DESCRIBE) against an ExCyTIn incident's log database."""
    return _db(incident).run(query).render()


@mcp.tool()
def list_tables(incident: int) -> list[str]:
    """Tables in an incident's log database."""
    return _db(incident).tables()


@mcp.tool()
def describe_table(incident: int, table: str) -> str:
    """Columns of one table."""
    return _db(incident).describe(table)


@mcp.tool()
def threat_intel(indicator: str) -> str:
    """Look up a CVE (NVD + CISA KEV), ATT&CK technique, or public IP / domain / hash (AbuseIPDB, ThreatFox)."""
    return enrich(indicator)


@mcp.tool()
def recall(entity: str) -> str:
    """What earlier triage cases found about an entity (host, account, IP, file...), with source rows."""
    path = DEFAULT_DIR / "memory.sqlite"
    if not path.exists():
        return "No case memory yet."
    return GraphMemory(str(path)).recall(entity)


@mcp.tool()
def list_alerts(status: str = "", limit: int = 50) -> list[dict]:
    """Alerts in the triage queue. status: new | escalated | auto_closed | auto_confirmed | reviewed."""
    return [{k: a[k] for k in ("id", "source", "incident", "title", "severity", "time", "status")}
            for a in CaseStore().alerts(status=status or None, limit=limit)]


@mcp.tool()
def get_case(alert_id: int) -> dict:
    """An alert and its latest investigation (verdict, confidence, cited claims, decision)."""
    store = CaseStore()
    alert = store.alert(alert_id)
    if alert is None:
        return {"error": f"no alert {alert_id}"}
    inv = store.latest_investigation(alert_id) or {}
    keep = ("verdict", "confidence", "summary", "claims", "attack", "actions", "decision", "citations_valid")
    return {"alert": alert, "investigation": {k: inv.get(k) for k in keep}}


if __name__ == "__main__":
    mcp.run(transport=os.getenv("TRIAGE_MCP_TRANSPORT", "streamable-http"))
