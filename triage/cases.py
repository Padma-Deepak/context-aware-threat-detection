"""Case store for the triage app: alerts, investigations, human reviews (SQLite).

    alert ──investigate──▶ investigation (verdict, confidence, cited claims, decision auto|escalated)
                                   │
                         escalated └──▶ review queue ──reviewer verdict──▶ reviews ──▶ eval set + calibration

Ground truth: ExCyTIn alerts linked to a SecurityIncident are confirmed attack activity (label
"malicious"). Everything else is unlabeled until a reviewer labels it; reviews are the only source of
benign labels, which is why the review loop feeds the evaluation set.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = Path(os.getenv("TRIAGE_HOME", str(ROOT / ".triage")))

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_id TEXT UNIQUE,
    source TEXT,              -- sentinel | sigma
    incident INTEGER,         -- ExCyTIn incident database the alert came from
    title TEXT, severity TEXT, time TEXT,
    entities TEXT,            -- JSON [[type, value], ...]
    attack TEXT,              -- JSON [technique ids]
    raw TEXT,                 -- JSON rows
    label TEXT,               -- ground truth if known: malicious | benign | NULL
    status TEXT DEFAULT 'new',-- new | auto_closed | auto_confirmed | escalated | reviewed
    created REAL
);
CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER, started REAL, finished REAL, model TEXT, provider TEXT, memory TEXT,
    verdict TEXT, confidence INTEGER, summary TEXT, claims TEXT, attack TEXT, actions TEXT,
    evidence TEXT, citations_valid INTEGER, decision TEXT, threshold REAL,
    steps INTEGER, input_tokens INTEGER, output_tokens INTEGER, cost_usd REAL, seconds REAL,
    tool_calls TEXT, trace TEXT, error TEXT, injected INTEGER DEFAULT 0, injection_success INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER, investigation_id INTEGER, reviewer TEXT, verdict TEXT, note TEXT, created REAL
);
CREATE INDEX IF NOT EXISTS ix_inv_alert ON investigations(alert_id);
CREATE INDEX IF NOT EXISTS ix_alert_status ON alerts(status);
"""


class CaseStore:
    def __init__(self, path: str | Path | None = None):
        path = Path(path) if path else DEFAULT_DIR / "cases.sqlite"
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ── alerts ──
    def add_alert(self, *, external_id, source, incident, title, severity, time_, entities, attack, raw,
                  label=None) -> int | None:
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO alerts (external_id, source, incident, title, severity, time, entities, "
                "attack, raw, label, created) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (external_id, source, incident, title, severity, time_, json.dumps(sorted(entities)),
                 json.dumps(attack), json.dumps(raw, default=str), label, time.time()))
            self.db.commit()
            return cur.lastrowid if cur.rowcount else None

    def alert(self, alert_id: int) -> dict | None:
        r = self.db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return _alert_dict(r) if r else None

    def alerts(self, status: str | None = None, source: str | None = None, limit: int = 1000) -> list[dict]:
        q, args = "SELECT * FROM alerts WHERE 1=1", []
        if status:
            q += " AND status = ?"
            args.append(status)
        if source:
            q += " AND source = ?"
            args.append(source)
        q += " ORDER BY time, id LIMIT ?"
        return [_alert_dict(r) for r in self.db.execute(q, (*args, limit))]

    def set_status(self, alert_id: int, status: str):
        with self._lock:
            self.db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            self.db.commit()

    # ── investigations ──
    def add_investigation(self, alert_id: int, **f) -> int:
        cols = ["alert_id"] + list(f)
        vals = [alert_id] + [json.dumps(v, default=str) if isinstance(v, (list, dict)) else v for v in f.values()]
        with self._lock:
            cur = self.db.execute(f"INSERT INTO investigations ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)
            self.db.commit()
            return cur.lastrowid

    def latest_investigation(self, alert_id: int) -> dict | None:
        r = self.db.execute("SELECT * FROM investigations WHERE alert_id = ? ORDER BY id DESC LIMIT 1",
                            (alert_id,)).fetchone()
        return _inv_dict(r) if r else None

    def investigations(self) -> list[dict]:
        return [_inv_dict(r) for r in self.db.execute(
            "SELECT i.* FROM investigations i JOIN (SELECT alert_id, MAX(id) m FROM investigations GROUP BY alert_id) l "
            "ON i.id = l.m ORDER BY i.alert_id")]

    # ── reviews ──
    def add_review(self, alert_id: int, verdict: str, reviewer: str = "analyst", note: str = "") -> int:
        if verdict not in ("MALICIOUS", "BENIGN"):
            raise ValueError("a reviewer decides MALICIOUS or BENIGN")
        inv = self.latest_investigation(alert_id)
        with self._lock:
            cur = self.db.execute("INSERT INTO reviews (alert_id, investigation_id, reviewer, verdict, note, created) "
                                  "VALUES (?,?,?,?,?,?)", (alert_id, inv["id"] if inv else None, reviewer, verdict, note, time.time()))
            self.db.execute("UPDATE alerts SET status = 'reviewed' WHERE id = ?", (alert_id,))
            self.db.commit()
            return cur.lastrowid

    def reviews(self) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM reviews ORDER BY id")]

    def truth(self, alert: dict) -> str | None:
        """Best available label: the latest human review, else the dataset label."""
        r = self.db.execute("SELECT verdict FROM reviews WHERE alert_id = ? ORDER BY id DESC LIMIT 1",
                            (alert["id"],)).fetchone()
        if r:
            return r[0]
        return {"malicious": "MALICIOUS", "benign": "BENIGN"}.get(alert.get("label") or "")

    def counts(self) -> dict:
        return {r[0]: r[1] for r in self.db.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")}


def _alert_dict(r) -> dict:
    d = dict(r)
    for k in ("entities", "attack", "raw"):
        d[k] = json.loads(d[k]) if d.get(k) else []
    return d


def _inv_dict(r) -> dict:
    d = dict(r)
    for k in ("claims", "attack", "actions", "evidence", "tool_calls", "trace"):
        d[k] = json.loads(d[k]) if d.get(k) else []
    return d
