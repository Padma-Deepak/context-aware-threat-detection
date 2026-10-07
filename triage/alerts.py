"""Alert ingestion: real Defender/Sentinel alerts and Sigma detections over the ExCyTIn logs.

Two sources feed the queue:
  sentinel  rows of ExCyTIn's SecurityAlert table (Microsoft Defender XDR alerts from a real tenant
            under simulated attack). Alerts listed in a SecurityIncident's AlertIds are labelled
            "malicious": the incident confirms them.
  sigma     SigmaHQ rules compiled to SQL and run over the raw Device* tables. Hits are grouped per rule,
            device and hour into one alert. Unlabelled until a reviewer decides.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from triage.cases import CaseStore
from triage.excytin.db import IncidentDB
from triage.excytin.setup_db import INCIDENTS
from triage.memory import extract_entities, _lenient_json
from triage.sigma.compiler import Compiler, load_rules

RULES_DIR = Path(__file__).resolve().parent / "sigma" / "rules"
_SEVERITY = {"informational": "Informational", "low": "Low", "medium": "Medium", "high": "High", "critical": "High"}


def _incident_alert_ids(db: IncidentDB) -> set:
    cur = db._conn().cursor()
    cur.execute("SELECT AlertIds FROM SecurityIncident")
    ids = set()
    for (raw,) in cur.fetchall():
        parsed = _lenient_json(raw or "[]") or []
        ids.update(str(x).lower() for x in parsed)
    cur.close()
    return ids


def ingest_sentinel(store: CaseStore, db: IncidentDB, limit: int | None = None) -> int:
    linked = _incident_alert_ids(db)
    cur = db._conn().cursor()
    cur.execute("SELECT SystemAlertId, AlertName, AlertSeverity, TimeGenerated, Description, Entities, Tactics, "
                "Techniques, ProviderName FROM SecurityAlert ORDER BY TimeGenerated")
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    cur.close()
    seen, added = set(), 0
    for row in rows:
        aid = (row["SystemAlertId"] or "").lower()
        if not aid or aid in seen:
            continue
        seen.add(aid)
        techniques = _lenient_json(row.get("Techniques") or "[]") or []
        new = store.add_alert(
            external_id=f"sentinel:{db.incident}:{aid}", source="sentinel", incident=db.incident,
            title=row["AlertName"], severity=row["AlertSeverity"], time_=row["TimeGenerated"],
            entities=[list(e) for e in extract_entities(row)], attack=[str(t) for t in techniques if t],
            raw=[{k: row[k] for k in ("AlertName", "AlertSeverity", "TimeGenerated", "Description", "ProviderName",
                                      "Tactics", "Techniques")} | {"Entities": (row["Entities"] or "")[:4000]}],
            label="malicious" if aid in linked else None)
        added += bool(new)
        if limit and added >= limit:
            break
    return added


def ingest_sigma(store: CaseStore, db: IncidentDB, rules_dir: Path = RULES_DIR, limit_per_rule: int = 200) -> int:
    rules, _ = load_rules(rules_dir, Compiler(placeholder=db.placeholder))
    added = 0
    for rule in rules:
        res = db.run(rule.sql(limit_per_rule), rule.params)
        if res.error or not res.full_rows:
            continue
        groups = defaultdict(list)
        for row in res.full_rows:
            stamp = str(row.get("Timestamp") or "")
            groups[(row.get("DeviceName") or "?", stamp[:13])].append(row)
        for (device, hour), rows in groups.items():
            ents = set()
            for row in rows:
                ents |= extract_entities(row)
            new = store.add_alert(
                external_id=f"sigma:{db.incident}:{rule.id}:{device}:{hour}", source="sigma", incident=db.incident,
                title=f"Sigma: {rule.title}", severity=_SEVERITY.get(rule.level, "Medium"),
                time_=min(str(r.get("Timestamp") or "") for r in rows), entities=[list(e) for e in ents],
                attack=rule.attack_ids, raw=rows[:10] + [{"sigma_rule": rule.title, "sigma_id": rule.id,
                                                          "matched_rows": len(rows), "description": rule.description}])
            added += bool(new)
    return added


def ingest(store: CaseStore, incidents=INCIDENTS, sources=("sentinel", "sigma"), rules_dir=RULES_DIR) -> dict:
    out = {}
    for n in incidents:
        db = IncidentDB(n, max_rows=500)
        out[n] = {}
        if "sentinel" in sources:
            out[n]["sentinel"] = ingest_sentinel(store, db)
        if "sigma" in sources:
            out[n]["sigma"] = ingest_sigma(store, db, rules_dir)
    return out


def rules_report(rules_dir=RULES_DIR) -> str:
    rules, skipped = load_rules(rules_dir)
    lines = [f"{len(rules)} rules compile, {len(skipped)} skipped"]
    lines += [f"  ok    {r.title} -> {r.table} {r.attack_ids}" for r in rules]
    lines += [f"  skip  {Path(p).name}: {why}" for p, why in skipped]
    return "\n".join(lines)


if __name__ == "__main__":
    print(json.dumps(ingest(CaseStore()), indent=1))
