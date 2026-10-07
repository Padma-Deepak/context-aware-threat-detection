"""Indicator lookups. Each returns a small dict the agent can read; ``found`` is always present, and
"not found" is never dressed up as "clean"."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
from pathlib import Path

from triage.intel.http import ROOT, cache

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
DAY = 86400

_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$", re.I)
_HASH = re.compile(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
_lock = threading.Lock()
_kev = None
_attack = None


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


# ── CISA KEV ──
def kev_index() -> dict:
    global _kev
    with _lock:
        if _kev is None:
            status, body = cache().request("GET", KEV_URL, max_age=DAY)
            data = json.loads(body) if status == 200 else {"vulnerabilities": []}
            _kev = {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}
    return _kev


def lookup_kev(cve: str) -> dict:
    v = kev_index().get(cve.upper())
    if not v:
        return {"source": "CISA KEV", "cve": cve, "found": False}
    return {"source": "CISA KEV", "cve": cve, "found": True, "known_exploited": True,
            "vendor": v.get("vendorProject"), "product": v.get("product"), "name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"), "ransomware_use": v.get("knownRansomwareCampaignUse"),
            "required_action": v.get("requiredAction")}


# ── NVD ──
def lookup_nvd(cve: str) -> dict:
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else None
    status, body = cache().request("GET", NVD_URL, params={"cveId": cve.upper()}, headers=headers, max_age=7 * DAY)
    if status != 200:
        return {"source": "NVD", "cve": cve, "found": False, "error": f"HTTP {status}"}
    vulns = json.loads(body).get("vulnerabilities", [])
    if not vulns:
        return {"source": "NVD", "cve": cve, "found": False}
    c = vulns[0]["cve"]
    metrics = c.get("metrics", {})
    score = severity = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            d = metrics[key][0]["cvssData"]
            score, severity = d.get("baseScore"), d.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            break
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    return {"source": "NVD", "cve": c["id"], "found": True, "cvss": score, "severity": severity,
            "published": c.get("published", "")[:10], "description": desc[:500],
            "cwe": [d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])][:3]}


# ── MITRE ATT&CK ──
def attack_index() -> dict:
    """technique id -> {name, tactics, url, description}. Built once from the 50 MB STIX bundle and saved."""
    global _attack
    with _lock:
        if _attack is None:
            path = Path(os.getenv("TRIAGE_ATTACK_INDEX", str(ROOT / ".intel_cache" / "attack_index.json")))
            if path.exists():
                _attack = json.loads(path.read_text())
            else:
                status, body = cache().request("GET", ATTACK_URL, max_age=30 * DAY, timeout=120)
                _attack = {}
                if status == 200:
                    for obj in json.loads(body).get("objects", []):
                        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                            continue
                        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
                        if ref:
                            _attack[ref["external_id"].upper()] = {
                                "name": obj.get("name"), "url": ref.get("url"),
                                "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                                "description": (obj.get("description") or "")[:400]}
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps(_attack))
    return _attack


def lookup_attack(technique: str) -> dict:
    t = attack_index().get(technique.upper())
    if not t:
        return {"source": "MITRE ATT&CK", "technique": technique, "found": False}
    return {"source": "MITRE ATT&CK", "technique": technique.upper(), "found": True, **t}


def attack_by_name(name: str) -> list[str]:
    """Technique ids whose name matches (case-insensitive substring), for alerts that only give names."""
    n = name.lower()
    return [tid for tid, t in attack_index().items() if n and n in (t["name"] or "").lower()][:5]


# ── keyed sources ──
def lookup_abuseipdb(ip: str) -> dict:
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        return {"source": "AbuseIPDB", "ip": ip, "found": False, "skipped": "set ABUSEIPDB_API_KEY"}
    if not _public_ip(ip):
        return {"source": "AbuseIPDB", "ip": ip, "found": False, "skipped": "not a public IP; not sent"}
    status, body = cache().request("GET", ABUSEIPDB_URL, params={"ipAddress": ip, "maxAgeInDays": 90},
                                   headers={"Key": key, "Accept": "application/json"}, max_age=DAY)
    if status != 200:
        return {"source": "AbuseIPDB", "ip": ip, "found": False, "error": f"HTTP {status}"}
    d = json.loads(body).get("data", {})
    return {"source": "AbuseIPDB", "ip": ip, "found": bool(d.get("totalReports")),
            "abuse_confidence": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
            "country": d.get("countryCode"), "isp": d.get("isp"), "usage": d.get("usageType"),
            "last_reported": d.get("lastReportedAt")}


def lookup_threatfox(indicator: str) -> dict:
    key = os.getenv("ABUSECH_AUTH_KEY")
    if not key:
        return {"source": "ThreatFox", "ioc": indicator, "found": False, "skipped": "set ABUSECH_AUTH_KEY"}
    status, body = cache().request("POST", THREATFOX_URL, json_body={"query": "search_ioc", "search_term": indicator},
                                   headers={"Auth-Key": key}, max_age=DAY)
    if status != 200:
        return {"source": "ThreatFox", "ioc": indicator, "found": False, "error": f"HTTP {status}"}
    d = json.loads(body)
    rows = d.get("data") if isinstance(d.get("data"), list) else []
    if not rows:
        return {"source": "ThreatFox", "ioc": indicator, "found": False}
    r = rows[0]
    return {"source": "ThreatFox", "ioc": indicator, "found": True, "threat_type": r.get("threat_type"),
            "malware": r.get("malware_printable"), "confidence": r.get("confidence_level"),
            "first_seen": r.get("first_seen"), "tags": r.get("tags")}


# ── dispatch ──
def classify(indicator: str) -> str:
    v = indicator.strip()
    if _CVE.match(v):
        return "cve"
    if _TECHNIQUE.match(v):
        return "technique"
    if _HASH.match(v):
        return "hash"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "." in v and " " not in v:
        return "domain"
    return "unknown"


def lookup_indicator(indicator: str) -> list[dict]:
    kind = classify(indicator)
    v = indicator.strip()
    if kind == "cve":
        return [lookup_nvd(v), lookup_kev(v)]
    if kind == "technique":
        return [lookup_attack(v)]
    if kind == "ip":
        return [lookup_abuseipdb(v), lookup_threatfox(v)] if _public_ip(v) else [
            {"source": "local", "ip": v, "found": False, "note": "private or reserved address; not sent to external intel"}]
    if kind in ("domain", "hash"):
        return [lookup_threatfox(v)]
    return [{"source": "none", "indicator": v, "found": False, "note": "not a CVE, ATT&CK id, IP, domain or hash"}]


def enrich(indicator: str) -> str:
    """Text form for the agent's threat_intel tool."""
    out = []
    for r in lookup_indicator(indicator):
        out.append(json.dumps(r, default=str))
    return "\n".join(out)
