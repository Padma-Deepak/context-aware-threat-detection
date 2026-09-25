"""
Data access layer for the security-investigation MCP server.

Phase 5: this module now queries PostgreSQL (see db/schema.sql for the
table definitions and db/seed.sql for the synthetic dataset -- the same
data that used to live here as in-memory dicts in Phase 1) via
mcp_server/db.py's connection pool.

Every accessor function below keeps the exact same name, parameters, and
return dict shape as the Phase 1 dict-backed version, including the
graceful "not found" behavior for unknown IPs/domains/CVEs (a well-formed
zero/null response, never an exception). mcp_server.py calls these
functions and is unaware the storage backend changed -- that stability is
the entire point of keeping this layer separate.

All underlying data is SYNTHETIC / FABRICATED for a benchmark project
(see db/seed.sql for details: RFC 5737 example IPs, invented domains and
orgs, non-real CVE IDs).
"""

from datetime import timezone

import db


def lookup_ip_reputation(ip: str) -> dict:
    """Look up reputation data for a single IP address.

    Returns:
        {"ip": str, "malicious": bool, "score": int,
         "sources_flagging": list[str], "first_seen": str | None}

    Unknown IPs return a well-formed "no data" record
    (malicious=False, score=0, sources_flagging=[], first_seen=None)
    rather than raising.
    """
    key = (ip or "").strip()
    with db.get_cursor() as cur:
        cur.execute(
            "SELECT malicious, score, sources_flagging, first_seen "
            "FROM ip_reputation WHERE ip = %s",
            (key,),
        )
        row = cur.fetchone()

    if row is None:
        return {
            "ip": ip,
            "malicious": False,
            "score": 0,
            "sources_flagging": [],
            "first_seen": None,
        }
    return {
        "ip": ip,
        "malicious": row["malicious"],
        "score": row["score"],
        "sources_flagging": list(row["sources_flagging"] or []),
        "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
    }


def geolocate_ip(ip: str) -> dict:
    """Look up coarse geolocation/network data for a single IP address.

    Returns:
        {"ip": str, "found": bool, "country": str | None, "city": str | None,
         "asn": str | None, "org": str | None}

    Unknown IPs return found=False with all other fields set to None
    rather than raising.
    """
    key = (ip or "").strip()
    with db.get_cursor() as cur:
        cur.execute(
            "SELECT country, city, asn, org FROM ip_geolocation WHERE ip = %s",
            (key,),
        )
        row = cur.fetchone()

    if row is None:
        return {
            "ip": ip,
            "found": False,
            "country": None,
            "city": None,
            "asn": None,
            "org": None,
        }
    return {
        "ip": ip,
        "found": True,
        "country": row["country"],
        "city": row["city"],
        "asn": row["asn"],
        "org": row["org"],
    }


def check_domain_reputation(domain: str) -> dict:
    """Look up reputation data for a single domain.

    Returns:
        {"domain": str, "malicious": bool, "score": int, "category": str,
         "sources_flagging": list[str], "first_seen": str | None}

    category is one of: malware, phishing, c2, suspicious, benign, unknown.
    Unknown domains return a well-formed "no data" record
    (malicious=False, score=0, category="unknown", sources_flagging=[],
    first_seen=None) rather than raising.
    """
    key = (domain or "").strip().lower()
    with db.get_cursor() as cur:
        cur.execute(
            "SELECT malicious, score, category, sources_flagging, first_seen "
            "FROM domain_reputation WHERE domain = %s",
            (key,),
        )
        row = cur.fetchone()

    if row is None:
        return {
            "domain": domain,
            "malicious": False,
            "score": 0,
            "category": "unknown",
            "sources_flagging": [],
            "first_seen": None,
        }
    return {
        "domain": domain,
        "malicious": row["malicious"],
        "score": row["score"],
        "category": row["category"],
        "sources_flagging": list(row["sources_flagging"] or []),
        "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
    }


def lookup_cve(cve_id: str) -> dict:
    """Look up a single synthetic CVE record by ID.

    Returns:
        {"cve_id": str, "found": bool, "severity": str | None,
         "cvss_score": float | None, "description": str | None,
         "affected_products": list[str], "published": str | None,
         "synthetic": True}

    All records in this dataset are fabricated for testing purposes
    (synthetic=True always). Unknown CVE IDs return found=False with the
    other data fields set to None/empty rather than raising.
    """
    key = (cve_id or "").strip().upper()
    with db.get_cursor() as cur:
        cur.execute(
            "SELECT severity, cvss_score, description, affected_products, published "
            "FROM cve_records WHERE cve_id = %s",
            (key,),
        )
        row = cur.fetchone()

    if row is None:
        return {
            "cve_id": cve_id,
            "found": False,
            "severity": None,
            "cvss_score": None,
            "description": None,
            "affected_products": [],
            "published": None,
            "synthetic": True,
        }
    return {
        "cve_id": key,
        "found": True,
        "severity": row["severity"],
        "cvss_score": float(row["cvss_score"]) if row["cvss_score"] is not None else None,
        "description": row["description"],
        "affected_products": list(row["affected_products"] or []),
        "published": row["published"].isoformat() if row["published"] else None,
        "synthetic": True,
    }


def query_logs(src_ip: str, hours: int = 24) -> dict:
    """Query security log entries for a given source IP within a time window.

    Returns:
        {"src_ip": str, "hours": int, "count": int,
         "logs": [{"id": str, "timestamp": str (ISO 8601 UTC),
                    "event_type": str, "src": str, "detail": str}, ...]}

    event_type is one of: failed_login, port_scan, outbound_conn, file_download.
    "id" surfaces security_logs.log_id (the original "LOG-0001"-style
    string identifier), not the internal SERIAL primary key, matching
    what the Phase 1 dict-backed version returned.
    Logs are sorted most-recent-first. An IP with no matching logs (known
    or unknown) returns count=0 and an empty logs list rather than raising.
    """
    key = (src_ip or "").strip()
    window_hours = hours if hours is not None else 24

    with db.get_cursor() as cur:
        cur.execute(
            "SELECT log_id, timestamp, event_type, src, detail "
            "FROM security_logs "
            "WHERE src = %s AND timestamp >= now() - (%s * interval '1 hour') "
            "ORDER BY timestamp DESC",
            (key, window_hours),
        )
        rows = cur.fetchall()

    logs = [
        {
            "id": row["log_id"],
            "timestamp": row["timestamp"].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": row["event_type"],
            "src": row["src"],
            "detail": row["detail"],
        }
        for row in rows
    ]

    return {
        "src_ip": src_ip,
        "hours": window_hours,
        "count": len(logs),
        "logs": logs,
    }
