"""
Phase 7-8: verify every scenario in scenarios.json against the live,
Postgres-backed data.py accessor functions (not a re-read of seed.sql or
scenarios.json's own rationale text).

For each scenario this script:
  1. Calls the real data.py accessor function(s) needed to investigate it.
  2. Prints the raw evidence returned.
  3. Runs an automated consistency check (hand-written per scenario,
     since each one hinges on a different combination of fields) and
     prints PASS/FAIL with the reasoning.

Usage:
    DATABASE_URL=postgresql://... python scripts/verify_scenarios.py
"""

import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
import data  # noqa: E402  (requires DATABASE_URL to be set; see db.py)

SCENARIOS_PATH = os.path.join(REPO_ROOT, "scenarios.json")

# A generous log window: the oldest seeded log is 70 hours old, so 168h
# (1 week) comfortably captures every relevant entry regardless of when
# this script actually runs relative to the seed.
WIDE_HOURS = 168


def jprint(label, obj):
    print(f"    {label}: {json.dumps(obj, indent=2)}")


def get_logs(ip):
    return data.query_logs(ip, WIDE_HOURS)


def log_ids(logs_result):
    return {log["id"] for log in logs_result["logs"]}


# ---------------------------------------------------------------------------
# Per-scenario verification. Each function gathers real evidence via
# data.py, prints it, and returns (ok: bool, reason: str).
# ---------------------------------------------------------------------------

def verify_S01(s):
    rep = data.lookup_ip_reputation("198.51.100.77")
    jprint("lookup_ip_reputation('198.51.100.77')", rep)
    ok = rep["malicious"] is True and rep["score"] >= 90 and len(rep["sources_flagging"]) >= 2
    return ok, f"malicious={rep['malicious']}, score={rep['score']}, sources={rep['sources_flagging']}"


def verify_S02(s):
    rep = data.lookup_ip_reputation("192.0.2.99")
    jprint("lookup_ip_reputation('192.0.2.99')", rep)
    ok = rep["malicious"] is True and rep["score"] >= 90
    return ok, f"malicious={rep['malicious']}, score={rep['score']}"


def verify_S03(s):
    rep = data.lookup_ip_reputation("203.0.113.200")
    jprint("lookup_ip_reputation('203.0.113.200')", rep)
    ok = rep["malicious"] is False and rep["score"] <= 10
    return ok, f"malicious={rep['malicious']}, score={rep['score']}"


def verify_S04(s):
    rep = data.lookup_ip_reputation("192.0.2.150")
    jprint("lookup_ip_reputation('192.0.2.150')", rep)
    ok = rep["malicious"] is False and rep["score"] <= 10
    return ok, f"malicious={rep['malicious']}, score={rep['score']}"


def verify_S05(s):
    dom = data.check_domain_reputation("secure-login-update.net")
    jprint("check_domain_reputation('secure-login-update.net')", dom)
    ok = dom["malicious"] is True and dom["category"] == "phishing" and dom["score"] >= 90
    return ok, f"malicious={dom['malicious']}, category={dom['category']}, score={dom['score']}"


def verify_S06(s):
    cve = data.lookup_cve("CVE-2025-90007")
    jprint("lookup_cve('CVE-2025-90007')", cve)
    ok = cve["found"] is True and cve["severity"] == "CRITICAL" and cve["cvss_score"] >= 9.0
    return ok, f"found={cve['found']}, severity={cve['severity']}, cvss={cve['cvss_score']}"


def verify_S07(s):
    rep = data.lookup_ip_reputation("203.0.113.45")
    geo = data.geolocate_ip("203.0.113.45")
    logs = get_logs("203.0.113.45")
    jprint("lookup_ip_reputation('203.0.113.45')", rep)
    jprint("geolocate_ip('203.0.113.45')", geo)
    jprint("query_logs('203.0.113.45', 168)", logs)
    ids = log_ids(logs)
    failed_logins = [l for l in logs["logs"] if l["event_type"] == "failed_login"]
    has_brute_force_set = {"LOG-0004", "LOG-0005", "LOG-0006", "LOG-0007"}.issubset(ids)
    ok = rep["malicious"] is True and len(failed_logins) >= 4 and has_brute_force_set and geo["found"] is True
    return ok, f"malicious={rep['malicious']}, failed_login_count={len(failed_logins)}, brute_force_logs_present={has_brute_force_set}, geo_found={geo['found']}"


def verify_S08(s):
    rep = data.lookup_ip_reputation("198.51.100.12")
    logs = get_logs("198.51.100.12")
    jprint("lookup_ip_reputation('198.51.100.12')", rep)
    jprint("query_logs('198.51.100.12', 168)", logs)
    port_scans = [l for l in logs["logs"] if l["event_type"] == "port_scan"]
    ok = rep["malicious"] is True and len(port_scans) >= 2
    return ok, f"malicious={rep['malicious']}, port_scan_count={len(port_scans)}"


def verify_S09(s):
    rep = data.lookup_ip_reputation("203.0.113.10")
    logs = get_logs("203.0.113.10")
    dom = data.check_domain_reputation("cdn-analytics-node7.info")
    jprint("lookup_ip_reputation('203.0.113.10')", rep)
    jprint("query_logs('203.0.113.10', 168)", logs)
    jprint("check_domain_reputation('cdn-analytics-node7.info')", dom)
    mentions_domain = any("cdn-analytics-node7.info" in l["detail"] for l in logs["logs"])
    ok = rep["malicious"] is True and mentions_domain and dom["malicious"] is True
    return ok, f"ip_malicious={rep['malicious']}, logs_mention_domain={mentions_domain}, domain_malicious={dom['malicious']}"


def verify_S10(s):
    rep = data.lookup_ip_reputation("192.0.2.10")
    logs = get_logs("192.0.2.10")
    jprint("lookup_ip_reputation('192.0.2.10')", rep)
    jprint("query_logs('192.0.2.10', 168)", logs)
    suspicious_events = [l for l in logs["logs"] if l["event_type"] in ("port_scan", "failed_login")]
    ok = rep["malicious"] is False and rep["score"] <= 10 and len(suspicious_events) == 0
    return ok, f"malicious={rep['malicious']}, score={rep['score']}, suspicious_event_count={len(suspicious_events)}"


def verify_S11(s):
    rep = data.lookup_ip_reputation("198.51.100.150")
    logs = get_logs("198.51.100.150")
    jprint("lookup_ip_reputation('198.51.100.150')", rep)
    jprint("query_logs('198.51.100.150', 168)", logs)
    suspicious_events = [l for l in logs["logs"] if l["event_type"] in ("port_scan", "failed_login")]
    ok = rep["malicious"] is False and rep["score"] <= 10 and len(suspicious_events) == 0
    return ok, f"malicious={rep['malicious']}, score={rep['score']}, suspicious_event_count={len(suspicious_events)}"


def verify_S12(s):
    rep = data.lookup_ip_reputation("203.0.113.66")
    geo = data.geolocate_ip("203.0.113.66")
    logs = get_logs("203.0.113.66")
    dom = data.check_domain_reputation("cdn-analytics-node7.info")
    jprint("lookup_ip_reputation('203.0.113.66')", rep)
    jprint("geolocate_ip('203.0.113.66')", geo)
    jprint("query_logs('203.0.113.66', 168)", logs)
    jprint("check_domain_reputation('cdn-analytics-node7.info')", dom)
    mentions_domain = any("cdn-analytics-node7.info" in l["detail"] for l in logs["logs"])
    # The hard-case signature: reputation ALONE is inconclusive, but the
    # cross-referenced domain is independently confirmed malicious.
    reputation_inconclusive = rep["malicious"] is False and 0 < rep["score"] < 90
    ok = reputation_inconclusive and mentions_domain and dom["malicious"] is True
    return ok, f"ip_malicious={rep['malicious']} (score={rep['score']}, inconclusive alone), logs_mention_domain={mentions_domain}, domain_malicious={dom['malicious']}"


def verify_S13(s):
    rep = data.lookup_ip_reputation("198.51.100.33")
    logs = get_logs("198.51.100.33")
    dom = data.check_domain_reputation("datasync-relay.online")
    jprint("lookup_ip_reputation('198.51.100.33')", rep)
    jprint("query_logs('198.51.100.33', 168)", logs)
    jprint("check_domain_reputation('datasync-relay.online')", dom)
    mentions_domain = any("datasync-relay.online" in l["detail"] for l in logs["logs"])
    reputation_inconclusive = rep["malicious"] is False and 0 < rep["score"] < 90
    ok = reputation_inconclusive and mentions_domain and dom["malicious"] is True
    return ok, f"ip_malicious={rep['malicious']} (score={rep['score']}, inconclusive alone), logs_mention_domain={mentions_domain}, domain_malicious={dom['malicious']}"


def verify_S14(s):
    rep = data.lookup_ip_reputation("198.51.100.200")
    geo = data.geolocate_ip("198.51.100.200")
    logs = get_logs("198.51.100.200")
    jprint("lookup_ip_reputation('198.51.100.200')", rep)
    jprint("geolocate_ip('198.51.100.200')", geo)
    jprint("query_logs('198.51.100.200', 168)", logs)
    failed_logins = [l for l in logs["logs"] if l["event_type"] == "failed_login"]
    # The trap: event_type alone looks like the brute-force pattern, but
    # there must be exactly ONE failed_login, not a burst like S07's.
    ok = (
        rep["malicious"] is False
        and rep["score"] <= 10
        and len(failed_logins) == 1
        and geo["found"] is True
    )
    return ok, f"malicious={rep['malicious']}, score={rep['score']}, failed_login_count={len(failed_logins)} (must be exactly 1, not a burst), geo_found={geo['found']}"


def verify_S15(s):
    rep = data.lookup_ip_reputation("192.0.2.77")
    logs = get_logs("192.0.2.77")
    dom = data.check_domain_reputation("cloudmetrics-stats.io")
    jprint("lookup_ip_reputation('192.0.2.77')", rep)
    jprint("query_logs('192.0.2.77', 168)", logs)
    jprint("check_domain_reputation('cloudmetrics-stats.io')", dom)
    # The ambiguous-case signature: NEITHER side confirms malicious, and
    # NEITHER side is squeaky clean either -- genuinely thin evidence.
    ip_inconclusive = rep["malicious"] is False and rep["score"] > 10
    domain_inconclusive = dom["malicious"] is False and dom["category"] == "suspicious"
    ok = ip_inconclusive and domain_inconclusive and len(logs["logs"]) <= 3
    return ok, f"ip_malicious={rep['malicious']} (score={rep['score']}), domain_malicious={dom['malicious']} (category={dom['category']}), log_count={len(logs['logs'])} -- thin on both sides"


def verify_S16(s):
    dom = data.check_domain_reputation("quickfile-share.top")
    jprint("check_domain_reputation('quickfile-share.top')", dom)
    ok = dom["malicious"] is False and dom["category"] == "suspicious" and len(dom["sources_flagging"]) == 0
    return ok, f"malicious={dom['malicious']}, category={dom['category']}, sources={dom['sources_flagging']} -- no source names, not confirmed either way"


def verify_S17(s):
    dom = data.check_domain_reputation("cloudmetrics-stats.io")
    jprint("check_domain_reputation('cloudmetrics-stats.io')", dom)
    ok = dom["malicious"] is False and dom["category"] == "suspicious" and len(dom["sources_flagging"]) == 1
    return ok, f"malicious={dom['malicious']}, category={dom['category']}, sources={dom['sources_flagging']} -- exactly one weak source"


def verify_S18(s):
    cve = data.lookup_cve("CVE-2024-90310")
    jprint("lookup_cve('CVE-2024-90310')", cve)
    ok = cve["found"] is True and cve["severity"] == "MEDIUM" and 4.0 <= cve["cvss_score"] <= 7.0
    return ok, f"found={cve['found']}, severity={cve['severity']}, cvss={cve['cvss_score']} -- moderate, not critical, no exploitation evidence available"


VERIFIERS = {
    "S01": verify_S01, "S02": verify_S02, "S03": verify_S03, "S04": verify_S04,
    "S05": verify_S05, "S06": verify_S06, "S07": verify_S07, "S08": verify_S08,
    "S09": verify_S09, "S10": verify_S10, "S11": verify_S11, "S12": verify_S12,
    "S13": verify_S13, "S14": verify_S14, "S15": verify_S15, "S16": verify_S16,
    "S17": verify_S17, "S18": verify_S18,
}


def main():
    with open(SCENARIOS_PATH) as f:
        scenarios = json.load(f)

    failures = []
    for s in scenarios:
        sid = s["id"]
        print("=" * 78)
        print(f"{sid} [{s['difficulty']}] ground_truth={s['ground_truth']}")
        print(f"  task: {s['task']}")
        verifier = VERIFIERS.get(sid)
        if verifier is None:
            print(f"  !! NO VERIFIER DEFINED for {sid}")
            failures.append((sid, "no verifier defined"))
            continue
        try:
            ok, reason = verifier(s)
        except Exception as exc:
            print(f"  !! EXCEPTION during verification: {exc!r}")
            failures.append((sid, f"exception: {exc!r}"))
            continue
        status = "PASS" if ok else "FAIL"
        print(f"  -> {status}: {reason}")
        if not ok:
            failures.append((sid, reason))

    print("=" * 78)
    print(f"\n{len(scenarios)} scenarios checked, {len(failures)} failure(s).")
    if failures:
        print("\nFLAGGED SCENARIOS:")
        for sid, reason in failures:
            print(f"  - {sid}: {reason}")
        sys.exit(1)
    else:
        print("All scenarios' evidence is consistent with their stated ground_truth.")


if __name__ == "__main__":
    main()
