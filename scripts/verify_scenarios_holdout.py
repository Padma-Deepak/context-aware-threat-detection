"""
Verifies every scenario in scenarios_holdout.json against the live,
Postgres-backed data.py accessor functions -- the held-out counterpart to
verify_scenarios.py.

Requires db/seed_holdout.sql to have been loaded (it is NOT loaded
automatically by docker-entrypoint-initdb.d -- see the header comment in
that file for why, and the exact command to load it).

Usage:
    DATABASE_URL=postgresql://... python scripts/verify_scenarios_holdout.py
"""

import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
import data  # noqa: E402  (requires DATABASE_URL to be set; see db.py)

SCENARIOS_PATH = os.path.join(REPO_ROOT, "scenarios_holdout.json")

# Same generous window verify_scenarios.py uses, for the same reason: the
# oldest held-out log is ~30 hours old, so 168h (1 week) comfortably covers
# every relevant entry regardless of when this script runs relative to the
# seed.
WIDE_HOURS = 168


def jprint(label, obj):
    print(f"    {label}: {json.dumps(obj, indent=2)}")


def get_logs(ip):
    return data.query_logs(ip, WIDE_HOURS)


# ---------------------------------------------------------------------------
# Per-scenario verification. Each function gathers real evidence via
# data.py, prints it, and returns (ok: bool, reason: str).
# ---------------------------------------------------------------------------

def verify_H01(s):
    rep = data.lookup_ip_reputation("203.0.113.88")
    jprint("lookup_ip_reputation('203.0.113.88')", rep)
    ok = rep["malicious"] is True and rep["score"] == 100 and len(rep["sources_flagging"]) >= 3
    return ok, f"malicious={rep['malicious']}, score={rep['score']}, sources={rep['sources_flagging']}"


def verify_H02(s):
    rep = data.lookup_ip_reputation("203.0.113.5")
    jprint("lookup_ip_reputation('203.0.113.5')", rep)
    # The point of H02: this IP is deliberately unseeded. "Not found" must
    # come back as the well-formed zero record, not an error, and it must
    # be distinguishable from a *confirmed* clean IP (H03) by the caller.
    ok = rep["malicious"] is False and rep["score"] == 0 and rep["sources_flagging"] == [] and rep["first_seen"] is None
    return ok, f"malicious={rep['malicious']}, score={rep['score']}, first_seen={rep['first_seen']} -- unseeded, not confirmed-clean"


def verify_H03(s):
    rep = data.lookup_ip_reputation("192.0.2.222")
    jprint("lookup_ip_reputation('192.0.2.222')", rep)
    ok = rep["malicious"] is False and rep["score"] == 0 and rep["first_seen"] is not None
    return ok, f"malicious={rep['malicious']}, score={rep['score']}, first_seen={rep['first_seen']} (recent, but a real record, unlike H02)"


def verify_H04(s):
    rep = data.lookup_ip_reputation("198.51.100.90")
    geo = data.geolocate_ip("198.51.100.90")
    logs = get_logs("198.51.100.90")
    jprint("lookup_ip_reputation('198.51.100.90')", rep)
    jprint("geolocate_ip('198.51.100.90')", geo)
    jprint("query_logs('198.51.100.90', 168)", logs)
    suspicious_events = [l for l in logs["logs"] if l["event_type"] in ("port_scan", "failed_login")]
    ok = (
        rep["malicious"] is False
        and rep["score"] == 31  # exactly one point past agent.py's ">30" trigger
        and geo["found"] is True
        and len(suspicious_events) == 0
        and len(logs["logs"]) >= 1
    )
    return ok, f"malicious={rep['malicious']}, score={rep['score']} (just above the >30 trigger), suspicious_event_count={len(suspicious_events)}, log_count={len(logs['logs'])}"


def verify_H05(s):
    rep = data.lookup_ip_reputation("203.0.113.30")
    logs = get_logs("203.0.113.30")
    jprint("lookup_ip_reputation('203.0.113.30')", rep)
    jprint("query_logs('203.0.113.30', 168)", logs)
    mentions_cve = any("CVE-2025-90410" in l["detail"] for l in logs["logs"])
    cve = data.lookup_cve("CVE-2025-90410")
    jprint("lookup_cve('CVE-2025-90410')", cve)
    ok = (
        rep["malicious"] is True
        and mentions_cve
        and cve["found"] is True
        and cve["severity"] == "CRITICAL"
        and cve["cvss_score"] >= 9.0
    )
    return ok, f"ip_malicious={rep['malicious']}, logs_mention_cve={mentions_cve}, cve_severity={cve['severity']}, cvss={cve['cvss_score']}"


def verify_H06(s):
    dom = data.check_domain_reputation("metrics-sync-edge.io")
    jprint("check_domain_reputation('metrics-sync-edge.io')", dom)
    ok = dom["malicious"] is False and dom["category"] == "suspicious" and dom["score"] == 55 and len(dom["sources_flagging"]) == 1
    return ok, f"malicious={dom['malicious']}, category={dom['category']}, score={dom['score']}, sources={dom['sources_flagging']} -- one weak source, not confirmed either way"


def verify_H07(s):
    rep = data.lookup_ip_reputation("198.51.100.5")
    geo = data.geolocate_ip("198.51.100.5")
    logs = get_logs("198.51.100.5")
    jprint("lookup_ip_reputation('198.51.100.5')", rep)
    jprint("geolocate_ip('198.51.100.5')", geo)
    jprint("query_logs('198.51.100.5', 168)", logs)
    failed_logins = [l for l in logs["logs"] if l["event_type"] == "failed_login"]
    port_scans = [l for l in logs["logs"] if l["event_type"] == "port_scan"]
    ok = (
        rep["malicious"] is True
        and len(failed_logins) >= 3
        and len(port_scans) >= 1
        and geo["found"] is True
    )
    return ok, f"malicious={rep['malicious']}, failed_login_count={len(failed_logins)}, port_scan_count={len(port_scans)} -- brute-force AND scan combo, geo_found={geo['found']}"


def verify_H08(s):
    rep = data.lookup_ip_reputation("192.0.2.5")
    logs = get_logs("192.0.2.5")
    jprint("lookup_ip_reputation('192.0.2.5')", rep)
    jprint("query_logs('192.0.2.5', 168)", logs)
    ok = rep["malicious"] is False and 0 < rep["score"] < 30 and len(logs["logs"]) <= 1
    return ok, f"malicious={rep['malicious']}, score={rep['score']} (nonzero but below the >30 trigger), log_count={len(logs['logs'])}"


VERIFIERS = {
    "H01": verify_H01, "H02": verify_H02, "H03": verify_H03, "H04": verify_H04,
    "H05": verify_H05, "H06": verify_H06, "H07": verify_H07, "H08": verify_H08,
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
    print(f"\n{len(scenarios)} held-out scenarios checked, {len(failures)} failure(s).")
    if failures:
        print("\nFLAGGED SCENARIOS:")
        for sid, reason in failures:
            print(f"  - {sid}: {reason}")
        sys.exit(1)
    else:
        print("All held-out scenarios' evidence is consistent with their stated ground_truth.")


if __name__ == "__main__":
    main()
