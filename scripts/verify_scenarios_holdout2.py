"""
Verifies every scenario in scenarios_holdout2.json against the live,
Postgres-backed data.py accessors. Requires db/seed_holdout2.sql to be
loaded (see its header comment).

Usage:
    DATABASE_URL=postgresql://... python scripts/verify_scenarios_holdout2.py
"""

import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
import data  # noqa: E402

SCENARIOS_PATH = os.path.join(REPO_ROOT, "scenarios_holdout2.json")
WIDE_HOURS = 168


def logs_of(ip):
    return data.query_logs(ip, WIDE_HOURS)["logs"]


def mentions(logs, needle):
    return any(needle in l["detail"] for l in logs)


def verify_J01():
    rep, logs = data.lookup_ip_reputation("203.0.113.17"), logs_of("203.0.113.17")
    dom = data.check_domain_reputation("telemetry-cache-node.net")
    ok = rep["malicious"] and mentions(logs, "telemetry-cache-node.net") and dom["malicious"] and dom["category"] == "c2"
    return ok, f"ip_malicious={rep['malicious']}, logs_mention_c2={mentions(logs, 'telemetry-cache-node.net')}, domain={dom['category']}"


def verify_J02():
    rep = data.lookup_ip_reputation("192.0.2.41")
    ok = not rep["malicious"] and rep["score"] <= 10 and rep["first_seen"] is not None
    return ok, f"malicious={rep['malicious']}, score={rep['score']}"


def verify_J03():
    rep, logs = data.lookup_ip_reputation("198.51.100.44"), logs_of("198.51.100.44")
    dom = data.check_domain_reputation("payroll-portal-verify.com")
    ok = rep["malicious"] and mentions(logs, "payroll-portal-verify.com") and dom["malicious"] and dom["category"] == "phishing"
    return ok, f"ip_malicious={rep['malicious']}, domain={dom['category']}"


def verify_J04():
    rep, logs = data.lookup_ip_reputation("203.0.113.140"), logs_of("203.0.113.140")
    dom = data.check_domain_reputation("telemetry-cache-node.net")
    inconclusive = not rep["malicious"] and 0 < rep["score"] < 90
    ok = inconclusive and mentions(logs, "telemetry-cache-node.net") and dom["malicious"]
    return ok, f"ip_malicious={rep['malicious']} (score={rep['score']}), logs_mention_c2={mentions(logs, 'telemetry-cache-node.net')}, domain_malicious={dom['malicious']}"


def verify_J05():
    dom = data.check_domain_reputation("docs-mirror-cdn.org")
    ok = not dom["malicious"] and dom["category"] == "benign" and dom["score"] <= 10
    return ok, f"malicious={dom['malicious']}, category={dom['category']}"


def verify_J06():
    dom = data.check_domain_reputation("fastupdate-dl.xyz")
    ok = not dom["malicious"] and dom["category"] == "suspicious" and dom["sources_flagging"] == []
    return ok, f"malicious={dom['malicious']}, category={dom['category']}, score={dom['score']}"


def verify_J07():
    rep, logs = data.lookup_ip_reputation("198.51.100.121"), logs_of("198.51.100.121")
    cve = data.lookup_cve("CVE-2026-90022")
    ok = rep["malicious"] and mentions(logs, "CVE-2026-90022") and cve["found"] and cve["severity"] == "HIGH"
    return ok, f"ip_malicious={rep['malicious']}, logs_mention_cve={mentions(logs, 'CVE-2026-90022')}, cve={cve['severity']}"


def verify_J08():
    rep, geo, logs = data.lookup_ip_reputation("192.0.2.63"), data.geolocate_ip("192.0.2.63"), logs_of("192.0.2.63")
    bad = [l for l in logs if l["event_type"] in ("port_scan", "failed_login")]
    ok = not rep["malicious"] and rep["score"] > 30 and geo["found"] and "Example Corp" in geo["org"] and not bad
    return ok, f"malicious={rep['malicious']}, score={rep['score']}, org={geo['org']}, suspicious_events={len(bad)}"


def verify_J09():
    rep, logs = data.lookup_ip_reputation("198.51.100.230"), logs_of("198.51.100.230")
    scans = [l for l in logs if l["event_type"] == "port_scan"]
    ok = rep["malicious"] and len(scans) >= 2
    return ok, f"malicious={rep['malicious']}, port_scans={len(scans)}"


def verify_J10():
    rep, logs = data.lookup_ip_reputation("192.0.2.180"), logs_of("192.0.2.180")
    dom = data.check_domain_reputation("fastupdate-dl.xyz")
    ok = not rep["malicious"] and rep["score"] > 10 and mentions(logs, "fastupdate-dl.xyz") and not dom["malicious"] and dom["category"] == "suspicious"
    return ok, f"ip_malicious={rep['malicious']} (score={rep['score']}), domain={dom['category']} -- thin on both sides"


VERIFIERS = {f"J{i:02d}": globals()[f"verify_J{i:02d}"] for i in range(1, 11)}


def main():
    with open(SCENARIOS_PATH) as f:
        scenarios = json.load(f)

    failures = []
    for s in scenarios:
        sid = s["id"]
        try:
            ok, reason = VERIFIERS[sid]()
        except Exception as exc:
            ok, reason = False, f"exception: {exc!r}"
        print(f"{sid} [{s['difficulty']}] ground_truth={s['ground_truth']} -> {'PASS' if ok else 'FAIL'}: {reason}")
        if not ok:
            failures.append(sid)

    print(f"\n{len(scenarios)} scenarios checked, {len(failures)} failure(s).")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
