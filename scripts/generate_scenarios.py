"""Deterministically generate a large, labelled scenario set plus its seed data.

Hand-writing scenarios does not scale past a few dozen and invites unconscious
fitting. This generator builds each scenario from an *archetype* whose ground
truth is true by construction (for example "malicious_ip" always has a high
score, several flagging sources and hostile log lines), then writes:

    db/seed_generated.sql        INSERTs for the synthetic entities
    scenarios_generated.json     scenarios, grouped into chains of CHAIN_SIZE

Same seed => byte-identical output. Entities are drawn from RFC 5737 IP ranges,
invented domains and synthetic CVE IDs, and never collide with anything already
in db/seed*.sql. Verify the result against a live database with
scripts/verify_extended.py.

Usage:
    python scripts/generate_scenarios.py --n 48 --seed 20260930
"""

import argparse
import json
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED_GLOB = "db/seed*.sql"
CHAIN_SIZE = 8

SOURCES = ["VirusTotal", "AbuseIPDB", "GreyNoise", "SpamhausSynthetic"]
GEO = [
    ("Ukraine", "Kharkiv", "AS65011", "Slobozhan Telecom (synthetic)"),
    ("Kenya", "Nairobi", "AS65022", "Savanna Data Ltd (synthetic)"),
    ("Thailand", "Chiang Mai", "AS65033", "Lanna Cloud Co (synthetic)"),
    ("Argentina", "Cordoba", "AS65044", "Pampa Hosting SA (synthetic)"),
    ("Germany", "Leipzig", "AS65055", "Elbe Rechenzentrum GmbH (synthetic)"),
    ("Japan", "Sendai", "AS65066", "Tohoku Net KK (synthetic)"),
    ("Canada", "Calgary", "AS65077", "Prairie Transit Inc (synthetic)"),
    ("Turkey", "Izmir", "AS65088", "Ege Bilisim AS (synthetic)"),
]
WORDS_A = ["north", "delta", "quartz", "ember", "harbor", "cobalt", "willow", "signal", "amber", "vector", "lumen", "prairie"]
WORDS_B = ["sync", "portal", "cdn", "update", "relay", "share", "metrics", "login", "cloud", "docs", "edge", "assets"]
TLDS = ["com", "net", "io", "info", "xyz", "site", "online"]
HOSTS = ["bastion-03", "vpn-04", "fs-05", "web-07", "ws-203", "db-02", "mail-01"]

# archetype -> (count share, ground truth, difficulty)
ARCHETYPES = {
    "malicious_ip": (8, "MALICIOUS", "easy"),
    "benign_ip": (8, "BENIGN", "easy"),
    "threshold_trap_ip": (6, "BENIGN", "medium"),
    "unseeded_ip": (6, "ESCALATE", "hard"),
    "suspicious_domain": (6, "ESCALATE", "ambiguous"),
    "malicious_domain": (6, "MALICIOUS", "easy"),
    "benign_domain": (4, "BENIGN", "easy"),
    "cve_only": (4, "ESCALATE", "ambiguous"),
}


def q(text):
    return "'" + str(text).replace("'", "''") + "'"


def arr(items):
    return "ARRAY[" + ", ".join(q(i) for i in items) + "]::TEXT[]" if items else "ARRAY[]::TEXT[]"


def used_text():
    return "\n".join(p.read_text() for p in sorted(ROOT.glob(SEED_GLOB)) if p.name != "seed_generated.sql")


class Pool:
    """Hands out unique IPs / domains / CVE IDs not present in any existing seed."""

    def __init__(self, rng):
        self.rng, self.text = rng, used_text()
        self.ips = [f"{p}.{i}" for p in ("192.0.2", "198.51.100", "203.0.113") for i in range(1, 255)]
        self.rng.shuffle(self.ips)
        self.domains, self.cve_n, self.log_n = set(), 0, 0

    def ip(self):
        while True:
            ip = self.ips.pop()
            if not re.search(rf"'{re.escape(ip)}'", self.text):
                return ip

    def domain(self):
        while True:
            d = f"{self.rng.choice(WORDS_A)}-{self.rng.choice(WORDS_B)}.{self.rng.choice(TLDS)}"
            if d not in self.domains and d not in self.text:
                self.domains.add(d)
                return d

    def cve(self):
        self.cve_n += 1
        return f"CVE-2026-93{self.cve_n:03d}"

    def log_id(self):
        self.log_n += 1
        return f"LOG-G{self.log_n:03d}"


def build(n, seed):
    rng = random.Random(seed)
    pool = Pool(rng)
    total_share = sum(v[0] for v in ARCHETYPES.values())
    plan = []
    for name, (share, _truth, _diff) in ARCHETYPES.items():
        plan += [name] * max(1, round(n * share / total_share))
    rng.shuffle(plan)
    plan = plan[:n]

    ip_rows, geo_rows, dom_rows, cve_rows, log_rows, scenarios = [], [], [], [], [], []

    def add_logs(ip, entries):
        for hours, etype, detail in entries:
            log_rows.append((pool.log_id(), hours, etype, ip, detail))

    for i, arch in enumerate(plan, start=1):
        _, truth, diff = ARCHETYPES[arch]
        sid = f"G{i:02d}"
        first_recent = f"2026-0{rng.randint(5, 9)}-{rng.randint(10, 28)}"
        first_old = f"20{rng.randint(22, 25)}-{rng.randint(1, 12):02d}-{rng.randint(10, 28)}"
        geo = rng.choice(GEO)
        host = rng.choice(HOSTS)
        s = {"id": sid, "archetype": arch, "difficulty": diff, "ground_truth": truth}

        if arch == "malicious_ip":
            ip = pool.ip()
            srcs = rng.sample(SOURCES, rng.randint(2, 4))
            ip_rows.append((ip, "TRUE", rng.randint(80, 99), srcs, first_recent))
            geo_rows.append((ip,) + geo)
            kind = rng.choice(["brute", "scan_exploit", "exfil"])
            if kind == "brute":
                add_logs(ip, [
                    (rng.uniform(1, 6), "failed_login", f"Failed SSH login for user 'root' on {host} (attempt 30 of 45 in 4 minutes)."),
                    (rng.uniform(0.5, 1), "failed_login", f"Failed SSH login for user 'admin' on {host} (attempt 45 of 45 in 4 minutes), account lockout triggered."),
                ])
            elif kind == "scan_exploit":
                add_logs(ip, [
                    (rng.uniform(2, 8), "port_scan", f"TCP SYN scan across 1-1024 on {host}."),
                    (rng.uniform(0.5, 2), "outbound_conn", f"Exploit attempt against an exposed service on {host} immediately after the scan."),
                ])
            else:
                add_logs(ip, [
                    (rng.uniform(1, 5), "file_download", f"{host} uploaded {rng.randint(2, 9)} GB of archived data to this address in 12 minutes."),
                    (rng.uniform(0.5, 1), "outbound_conn", f"Repeated large TLS uploads from {host} to this address, ending in a connection reset."),
                ])
            s["task"] = rng.choice([
                f"{ip} is generating suspicious activity against {host}. Investigate and recommend an action.",
                f"Our IDS raised alerts naming {ip}. Is this address a real threat?",
                f"Please assess {ip}: it keeps appearing in alerts on {host}.",
            ])
            s["expected_tools"] = ["lookup_ip_reputation", "query_logs", "geolocate_ip"]
            s["rationale"] = "High score, several flagging sources and hostile log lines: unambiguous by construction."

        elif arch == "benign_ip":
            ip = pool.ip()
            ip_rows.append((ip, "FALSE", rng.randint(0, 12), [], first_old))
            geo_rows.append((ip,) + geo)
            add_logs(ip, [(rng.uniform(2, 20), "file_download", "Downloaded a routine vendor update package, signature verified.")])
            s["task"] = rng.choice([
                f"{ip} shows up in our network logs. Is it something we should worry about?",
                f"Can you check whether {ip} is a problem? It appeared in a routine report.",
            ])
            s["expected_tools"] = ["lookup_ip_reputation", "query_logs"]
            s["rationale"] = "Low score, old first_seen, no flagging sources, routine signed download: clean by construction."

        elif arch == "threshold_trap_ip":
            ip = pool.ip()
            ip_rows.append((ip, "FALSE", rng.randint(31, 44), ["GreyNoise"], first_old))
            geo_rows.append((ip,) + geo)
            add_logs(ip, [(rng.uniform(3, 18), "outbound_conn", "Routine outbound HTTPS to a public CDN, nothing unusual.")])
            s["task"] = f"{ip} has a middling reputation score. Investigate and tell us whether we should act."
            s["expected_tools"] = ["lookup_ip_reputation", "geolocate_ip", "query_logs"]
            s["rationale"] = "Score just above the prompt's >30 trigger from one noisy source, but every deeper check is clean."

        elif arch == "unseeded_ip":
            ip = pool.ip()  # deliberately no rows anywhere
            s["task"] = rng.choice([
                f"We saw a single connection attempt from {ip} and nothing else. Threat, safe, or something else?",
                f"{ip} touched {host} once. Can you tell us what it is?",
            ])
            s["expected_tools"] = ["lookup_ip_reputation"]
            s["rationale"] = "Never seeded, so every tool returns no data. Absence of evidence: ESCALATE, not BENIGN."

        elif arch == "suspicious_domain":
            d = pool.domain()
            dom_rows.append((d, "FALSE", "suspicious", rng.randint(46, 62), ["GreyNoise"], first_recent))
            s["task"] = f"An analyst flagged {d} as 'maybe weird'. Can you confirm one way or the other?"
            s["expected_tools"] = ["check_domain_reputation"]
            s["rationale"] = "Suspicious category, mid score, one weak source: not clean enough for BENIGN, not confirmed for MALICIOUS."

        elif arch == "malicious_domain":
            d = pool.domain()
            cat = rng.choice(["c2", "phishing", "malware"])
            dom_rows.append((d, "TRUE", cat, rng.randint(85, 97), rng.sample(SOURCES, rng.randint(2, 3)), first_recent))
            s["task"] = f"A user reported an email linking to {d}. Is this domain malicious?"
            s["expected_tools"] = ["check_domain_reputation"]
            s["rationale"] = f"Category {cat}, score >= 85 from multiple sources: unambiguous by construction."

        elif arch == "benign_domain":
            d = pool.domain()
            dom_rows.append((d, "FALSE", "benign", rng.randint(0, 8), [], first_old))
            s["task"] = f"Our proxy logged traffic to {d}. Should we block it?"
            s["expected_tools"] = ["check_domain_reputation"]
            s["rationale"] = "Benign category, near-zero score, old first_seen: clean by construction."

        else:  # cve_only
            c = pool.cve()
            sev, cvss = rng.choice([("MEDIUM", 5.8), ("HIGH", 7.5), ("HIGH", 8.1)])
            cve_rows.append((c, sev, cvss,
                             f"[SYNTHETIC] Improper input validation in ExampleSuite {rng.randint(2, 9)}.x allows limited information disclosure.",
                             [f"ExampleSuite {rng.randint(2, 9)}.x"], f"2026-0{rng.randint(1, 6)}-1{rng.randint(0, 9)}"))
            s["task"] = f"A scan reported {c} on one of our servers, with no sign of exploitation. How urgent is it?"
            s["expected_tools"] = ["lookup_cve"]
            s["rationale"] = "A CVE with no exploitation evidence is ESCALATE in this benchmark (same convention as S06/S18)."

        scenarios.append(s)

    # Balanced chains: shuffle then cut into CHAIN_SIZE blocks.
    order = list(range(len(scenarios)))
    rng.shuffle(order)
    for pos, idx in enumerate(order):
        scenarios[idx]["chain"] = f"g{pos // CHAIN_SIZE + 1}"
    scenarios = [scenarios[idx] for idx in order]  # chains contiguous, order within a chain shuffled
    return scenarios, ip_rows, geo_rows, dom_rows, cve_rows, log_rows


def render_sql(ip_rows, geo_rows, dom_rows, cve_rows, log_rows, seed, n):
    out = [
        f"-- GENERATED by scripts/generate_scenarios.py --n {n} --seed {seed}. Do not edit by hand.",
        "-- Synthetic data only. Not loaded by docker-compose; load once with:",
        "--   docker compose exec -T postgres psql -U secinvest -d secinvest < db/seed_generated.sql",
        "BEGIN;",
    ]
    if ip_rows:
        out.append("INSERT INTO ip_reputation (ip, malicious, score, sources_flagging, first_seen) VALUES")
        out.append(",\n".join(f"    ({q(ip)}, {m}, {sc}, {arr(srcs)}, {q(fs)})" for ip, m, sc, srcs, fs in ip_rows) + ";")
    if geo_rows:
        out.append("INSERT INTO ip_geolocation (ip, country, city, asn, org) VALUES")
        out.append(",\n".join(f"    ({q(ip)}, {q(c)}, {q(ci)}, {q(a)}, {q(o)})" for ip, c, ci, a, o in geo_rows) + ";")
    if dom_rows:
        out.append("INSERT INTO domain_reputation (domain, malicious, category, score, sources_flagging, first_seen) VALUES")
        out.append(",\n".join(f"    ({q(d)}, {m}, {q(cat)}, {sc}, {arr(srcs)}, {q(fs)})" for d, m, cat, sc, srcs, fs in dom_rows) + ";")
    if cve_rows:
        out.append("INSERT INTO cve_records (cve_id, severity, cvss_score, description, affected_products, published, synthetic) VALUES")
        out.append(",\n".join(f"    ({q(c)}, {q(s)}, {cv}, {q(d)}, {arr(p)}, {q(pub)}, TRUE)" for c, s, cv, d, p, pub in cve_rows) + ";")
    if log_rows:
        out.append("INSERT INTO security_logs (log_id, timestamp, event_type, src, detail) VALUES")
        out.append(",\n".join(
            f"    ({q(lid)}, now() - interval '{h:.1f} hours', {q(et)}, {q(src)}, {q(det)})" for lid, h, et, src, det in log_rows
        ) + ";")
    out.append("COMMIT;")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, default=48)
    ap.add_argument("--seed", type=int, default=20260930)
    args = ap.parse_args()
    scenarios, *rows = build(args.n, args.seed)
    (ROOT / "db" / "seed_generated.sql").write_text(render_sql(*rows, args.seed, args.n))
    (ROOT / "scenarios_generated.json").write_text(json.dumps(scenarios, indent=2) + "\n")
    from collections import Counter

    print(f"wrote {len(scenarios)} scenarios in {len({s['chain'] for s in scenarios})} chains")
    print("ground truth:", dict(Counter(s["ground_truth"] for s in scenarios)))
    print("archetypes:  ", dict(Counter(s["archetype"] for s in scenarios)))


if __name__ == "__main__":
    main()
