-- HELD-OUT synthetic data, for final evaluation only.
--
-- Everything in db/seed.sql was visible while agent/agent.py's system
-- prompt was written and while agent/benchmark.py's WINDOW_SIZE was
-- tuned. That makes scenarios.json a dev set, not a real test of
-- generalization -- an agent (or a human) can pass it by fitting to
-- quirks of data it already knows about.
--
-- This file adds a second, disjoint batch of synthetic records (new
-- IPs/domain/CVE, none overlapping db/seed.sql) for scenarios.json's
-- held-out counterpart: scenarios_holdout.json. Intentionally NOT wired
-- into docker-compose.yml's docker-entrypoint-initdb.d -- if it loaded
-- automatically on every `docker compose up`, it would just become part
-- of the dataset everyone develops against, defeating the point. Load
-- it deliberately, once, when you're ready to run the held-out set:
--
--   docker compose exec -T postgres psql -U secinvest -d secinvest \
--       < db/seed_holdout.sql
--
-- Same fabrication rules as db/seed.sql: RFC 5737 example IPs, invented
-- domain/org/ASN, non-real CVE ID.

BEGIN;

-- ---------------------------------------------------------------------------
-- ip_reputation (6 new IPs -- a 7th, 203.0.113.5, is deliberately left
-- unseeded; see scenarios_holdout.json H02)
-- ---------------------------------------------------------------------------
INSERT INTO ip_reputation (ip, malicious, score, sources_flagging, first_seen) VALUES
    -- H01: maximally decisive, single-call malicious
    ('203.0.113.88',   TRUE,  100, ARRAY['VirusTotal', 'AbuseIPDB', 'SpamhausSynthetic', 'GreyNoise'], '2026-08-30'),
    -- H03: clean, but very recently first seen (recency alone isn't a threat signal)
    ('192.0.2.222',    FALSE, 0,   ARRAY[]::TEXT[],                                                    '2026-09-20'),
    -- H04: sits just above agent.py's "score > 30" investigation-trigger threshold, but resolves clean
    ('198.51.100.90',  FALSE, 31,  ARRAY['GreyNoise'],                                                  '2025-03-11'),
    -- H05: malicious, cross-references a CVE via its logs (not the task text)
    ('203.0.113.30',   TRUE,  91,  ARRAY['AbuseIPDB'],                                                  '2026-01-14'),
    -- H07: malicious, brute-force AND port-scan combo (not paired together in db/seed.sql)
    ('198.51.100.5',   TRUE,  85,  ARRAY['AbuseIPDB', 'GreyNoise'],                                     '2025-11-02'),
    -- H08: low-but-nonzero "background noise" score, no corroborating evidence anywhere
    ('192.0.2.5',      FALSE, 15,  ARRAY[]::TEXT[],                                                     '2024-04-19');

-- ---------------------------------------------------------------------------
-- ip_geolocation (same 6 seeded IPs; 203.0.113.5 has none, matching its
-- absence from ip_reputation)
-- ---------------------------------------------------------------------------
INSERT INTO ip_geolocation (ip, country, city, asn, org) VALUES
    ('203.0.113.88',   'Ukraine',      'Odesa',      'AS64701', 'Blacksea Transit AS (synthetic)'),
    ('192.0.2.222',    'United States','Ashburn',    'AS64712', 'Example Corp IT (synthetic)'),
    ('198.51.100.90',  'Portugal',     'Lisbon',     'AS64723', 'Atlantico Hosting Lda (synthetic)'),
    ('203.0.113.30',   'Indonesia',    'Jakarta',    'AS64734', 'Nusantara Cloud PT (synthetic)'),
    ('198.51.100.5',   'Nigeria',      'Lagos',      'AS64745', 'Lekki Data Networks (synthetic)'),
    ('192.0.2.5',      'Poland',       'Warsaw',     'AS64756', 'Wisla Broadband Sp. (synthetic)');

-- ---------------------------------------------------------------------------
-- domain_reputation (1 new domain, filling the score gap between
-- db/seed.sql's two "suspicious" domains at 52 and 47)
-- ---------------------------------------------------------------------------
INSERT INTO domain_reputation (domain, malicious, category, score, sources_flagging, first_seen) VALUES
    ('metrics-sync-edge.io', FALSE, 'suspicious', 55, ARRAY['GreyNoise'], '2026-02-18');

-- ---------------------------------------------------------------------------
-- cve_records (1 new CVE, referenced from H05's logs rather than the
-- task text -- db/seed.sql's CVE scenarios only ever look it up directly)
-- ---------------------------------------------------------------------------
INSERT INTO cve_records (cve_id, severity, cvss_score, description, affected_products, published, synthetic) VALUES
    ('CVE-2025-90410', 'CRITICAL', 9.6,
     '[SYNTHETIC] Unauthenticated remote code execution in GridSync File Server''s management interface via a crafted IOCTL-style request.',
     ARRAY['GridSync File Server 1.8', 'GridSync File Server 1.9'], '2025-11-20', TRUE);

-- ---------------------------------------------------------------------------
-- security_logs (9 new rows, IDs prefixed LOG-H0xx to avoid any collision
-- with db/seed.sql's LOG-0001..LOG-0036)
-- ---------------------------------------------------------------------------
INSERT INTO security_logs (log_id, timestamp, event_type, src, detail) VALUES
    -- 198.51.100.90 : clean logs, despite score sitting above the >30 trigger
    ('LOG-H001', now() - interval '4 hours',  'outbound_conn', '198.51.100.90',
     'Routine outbound HTTPS connection to a public CDN, nothing unusual.'),
    ('LOG-H002', now() - interval '20 hours', 'file_download', '198.51.100.90',
     'Downloaded routine software update package from vendor CDN, signature verified.'),

    -- 203.0.113.30 : exploit attempt referencing the new CVE, discovered via logs not the task
    ('LOG-H003', now() - interval '1 hours',  'outbound_conn', '203.0.113.30',
     'Exploit attempt referencing CVE-2025-90410 observed targeting internal GridSync File Server 1.8 instance.'),
    ('LOG-H004', now() - interval '1.1 hours','port_scan',     '203.0.113.30',
     'TCP connect scan against port 8090 (GridSync management interface) immediately before the exploit attempt.'),

    -- 198.51.100.5 : brute force AND port scan from the same source
    ('LOG-H005', now() - interval '2 hours',   'failed_login', '198.51.100.5',
     'Failed VPN login for user ''r.kimura'' on gateway vpn-02 (attempt 1 of 22 in 3 minutes).'),
    ('LOG-H006', now() - interval '1.9 hours', 'failed_login', '198.51.100.5',
     'Failed VPN login for user ''svc-backup'' on gateway vpn-02 (attempt 15 of 22 in 3 minutes).'),
    ('LOG-H007', now() - interval '1.8 hours', 'failed_login', '198.51.100.5',
     'Failed VPN login for user ''admin'' on gateway vpn-02 (attempt 22 of 22 in 3 minutes) -- account lockout triggered.'),
    ('LOG-H008', now() - interval '1.7 hours', 'port_scan',    '198.51.100.5',
     'TCP SYN scan against ports 443,1194,4443 (VPN service ports) on gateway vpn-02, immediately after lockout.'),

    -- 192.0.2.5 : one lone, unremarkable event -- not corroborating evidence
    ('LOG-H009', now() - interval '30 hours',  'outbound_conn', '192.0.2.5',
     'Single outbound HTTPS connection to a public news website, unremarkable.');

COMMIT;
