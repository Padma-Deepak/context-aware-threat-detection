-- LONG-HORIZON campaign data ("Operation Lantern"), for scenarios_longhorizon.json.
--
-- One interlinked intrusion: phishing document -> dropper -> C2 beacon ->
-- lateral movement (RDP brute force) -> exfiltration, plus two decoys (a
-- lookalike benign host on the C2's ASN, and an unseeded IP). Entities are
-- linked through log text, so the agent must pivot IP -> domain -> CVE -> IP.
-- The tasks run as ONE chain, so later tasks depend on earlier findings: that is
-- what gives a context-management strategy something real to keep or lose.
--
-- NOT loaded by docker-compose (same rule as seed_holdout.sql). Load once:
--   docker compose exec -T postgres psql -U secinvest -d secinvest < db/seed_longhorizon.sql
-- All data is synthetic: RFC 5737 IPs, invented domains/orgs/ASNs, non-real CVE IDs.

BEGIN;

INSERT INTO ip_reputation (ip, malicious, score, sources_flagging, first_seen) VALUES
    ('203.0.113.121', TRUE,  88, ARRAY['AbuseIPDB', 'VirusTotal'],                                   '2026-07-02'),  -- stage 1: phishing host
    ('198.51.100.141',TRUE,  96, ARRAY['AbuseIPDB', 'VirusTotal', 'GreyNoise', 'SpamhausSynthetic'],  '2026-06-20'),  -- C2
    ('192.0.2.161',   TRUE,  72, ARRAY['AbuseIPDB'],                                                  '2026-08-11'),  -- lateral movement
    ('203.0.113.171', TRUE,  93, ARRAY['VirusTotal', 'GreyNoise'],                                    '2026-08-25'),  -- exfil destination
    ('198.51.100.181',FALSE, 22, ARRAY[]::TEXT[],                                                     '2022-05-09');  -- benign lookalike on the C2's ASN
-- 192.0.2.191 is deliberately NOT seeded (no-data decoy).

INSERT INTO ip_geolocation (ip, country, city, asn, org) VALUES
    ('203.0.113.121', 'Romania',     'Bucharest', 'AS64801', 'Danubia Hosting SRL (synthetic)'),
    ('198.51.100.141','Netherlands', 'Rotterdam', 'AS64812', 'Delta Rack BV (synthetic)'),
    ('192.0.2.161',   'Brazil',      'Recife',    'AS64823', 'Nordeste Telecom SA (synthetic)'),
    ('203.0.113.171', 'Vietnam',     'Da Nang',   'AS64834', 'Trung Cloud JSC (synthetic)'),
    ('198.51.100.181','Netherlands', 'Rotterdam', 'AS64812', 'Delta Rack BV (synthetic)');

INSERT INTO domain_reputation (domain, malicious, category, score, sources_flagging, first_seen) VALUES
    ('lantern-docs.cc',      TRUE,  'phishing',   90, ARRAY['VirusTotal', 'AbuseIPDB'], '2026-06-30'),
    ('lantern-cdn.net',      TRUE,  'c2',         94, ARRAY['VirusTotal', 'GreyNoise', 'SpamhausSynthetic'], '2026-06-18'),
    ('fileshare-backup.org', FALSE, 'suspicious', 48, ARRAY['GreyNoise'],               '2026-08-01');

INSERT INTO cve_records (cve_id, severity, cvss_score, description, affected_products, published, synthetic) VALUES
    ('CVE-2026-91001', 'HIGH', 8.8,
     '[SYNTHETIC] Remote code execution when OfficeLite Viewer opens a macro-enabled document from an untrusted origin.',
     ARRAY['OfficeLite Viewer 4.2'], '2026-05-14', TRUE),
    ('CVE-2026-91002', 'CRITICAL', 9.8,
     '[SYNTHETIC] Authentication bypass in PortaGate RDP gateway allowing session hijack after credential reuse.',
     ARRAY['PortaGate RDP Gateway 3.1', 'PortaGate RDP Gateway 3.2'], '2026-06-02', TRUE);

INSERT INTO security_logs (log_id, timestamp, event_type, src, detail) VALUES
    -- 203.0.113.121: stage 1
    ('LOG-L001', now() - interval '9 hours',   'file_download', '203.0.113.121',
     'ws-114 downloaded invoice_q3.docm from a link hosted at lantern-docs.cc; document triggered CVE-2026-91001 in OfficeLite Viewer.'),
    ('LOG-L002', now() - interval '8.9 hours', 'outbound_conn', '203.0.113.121',
     'ws-114 spawned a child process that fetched a second-stage payload from lantern-docs.cc over HTTPS.'),
    -- 198.51.100.141: C2
    ('LOG-L003', now() - interval '8 hours',   'outbound_conn', '198.51.100.141',
     'ws-114 began beaconing to lantern-cdn.net every 60 seconds with fixed-size 312-byte HTTPS requests.'),
    ('LOG-L004', now() - interval '7 hours',   'outbound_conn', '198.51.100.141',
     'Beacon interval on ws-114 to lantern-cdn.net continues (jitter under 2 seconds); payload sizes unchanged.'),
    ('LOG-L005', now() - interval '1 hours',   'outbound_conn', '198.51.100.141',
     'Beacon from ws-114 to lantern-cdn.net still active, 60-second interval.'),
    -- 192.0.2.161: lateral movement
    ('LOG-L006', now() - interval '5 hours',   'failed_login',  '192.0.2.161',
     'RDP login failures for user ''svc-fileops'' against fs-02 (31 attempts in 4 minutes) using credentials previously harvested from ws-114.'),
    ('LOG-L007', now() - interval '4.9 hours', 'outbound_conn', '192.0.2.161',
     'Successful RDP session to fs-02 via PortaGate gateway after credential reuse, consistent with CVE-2026-91002.'),
    -- 203.0.113.171: exfil
    ('LOG-L008', now() - interval '3 hours',   'file_download', '203.0.113.171',
     'fs-02 uploaded 4.2 GB of archived documents to 203.0.113.171 over TLS in 11 minutes.'),
    ('LOG-L009', now() - interval '2.8 hours', 'outbound_conn', '203.0.113.171',
     'Second upload of 1.1 GB from fs-02 to 203.0.113.171, ending with a connection reset.'),
    -- 198.51.100.181: benign lookalike on the same ASN as the C2
    ('LOG-L010', now() - interval '6 hours',   'outbound_conn', '198.51.100.181',
     'Scheduled nightly backup sync to the vendor''s object store, matches the approved change ticket.'),
    ('LOG-L011', now() - interval '30 hours',  'file_download', '198.51.100.181',
     'Downloaded vendor firmware manifest, signature verified.');

COMMIT;
