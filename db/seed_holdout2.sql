-- SECOND held-out synthetic batch, for final evaluation only.
--
-- The first held-out set (db/seed_holdout.sql / scenarios_holdout.json)
-- is spent: its results were seen, and the context_manager.py fixes that
-- followed were found by investigating its failures. Validating those
-- fixes on it would be tuning on the test set. This batch was written and
-- committed BEFORE any experiment with the fixed code was run.
--
-- Disjoint from db/seed.sql AND db/seed_holdout.sql (no shared IPs,
-- domains, CVEs, ASNs, or log IDs), so either held-out batch can be loaded
-- with or without the other. Not auto-loaded by docker-compose.yml, for
-- the same reason as db/seed_holdout.sql. Load it deliberately:
--
--   docker compose exec -T postgres psql -U secinvest -d secinvest \
--       < db/seed_holdout2.sql

BEGIN;

INSERT INTO ip_reputation (ip, malicious, score, sources_flagging, first_seen) VALUES
    ('203.0.113.17',   TRUE,  94, ARRAY['VirusTotal', 'GreyNoise'],              '2026-06-03'),
    ('192.0.2.41',     FALSE, 2,  ARRAY[]::TEXT[],                               '2020-02-14'),
    ('198.51.100.44',  TRUE,  80, ARRAY['PhishTankSynthetic', 'AbuseIPDB'],      '2026-07-19'),
    ('203.0.113.140',  FALSE, 40, ARRAY['GreyNoise'],                            '2026-08-08'),
    ('198.51.100.121', TRUE,  88, ARRAY['AbuseIPDB', 'SpamhausSynthetic'],       '2026-04-27'),
    ('192.0.2.63',     FALSE, 35, ARRAY['GreyNoise'],                            '2022-10-05'),
    ('198.51.100.230', TRUE,  90, ARRAY['GreyNoise', 'AbuseIPDB'],               '2025-12-12'),
    ('192.0.2.180',    FALSE, 45, ARRAY[]::TEXT[],                               '2026-09-01');

INSERT INTO ip_geolocation (ip, country, city, asn, org) VALUES
    ('203.0.113.17',   'Kazakhstan',     'Almaty',     'AS64801', 'Steppe Hosting LLP (synthetic)'),
    ('192.0.2.41',     'United States',  'Chicago',    'AS64812', 'Example Corp Print Services (synthetic)'),
    ('198.51.100.44',  'Belize',         'Belmopan',   'AS64823', 'Coral Reef Servers Ltd (synthetic)'),
    ('203.0.113.140',  'Latvia',         'Riga',       'AS64834', 'Daugava Cloud SIA (synthetic)'),
    ('198.51.100.121', 'Bulgaria',       'Sofia',      'AS64845', 'Vitosha Datacenter EOOD (synthetic)'),
    ('192.0.2.63',     'United States',  'Seattle',    'AS64856', 'Example Corp Build Farm (synthetic)'),
    ('198.51.100.230', 'Chile',          'Santiago',   'AS64867', 'Andes Transit SpA (synthetic)'),
    ('192.0.2.180',    'Georgia',        'Tbilisi',    'AS64878', 'Mtkvari Net Services (synthetic)');

INSERT INTO domain_reputation (domain, malicious, category, score, sources_flagging, first_seen) VALUES
    ('telemetry-cache-node.net', TRUE,  'c2',         96, ARRAY['VirusTotal', 'GreyNoise'],          '2026-05-30'),
    ('payroll-portal-verify.com', TRUE, 'phishing',   93, ARRAY['PhishTankSynthetic', 'VirusTotal'], '2026-07-15'),
    ('docs-mirror-cdn.org',      FALSE, 'benign',     1,  ARRAY[]::TEXT[],                           '2017-03-22'),
    ('fastupdate-dl.xyz',        FALSE, 'suspicious', 50, ARRAY[]::TEXT[],                           '2026-08-20');

INSERT INTO cve_records (cve_id, severity, cvss_score, description, affected_products, published, synthetic) VALUES
    ('CVE-2026-90022', 'HIGH', 8.4,
     '[SYNTHETIC] Path traversal in Halcyon Web Console file-preview handler allows unauthenticated reading of arbitrary server files.',
     ARRAY['Halcyon Web Console 3.x'], '2026-03-09', TRUE);

INSERT INTO security_logs (log_id, timestamp, event_type, src, detail) VALUES
    -- 203.0.113.17 : C2 beacon to telemetry-cache-node.net
    ('LOG-J001', now() - interval '0.7 hours', 'outbound_conn', '203.0.113.17',
     'Periodic HTTPS beacon to telemetry-cache-node.net every 120s from host ws-210, fixed 312-byte payloads.'),
    ('LOG-J002', now() - interval '6 hours',   'outbound_conn', '203.0.113.17',
     'Host ws-210 POSTed 48 KB to telemetry-cache-node.net/upload outside business hours.'),

    -- 192.0.2.41 : internal print server, routine
    ('LOG-J003', now() - interval '3 hours',   'outbound_conn', '192.0.2.41',
     'Routine printer firmware check-in to vendor update service, HTTP 200.'),

    -- 198.51.100.44 : phishing landing host
    ('LOG-J004', now() - interval '2 hours',   'outbound_conn', '198.51.100.44',
     'Three employees followed an email link to payroll-portal-verify.com hosted on 198.51.100.44; credential form submitted by one.'),

    -- 203.0.113.140 : inconclusive reputation, but talks to the same C2 as 203.0.113.17
    ('LOG-J005', now() - interval '1.5 hours', 'outbound_conn', '203.0.113.140',
     'Outbound HTTPS from host ws-305 to telemetry-cache-node.net, SNI observed, 312-byte payloads.'),
    ('LOG-J006', now() - interval '22 hours',  'outbound_conn', '203.0.113.140',
     'Routine outbound HTTPS connection to a public time-sync service, nothing unusual.'),

    -- 198.51.100.121 : exploitation of CVE-2026-90022
    ('LOG-J007', now() - interval '4 hours',   'outbound_conn', '198.51.100.121',
     'Requests to Halcyon Web Console /preview?file=../../etc/shadow matching CVE-2026-90022 exploitation, HTTP 200 returned.'),
    ('LOG-J008', now() - interval '4.2 hours', 'port_scan',     '198.51.100.121',
     'TCP SYN scan of ports 8080-8090 on web-console-01 shortly before the exploitation requests.'),

    -- 192.0.2.63 : build farm, score just above the trigger, clean behavior
    ('LOG-J009', now() - interval '5 hours',   'file_download', '192.0.2.63',
     'Build agent downloaded dependency archive from docs-mirror-cdn.org, checksum verified against lockfile.'),
    ('LOG-J010', now() - interval '19 hours',  'outbound_conn', '192.0.2.63',
     'Routine CI artifact upload to internal artifact store, HTTP 201.'),

    -- 198.51.100.230 : scanner
    ('LOG-J011', now() - interval '1 hours',   'port_scan',     '198.51.100.230',
     'TCP SYN scan against ports 22,23,2323 across the 10.40.0.0/24 subnet.'),
    ('LOG-J012', now() - interval '9 hours',   'port_scan',     '198.51.100.230',
     'Telnet banner grabbing across the 10.40.0.0/24 subnet, default credential attempts observed.'),

    -- 192.0.2.180 : thin evidence on both sides
    ('LOG-J013', now() - interval '7 hours',   'file_download', '192.0.2.180',
     'Host ws-412 downloaded ''agent_setup.msi'' from fastupdate-dl.xyz; unsigned, no known-malware hash match.');

COMMIT;
