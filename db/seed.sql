-- Phase 3: seed data transcribed 1:1 from mcp_server/data.py.
-- SYNTHETIC / FABRICATED data for a benchmark project -- see the header
-- comment in mcp_server/data.py for details (RFC 5737 example IPs,
-- invented domains/orgs/ASNs, non-real CVE IDs).
--
-- security_logs uses relative timestamp expressions (now() - interval
-- 'X hours'), mirroring data.py's _ago(hours=...) helper, so the window
-- that query_logs(hours=24) filters on stays meaningful no matter when
-- this seed is run (e.g. every `docker compose up`).

BEGIN;

-- ---------------------------------------------------------------------------
-- ip_reputation (13 rows: 5 malicious, 5 benign, 3 suspicious/ambiguous)
-- ---------------------------------------------------------------------------
INSERT INTO ip_reputation (ip, malicious, score, sources_flagging, first_seen) VALUES
    -- malicious
    ('203.0.113.10',   TRUE,  97, ARRAY['VirusTotal', 'AbuseIPDB', 'GreyNoise'],          '2023-11-02'),
    ('203.0.113.45',   TRUE,  93, ARRAY['AbuseIPDB', 'SpamhausSynthetic'],                '2024-01-17'),
    ('198.51.100.77',  TRUE,  99, ARRAY['VirusTotal', 'AbuseIPDB', 'MalwareBazaarSynthetic'], '2023-08-30'),
    ('198.51.100.12',  TRUE,  88, ARRAY['GreyNoise', 'AbuseIPDB'],                        '2024-05-09'),
    ('192.0.2.99',     TRUE,  95, ARRAY['VirusTotal', 'SpamhausSynthetic', 'AbuseIPDB'],  '2023-12-21'),
    -- benign
    ('192.0.2.10',     FALSE, 2,  ARRAY[]::TEXT[],                                       '2021-04-11'),
    ('198.51.100.200', FALSE, 3,  ARRAY[]::TEXT[],                                       '2020-09-01'),
    ('203.0.113.200',  FALSE, 0,  ARRAY[]::TEXT[],                                       '2019-06-15'),
    ('198.51.100.150', FALSE, 4,  ARRAY[]::TEXT[],                                       '2022-02-27'),
    ('192.0.2.150',    FALSE, 1,  ARRAY[]::TEXT[],                                       '2018-11-03'),
    -- suspicious / ambiguous
    ('203.0.113.66',   FALSE, 58, ARRAY['GreyNoise'],                                    '2025-06-20'),
    ('198.51.100.33',  FALSE, 61, ARRAY['AbuseIPDB'],                                    '2025-07-04'),
    ('192.0.2.77',     FALSE, 44, ARRAY[]::TEXT[],                                       '2025-08-11');

-- ---------------------------------------------------------------------------
-- ip_geolocation (same 13 IPs)
-- ---------------------------------------------------------------------------
INSERT INTO ip_geolocation (ip, country, city, asn, org) VALUES
    ('203.0.113.10',   'Netherlands',    'Amsterdam',    'AS64510', 'Nordlight Hosting Ltd (synthetic)'),
    ('203.0.113.45',   'Romania',        'Bucharest',    'AS64522', 'Carpathia Datacenter SRL (synthetic)'),
    ('198.51.100.77',  'Russia',         'Novosibirsk',  'AS64533', 'SibNet Transit AS (synthetic)'),
    ('198.51.100.12',  'Vietnam',        'Hanoi',        'AS64544', 'RedRiver Broadband (synthetic)'),
    ('192.0.2.99',     'Brazil',         'Curitiba',     'AS64555', 'Serra Verde Telecom (synthetic)'),
    ('192.0.2.10',     'United States',  'Ashburn',      'AS64566', 'Example Corp IT (synthetic)'),
    ('198.51.100.200', 'United States',  'Denver',       'AS64577', 'Example Corp VPN (synthetic)'),
    ('203.0.113.200',  'Germany',        'Frankfurt',    'AS64588', 'FrankfurtEdge CDN AS (synthetic)'),
    ('198.51.100.150', 'Canada',         'Toronto',      'AS64599', 'Partner API Networks (synthetic)'),
    ('192.0.2.150',    'Ireland',        'Dublin',       'AS64600', 'Example Corp Software Distribution (synthetic)'),
    ('203.0.113.66',   'Panama',         'Panama City',  'AS64611', 'Istmo Cloud Servers (synthetic)'),
    ('198.51.100.33',  'Seychelles',     'Victoria',     'AS64622', 'Indigo Ocean Hosting (synthetic)'),
    ('192.0.2.77',     'Moldova',        'Chisinau',     'AS64633', 'Dniester Net Services (synthetic)');

-- ---------------------------------------------------------------------------
-- domain_reputation (8 rows: 4 malicious, 2 benign, 2 suspicious)
-- ---------------------------------------------------------------------------
INSERT INTO domain_reputation (domain, malicious, category, score, sources_flagging, first_seen) VALUES
    ('secure-login-update.net',  TRUE,  'phishing',   96, ARRAY['VirusTotal', 'PhishTankSynthetic'],          '2024-02-14'),
    ('cdn-analytics-node7.info', TRUE,  'c2',         98, ARRAY['VirusTotal', 'AbuseIPDB', 'GreyNoise'],      '2023-10-05'),
    ('freegiftcardclaim.biz',    TRUE,  'phishing',   90, ARRAY['PhishTankSynthetic'],                        '2024-06-22'),
    ('datasync-relay.online',    TRUE,  'malware',    94, ARRAY['VirusTotal', 'MalwareBazaarSynthetic'],      '2023-09-18'),
    ('example-corp.com',         FALSE, 'benign',      0, ARRAY[]::TEXT[],                                    '2015-01-10'),
    ('opensource-tools.dev',     FALSE, 'benign',      1, ARRAY[]::TEXT[],                                    '2019-07-22'),
    ('cloudmetrics-stats.io',    FALSE, 'suspicious', 52, ARRAY['GreyNoise'],                                 '2025-05-30'),
    ('quickfile-share.top',      FALSE, 'suspicious', 47, ARRAY[]::TEXT[],                                    '2025-08-02');

-- ---------------------------------------------------------------------------
-- cve_records (8 rows, all synthetic / fabricated)
-- ---------------------------------------------------------------------------
INSERT INTO cve_records (cve_id, severity, cvss_score, description, affected_products, published, synthetic) VALUES
    ('CVE-2024-90001', 'CRITICAL', 9.8,
     '[SYNTHETIC] Unauthenticated deserialization of untrusted data in NovaMail Server''s message-queue endpoint allows remote code execution.',
     ARRAY['NovaMail Server 4.x', 'NovaMail Server 5.0-5.2'], '2024-03-12', TRUE),
    ('CVE-2023-90045', 'HIGH', 8.2,
     '[SYNTHETIC] SQL injection in the login module of Fictional CRM Suite allows authentication bypass and data exfiltration.',
     ARRAY['Fictional CRM Suite 2.3', 'Fictional CRM Suite 2.4'], '2023-05-19', TRUE),
    ('CVE-2024-90102', 'MEDIUM', 6.1,
     '[SYNTHETIC] Stored cross-site scripting in BlueDesk Helpdesk ticket comments allows session hijacking of agent accounts.',
     ARRAY['BlueDesk Helpdesk 3.x'], '2024-07-01', TRUE),
    ('CVE-2022-90233', 'LOW', 3.7,
     '[SYNTHETIC] Debug endpoint in GridSync File Server discloses internal file paths and version banners to unauthenticated users.',
     ARRAY['GridSync File Server 1.8'], '2022-11-08', TRUE),
    ('CVE-2025-90007', 'CRITICAL', 9.9,
     '[SYNTHETIC] Authentication bypass in PulseVPN Gateway management interface allows full device takeover without credentials.',
     ARRAY['PulseVPN Gateway 6.0-6.4'], '2025-01-27', TRUE),
    ('CVE-2023-90188', 'HIGH', 7.8,
     '[SYNTHETIC] Local privilege escalation in Aster OS kernel driver via unchecked IOCTL buffer length.',
     ARRAY['Aster OS 12', 'Aster OS 13'], '2023-09-14', TRUE),
    ('CVE-2024-90310', 'MEDIUM', 5.4,
     '[SYNTHETIC] Cross-site request forgery in Meridian CMS admin panel allows unauthorized configuration changes.',
     ARRAY['Meridian CMS 9.x'], '2024-10-30', TRUE),
    ('CVE-2021-90056', 'HIGH', 8.1,
     '[SYNTHETIC] Stack buffer overflow in OrbitPrint network print spooler triggered by an oversized job-name field.',
     ARRAY['OrbitPrint Spooler 2.0-2.5'], '2021-12-02', TRUE);

-- ---------------------------------------------------------------------------
-- security_logs (36 rows)
-- Timestamps use now() - interval 'X hours', matching data.py's
-- _RAW_LOGS[*]["hours_ago"] values exactly, so the dataset stays "fresh"
-- relative to whenever this seed is actually run.
-- ---------------------------------------------------------------------------
INSERT INTO security_logs (log_id, timestamp, event_type, src, detail) VALUES
    -- 203.0.113.10 : malicious C2 beacon host
    ('LOG-0001', now() - interval '0.5 hours', 'outbound_conn', '203.0.113.10',
     'Beacon-like HTTPS connection to cdn-analytics-node7.info every 60s, JA3 fingerprint matches known C2 toolkit.'),
    ('LOG-0002', now() - interval '3 hours', 'outbound_conn', '203.0.113.10',
     'Repeated small POST requests to cdn-analytics-node7.info/checkin, consistent with C2 heartbeat.'),
    ('LOG-0003', now() - interval '20 hours', 'port_scan', '203.0.113.10',
     'TCP SYN scan against ports 22,3389,445 on 12 internal hosts within 90 seconds.'),

    -- 203.0.113.45 : malicious brute-force source
    ('LOG-0004', now() - interval '1 hours', 'failed_login', '203.0.113.45',
     'Failed SSH login for user ''admin'' on host bastion-01 (attempt 1 of 47 in 5 minutes).'),
    ('LOG-0005', now() - interval '0.9 hours', 'failed_login', '203.0.113.45',
     'Failed SSH login for user ''root'' on host bastion-01 (attempt 12 of 47 in 5 minutes).'),
    ('LOG-0006', now() - interval '0.8 hours', 'failed_login', '203.0.113.45',
     'Failed SSH login for user ''administrator'' on host bastion-01 (attempt 30 of 47 in 5 minutes).'),
    ('LOG-0007', now() - interval '0.75 hours', 'failed_login', '203.0.113.45',
     'Failed SSH login for user ''oracle'' on host bastion-01 (attempt 47 of 47 in 5 minutes) -- account lockout triggered.'),
    ('LOG-0008', now() - interval '30 hours', 'port_scan', '203.0.113.45',
     'Sequential TCP connect scan across ports 1-1024 on host bastion-01.'),

    -- 198.51.100.77 : malicious malware distribution
    ('LOG-0009', now() - interval '2 hours', 'file_download', '198.51.100.77',
     'Host ws-042 downloaded ''invoice_update.exe'' from 198.51.100.77; file hash matches known malware family (synthetic).'),
    ('LOG-0010', now() - interval '1.5 hours', 'file_download', '198.51.100.77',
     'Host ws-107 downloaded ''invoice_update.exe'' from 198.51.100.77 shortly after opening a phishing attachment.'),
    ('LOG-0011', now() - interval '40 hours', 'outbound_conn', '198.51.100.77',
     'Host ws-042 opened outbound connection to 198.51.100.77:8443 approximately 10 minutes after malware execution.'),

    -- 198.51.100.12 : malicious port scanner
    ('LOG-0012', now() - interval '4 hours', 'port_scan', '198.51.100.12',
     'TCP SYN scan against ports 80,443,8080,8443 across entire 10.20.0.0/24 subnet.'),
    ('LOG-0013', now() - interval '3.5 hours', 'port_scan', '198.51.100.12',
     'UDP scan against port 161 (SNMP) across 10.20.0.0/24 subnet, default community strings attempted.'),
    ('LOG-0014', now() - interval '55 hours', 'port_scan', '198.51.100.12',
     'TCP SYN scan against ports 3306,5432,27017 (database ports) across 10.20.0.0/24 subnet.'),

    -- 192.0.2.99 : malicious botnet / DDoS node
    ('LOG-0015', now() - interval '0.2 hours', 'outbound_conn', '192.0.2.99',
     'High-frequency outbound connections (400+/min) to edge-lb-03, consistent with participation in a DDoS botnet.'),
    ('LOG-0016', now() - interval '6 hours', 'outbound_conn', '192.0.2.99',
     'Short-lived TCP connections to edge-lb-03 on port 443, no valid TLS handshake completed.'),
    ('LOG-0017', now() - interval '70 hours', 'port_scan', '192.0.2.99',
     'TCP SYN scan against port 443 across the public-facing /24 prior to the DDoS activity.'),

    -- 192.0.2.10 : benign mail relay
    ('LOG-0018', now() - interval '5 hours', 'outbound_conn', '192.0.2.10',
     'Outbound SMTP connection to partner mail exchanger, delivered 3 queued messages successfully.'),
    ('LOG-0019', now() - interval '12 hours', 'file_download', '192.0.2.10',
     'Downloaded routine antivirus signature update package from vendor update service.'),
    ('LOG-0020', now() - interval '26 hours', 'outbound_conn', '192.0.2.10',
     'Outbound SMTP connection to partner mail exchanger, delivered 1 queued message successfully.'),

    -- 198.51.100.200 : benign VPN gateway
    ('LOG-0021', now() - interval '9 hours', 'failed_login', '198.51.100.200',
     'Employee VPN login for user ''j.alvarez'' failed once (typo), succeeded on second attempt 8 seconds later.'),
    ('LOG-0022', now() - interval '8.5 hours', 'outbound_conn', '198.51.100.200',
     'Established routine VPN tunnel to corporate gateway, session duration 6h42m.'),

    -- 203.0.113.200 : benign CDN edge node
    ('LOG-0023', now() - interval '2.5 hours', 'outbound_conn', '203.0.113.200',
     'Routine HTTPS asset delivery for static site content, 214 requests over 10 minutes.'),
    ('LOG-0024', now() - interval '14 hours', 'outbound_conn', '203.0.113.200',
     'Routine HTTPS asset delivery for static site content, 189 requests over 10 minutes.'),

    -- 198.51.100.150 : benign partner API server
    ('LOG-0025', now() - interval '3 hours', 'outbound_conn', '198.51.100.150',
     'Scheduled API sync call to /v2/orders endpoint, HTTP 200 returned.'),
    ('LOG-0026', now() - interval '27 hours', 'outbound_conn', '198.51.100.150',
     'Scheduled API sync call to /v2/inventory endpoint, HTTP 200 returned.'),
    ('LOG-0027', now() - interval '27.2 hours', 'file_download', '198.51.100.150',
     'Downloaded daily reconciliation report CSV via authenticated partner API session.'),

    -- 192.0.2.150 : benign software update server
    ('LOG-0028', now() - interval '10 hours', 'file_download', '192.0.2.150',
     'Host ws-018 downloaded scheduled OS patch bundle ''patch-2026-09.pkg'' (signature verified).'),
    ('LOG-0029', now() - interval '34 hours', 'file_download', '192.0.2.150',
     'Host ws-091 downloaded scheduled OS patch bundle ''patch-2026-08.pkg'' (signature verified).'),

    -- 203.0.113.66 : suspicious / HARD CASE (references malicious domain cdn-analytics-node7.info)
    ('LOG-0030', now() - interval '1.2 hours', 'outbound_conn', '203.0.113.66',
     'Outbound HTTPS connection from host ws-063 to cdn-analytics-node7.info, TLS SNI observed.'),
    ('LOG-0031', now() - interval '15 hours', 'outbound_conn', '203.0.113.66',
     'Routine outbound HTTPS connection to a public software-update CDN, nothing unusual.'),

    -- 198.51.100.33 : suspicious / HARD CASE (references malicious domain datasync-relay.online)
    ('LOG-0032', now() - interval '2.2 hours', 'outbound_conn', '198.51.100.33',
     'Outbound HTTPS connection from host ws-081 to datasync-relay.online shortly after a file_download event.'),
    ('LOG-0033', now() - interval '2.3 hours', 'file_download', '198.51.100.33',
     'Host ws-081 downloaded ''quarterly_report_draft.docm'' referencing datasync-relay.online as its update source.'),
    ('LOG-0034', now() - interval '18 hours', 'outbound_conn', '198.51.100.33',
     'Routine outbound HTTPS connection to a public weather API, nothing unusual.'),

    -- 192.0.2.77 : suspicious / low-confidence, ambiguous
    ('LOG-0035', now() - interval '5.5 hours', 'outbound_conn', '192.0.2.77',
     'Single outbound HTTPS connection to cloudmetrics-stats.io, low request volume, unclear intent.'),
    ('LOG-0036', now() - interval '48 hours', 'file_download', '192.0.2.77',
     'Host ws-129 downloaded an unsigned utility binary ''sysmetrics.exe'' from an unlisted source.');

COMMIT;
