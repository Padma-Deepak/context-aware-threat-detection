-- Phase 3: PostgreSQL schema mirroring mcp_server/data.py's in-memory
-- structures. Every table/column here maps 1:1 to a dict (or list of
-- dicts) in data.py so that Phase 5 can swap data.py's storage backend
-- without changing any accessor function's return shape.
--
-- Reminder: all data seeded against this schema is SYNTHETIC (fabricated
-- for a benchmark project) -- see db/seed.sql and mcp_server/data.py.

-- ---------------------------------------------------------------------------
-- ip_reputation  <-  data.py: IP_REPUTATION dict, keyed by ip
-- ---------------------------------------------------------------------------
CREATE TABLE ip_reputation (
    ip               TEXT PRIMARY KEY,
    malicious        BOOLEAN NOT NULL,
    score            INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    sources_flagging TEXT[] NOT NULL DEFAULT '{}',
    first_seen       DATE
);

-- ---------------------------------------------------------------------------
-- ip_geolocation  <-  data.py: IP_GEOLOCATION dict, keyed by ip
-- Every key in IP_GEOLOCATION is also a key in IP_REPUTATION, so the FK
-- holds for the full Phase 1 dataset.
-- ---------------------------------------------------------------------------
CREATE TABLE ip_geolocation (
    ip      TEXT PRIMARY KEY REFERENCES ip_reputation(ip),
    country TEXT,
    city    TEXT,
    asn     TEXT,
    org     TEXT
);

-- ---------------------------------------------------------------------------
-- domain_reputation  <-  data.py: DOMAIN_REPUTATION dict, keyed by domain
-- ---------------------------------------------------------------------------
CREATE TABLE domain_reputation (
    domain           TEXT PRIMARY KEY,
    malicious        BOOLEAN NOT NULL,
    category         TEXT NOT NULL CHECK (category IN
                       ('malware', 'phishing', 'c2', 'suspicious', 'benign', 'unknown')),
    score            INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    sources_flagging TEXT[] NOT NULL DEFAULT '{}',
    first_seen       DATE
);

-- ---------------------------------------------------------------------------
-- cve_records  <-  data.py: CVE_RECORDS dict, keyed by cve_id
-- ---------------------------------------------------------------------------
CREATE TABLE cve_records (
    cve_id             TEXT PRIMARY KEY,
    severity           TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    cvss_score         NUMERIC(3, 1) NOT NULL CHECK (cvss_score BETWEEN 0 AND 10),
    description        TEXT NOT NULL,
    affected_products  TEXT[] NOT NULL DEFAULT '{}',
    published          DATE,
    synthetic          BOOLEAN NOT NULL DEFAULT TRUE
);

-- ---------------------------------------------------------------------------
-- security_logs  <-  data.py: SECURITY_LOGS list of dicts
--
-- data.py's query_logs() contract returns each log's "id" as a string
-- like "LOG-0001" (see mcp_server/data.py:522-531). `id` here stays the
-- SERIAL surrogate primary key requested for Phase 3; `log_id` carries
-- the original string identifier from data.py so Phase 5 can reproduce
-- the exact "id" value the MCP tool contract promises.
-- ---------------------------------------------------------------------------
CREATE TABLE security_logs (
    id         SERIAL PRIMARY KEY,
    log_id     TEXT NOT NULL UNIQUE,
    timestamp  TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN
                 ('failed_login', 'port_scan', 'outbound_conn', 'file_download')),
    src        TEXT NOT NULL,
    detail     TEXT NOT NULL
);

-- query_logs(src_ip, hours) filters by src (equality) and timestamp
-- (>= now() - hours), then sorts most-recent-first -- a composite index
-- on (src, timestamp DESC) covers that access pattern directly; the
-- single-column indexes support src-only or timestamp-only lookups too.
CREATE INDEX idx_security_logs_src ON security_logs (src);
CREATE INDEX idx_security_logs_timestamp ON security_logs (timestamp);
CREATE INDEX idx_security_logs_src_timestamp ON security_logs (src, timestamp DESC);
