# Security Investigation MCP Server (Synthetic Benchmark)

This is a **mock security-investigation backend** built for an agent
benchmark project. It is not a real threat-intelligence feed. Every IP,
domain, CVE, and log entry in this dataset is fabricated:

- IPs are drawn from RFC 5737 documentation/example ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) that IANA
  reserves for exactly this purpose and never assigns to real hosts.
- Domains, hosting orgs, and ASNs are invented.
- CVE records are entirely synthetic (`synthetic: true` on every record)
  and do not correspond to real CVEs.

It exposes 5 read-only tools over the [Model Context Protocol](https://modelcontextprotocol.io)
so an agent can practice IP/domain reputation lookups, log correlation,
and CVE lookups against a realistic-shaped but safe dataset.

## Running it

One command, from this directory:

```
docker compose up --build
```

This starts two services:

- **postgres** (`postgres:16`) -- auto-initializes the schema and seed
  data from `db/schema.sql` and `db/seed.sql` on first start (via
  `docker-entrypoint-initdb.d`), persisted in a named volume (`pgdata`)
  so data survives restarts. Credentials come from `POSTGRES_USER` /
  `POSTGRES_PASSWORD` / `POSTGRES_DB` env vars (see `.env.example` --
  copy it to `.env` to override; sane local defaults are baked in so
  `docker compose up` works with no `.env` file at all).
- **mcp_server** -- built from `Dockerfile`, waits for postgres to
  report healthy, then serves the 5 MCP tools over **streamable-http**
  on `0.0.0.0:8000`, published to the host as `localhost:8000`.

To run in the background: `docker compose up -d --build`.

To tear down (including the data volume): `docker compose down -v`.

## Verifying it's healthy

Check both containers report healthy/running:

```
docker compose ps
```

Check Postgres actually seeded (should show 13/13/8/8/36):

```
docker compose exec postgres psql -U secinvest -d secinvest -c "
SELECT 'ip_reputation', count(*) FROM ip_reputation
UNION ALL SELECT 'ip_geolocation', count(*) FROM ip_geolocation
UNION ALL SELECT 'domain_reputation', count(*) FROM domain_reputation
UNION ALL SELECT 'cve_records', count(*) FROM cve_records
UNION ALL SELECT 'security_logs', count(*) FROM security_logs;
"
```

Check the MCP server is serving:

```
docker compose logs mcp_server
```

## Connecting an MCP client

- **Transport:** streamable-http
- **URL:** `http://localhost:8000/mcp` (or `http://<host>:8000/mcp` if
  not running locally)

Example using the Python `mcp` SDK:

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("http://localhost:8000/mcp") as (read, write, _):
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        result = await session.call_tool("lookup_ip_reputation", {"ip": "203.0.113.10"})
```

## Tool contracts

All 5 tools are stable -- names, parameters, and return shapes will not
change as the storage backend evolves.

| Tool | Parameters | Returns |
|---|---|---|
| `lookup_ip_reputation` | `ip: str` | `{ip, malicious: bool, score: int (0-100), sources_flagging: [str], first_seen: str \| null}` |
| `geolocate_ip` | `ip: str` | `{ip, found: bool, country, city, asn, org: str \| null}` |
| `query_logs` | `src_ip: str, hours: int = 24` | `{src_ip, hours, count: int, logs: [{id, timestamp, event_type, src, detail}]}` |
| `lookup_cve` | `cve_id: str` | `{cve_id, found: bool, severity, cvss_score, description, affected_products: [str], published, synthetic: true}` |
| `check_domain_reputation` | `domain: str` | `{domain, malicious: bool, score: int (0-100), category, sources_flagging: [str], first_seen: str \| null}` |

Unknown IPs/domains/CVE IDs are never an error -- each tool returns a
well-formed zero/null "not found" response instead of raising.
