# Context-Aware Threat Detection System

An investigation agent that uses [MCP](https://modelcontextprotocol.io) tools to
research potential security threats (IPs, domains, CVEs, logs) and produce a
structured verdict -- plus a benchmark comparing two context-management
strategies for keeping a long-running tool-using agent cheap without hurting
its accuracy.

The project has two halves:

1. **MCP server** (`mcp_server.py`, `data.py`, `db.py`, `db/`) -- a synthetic
   threat-intelligence backend exposing 5 read-only tools over MCP.
2. **Agent + benchmark** (`agent/`) -- a LangChain tool-calling agent that
   investigates tasks against those tools, and a benchmark that runs it
   through 18 scenarios under two different context strategies.

All data is fabricated for this benchmark -- see "Synthetic data" below.

## Quickstart

```bash
# 1. Start the MCP server + Postgres backend
docker compose up --build -d

# 2. Set up the agent
cd agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in OPENAI_API_KEY

# 3. Run a single investigation
python agent.py

# 4. Or run the full benchmark (18 scenarios x 2 context modes x 3 repeats)
python benchmark.py
```

## MCP server

A **mock security-investigation backend**. It is not a real threat-intelligence
feed -- every IP, domain, CVE, and log entry is fabricated:

- IPs are drawn from RFC 5737 documentation/example ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) that IANA
  reserves for exactly this purpose and never assigns to real hosts.
- Domains, hosting orgs, and ASNs are invented.
- CVE records are entirely synthetic (`synthetic: true` on every record)
  and do not correspond to real CVEs.

### Running it

One command, from the repo root:

```bash
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

### Verifying it's healthy

Check both containers report healthy/running:

```bash
docker compose ps
```

Check Postgres actually seeded (should show 13/13/8/8/36):

```bash
docker compose exec postgres psql -U secinvest -d secinvest -c "
SELECT 'ip_reputation', count(*) FROM ip_reputation
UNION ALL SELECT 'ip_geolocation', count(*) FROM ip_geolocation
UNION ALL SELECT 'domain_reputation', count(*) FROM domain_reputation
UNION ALL SELECT 'cve_records', count(*) FROM cve_records
UNION ALL SELECT 'security_logs', count(*) FROM security_logs;
"
```

Check the MCP server is serving:

```bash
docker compose logs mcp_server
```

### Connecting an MCP client

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

### Tool contracts

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

## Agent

`agent/agent.py`'s `InvestigationAgent` connects to the MCP server, discovers
its 5 tools, and runs a LangChain tool-calling loop (`temperature=0`, up to 10
tool-call iterations) with a system prompt that enforces an investigation
order (reputation first, then logs/geolocation/CVE/domain lookups as evidence
warrants) and a fixed report format ending in a `VERDICT: MALICIOUS|BENIGN|ESCALATE`
line.

```bash
cd agent
cp .env.example .env   # set OPENAI_API_KEY at minimum
python agent.py
```

`investigate(task)` returns a dict with the report, the extracted verdict, tool
call count, an estimated token cost, and wall-clock duration.

## Context-management research

`agent/context_manager.py` is the project's research contribution: an
implementation of two context strategies from *"Less Context, Better Agents:
Efficient Context Engineering for Long-Horizon Tool-Using LLM Agents"*
(Lodha et al., arXiv:2606.10209), so `benchmark.py` can compare them
experimentally on this workload:

- **`full`** -- every past tool call and result is kept and resent verbatim
  on every turn (baseline).
- **`windowed_summary`** -- only the last `window_size` tool call/result
  pairs are kept verbatim; everything older is compressed into a rolling
  summary by a cheap model (`gpt-4o-mini`), refreshed after each
  investigation.

`InvestigationAgent` never knows which mode is active -- it just calls
`context_manager.get_history()` before each investigation and
`context_manager.update()` after.

### Running the benchmark

```bash
cd agent
python benchmark.py
```

This groups `scenarios.json`'s 18 scenarios into 3 chains of 6 (so history
actually accumulates within a chain instead of every scenario starting from
an empty `ContextManager`), runs each chain 3 times under both `full` and
`windowed_summary`, and prints a comparison table of verdict accuracy,
average tokens, average latency, and average tool-call count. Raw results are
checkpointed to `agent/benchmark_results.json` after every single run (so an
interrupted benchmark doesn't lose completed work) and finalized with
`status: "complete"` when it finishes. That file is git-ignored -- it's
generated output, not part of the repo.

**Token accounting:** `tokens_used` includes both the main agent's own
request (estimated at ~4 chars/token, since LangChain's `AgentExecutor`
doesn't surface OpenAI's real usage numbers) *and* the exact token cost of
any summarizer call `windowed_summary` mode triggered for that investigation.
Without the latter, `windowed_summary`'s reported cost would look
artificially lower than it actually is, since the summarizer's own
`gpt-4o-mini` calls are real, billed requests.

### Held-out evaluation

`scenarios.json` was visible while `SYSTEM_PROMPT` (in `agent/agent.py`) was
written and while `WINDOW_SIZE` (in `agent/benchmark.py`) was tuned -- so a
good score on it proves the system was built to fit that exact data, not
that it generalizes. `scenarios_holdout.json` and `db/seed_holdout.sql` are
a second, disjoint batch of 8 scenarios / 6 IPs / 1 domain / 1 CVE that
weren't used to write the prompt or tune anything, covering combinations the
main set doesn't: a truly unseeded IP (tests that "no data" isn't silently
treated as "confirmed clean"), a score sitting one point past the system
prompt's own `> 30` investigation-trigger threshold, a CVE ID discovered
from log content rather than the task text, and a brute-force + port-scan
combo on one source.

It's a separate file, and `db/seed_holdout.sql` is **not** wired into
`docker-compose.yml`'s auto-init -- if it loaded on every `docker compose
up`, it would just become more data you develop against, defeating the
point. Load it deliberately, once, when you're ready for a final run:

```bash
# 1. Load the held-out data into the already-running postgres container
docker compose exec -T postgres psql -U secinvest -d secinvest \
    < db/seed_holdout.sql

# 2. Verify its ground truth mechanically (same pattern as verify_scenarios.py)
DATABASE_URL=postgresql://secinvest:secinvest_local_only@localhost:5432/secinvest \
    python scripts/verify_scenarios_holdout.py

# 3. Run the benchmark against it instead of scenarios.json
cd agent
SCENARIOS_FILE=../scenarios_holdout.json \
RESULTS_FILE=benchmark_results_holdout.json \
    python benchmark.py
```

Do this **once**, at the end. If the results are bad and you go tweak
`SYSTEM_PROMPT` or `WINDOW_SIZE` in response, the held-out set has become a
dev set too, and you're back to square one -- you'd need a third, still-fresh
batch to actually test whatever you just changed.

## Repo layout

```
mcp_server.py, data.py, db.py       MCP server + data access layer
db/schema.sql, db/seed.sql          Postgres schema and synthetic seed (dev) data
scenarios.json                      18 verified investigation scenarios (dev set)
scripts/verify_scenarios.py         Re-verifies scenarios against live data.py
db/seed_holdout.sql                 Disjoint held-out data (not auto-loaded)
scenarios_holdout.json              8 held-out scenarios, never used to tune the agent
scripts/verify_scenarios_holdout.py Re-verifies held-out scenarios against live data.py
agent/agent.py                      InvestigationAgent (the tool-calling loop)
agent/context_manager.py            full vs. windowed_summary context strategies
agent/benchmark.py                  Runs scenarios through both modes, compares
```

## Synthetic data

Every IP, domain, CVE, and log entry in `db/seed.sql` is fabricated for this
benchmark -- see the MCP server section above for details. Nothing here
should be treated as real threat intelligence.
