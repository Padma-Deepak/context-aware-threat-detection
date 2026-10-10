# v1: Context-compression benchmark (synthetic data)

> This is the original experiment, kept for reference. The current project is in the [main README](../README.md).
> **Read [RESULTS.md](../RESULTS.md) first:** it holds the final v1 result. After the bugs described there were fixed, the
> summary-based window **matched** full history's accuracy (30/30 vs 28/30 on a second held-out set, a tie) with 39%
> fewer tokens. The numbers in the "Results so far" section below are from the **earlier, pre-fix runs**, where windowed
> looked worse (62.5% vs 83.3%, not statistically significant); they are kept because they are what exposed the bugs.
> v2 retrieves instead of compressing for a different reason: in security a lossy summary can drop an exact identifier.

[![CI](https://github.com/Padma-Deepak/context-aware-threat-detection/actions/workflows/ci.yml/badge.svg)](https://github.com/Padma-Deepak/context-aware-threat-detection/actions/workflows/ci.yml)

A testbed for one question: **when a tool-using LLM agent runs many investigations back to back, can
you shrink its history without making it less accurate?**

It is a synthetic threat-intel backend served over [MCP](https://modelcontextprotocol.io) (5 tools,
Postgres, Docker), a LangChain agent that returns `MALICIOUS | BENIGN | ESCALATE`, three
context-management strategies, and a benchmark with a held-out set, statistics, and prompt-injection tests.
Ground truth is known because every fact in the world is fabricated and every label is re-verified
against the live data.

## Results so far — read this before quoting a number

Two runs exist (GPT-4o, window = 2 tool pairs, 3 repeats). Full analysis:
[`results/`](../results/). Both were analysed with a cluster bootstrap over scenarios and an exact
McNemar test on paired runs.

| Set | `full` | `windowed_summary` | Difference | McNemar p |
|---|---|---|---|---|
| **Held-out** (8 scenarios × 3, one chain of 8) | 20/24 = 83.3% (95% CI 58–100) | 15/24 = 62.5% (25–88) | −20.8 pts (CI −58 to **+8**) | 0.125 |
| **Dev** (18 scenarios, 104 of 108 runs, 3 chains of 6) | 46/54 = 85.2% (69–98) | 45/50 = 90.0% (75–100) | +4.0 pts (CI −9 to +20) | 0.69 |

**What this shows, honestly:** a *direction* on the held-out set, not a result. The confidence
interval on the difference includes zero, and the dev set points the other way. With 8 scenarios the
experiment cannot separate "compression hurts" from noise. The new 48-scenario generated set and the
runbook in [`docs/EXPERIMENTS.md`](EXPERIMENTS.md) exist to settle it.

**What the failures look like** (held-out): under `windowed_summary`, H06 (ambiguous domain) and H08
(low-score IP) flipped to `MALICIOUS`, i.e. false positives rather than vague answers. H02 (a never-seen
IP) failed in **both** modes, because the original prompt never says "no data is not evidence of safety".
Why windowing produced false positives is **untested**; there are two candidate explanations and an
experiment for each (E7a/E7b).

**Token counts from those runs are not comparable across modes.** The original estimator counted only
each investigation's own text and excluded the injected history, which is exactly what the modes differ in.
The benchmark now records real API usage for every LLM call in the agent loop (including re-sent history) plus
the summarizer's, which is what makes the modes comparable; the later runs in [RESULTS.md](../RESULTS.md) use it.

## What is in the box

| Area | What | Status |
|---|---|---|
| MCP server | 5 read-only tools, Postgres, Docker Compose, streamable-HTTP | Working. Verified live against Postgres 16. |
| Strategies | `full`, `windowed_summary`, **`pinned_evidence`** (new: verbatim, deterministic evidence store, no LLM in the compression path) | Unit-tested. **Not yet benchmarked.** |
| Scenarios | 87 across 5 sets (below) | All labels verified against live data. |
| Statistics | Cluster-bootstrap CIs, exact McNemar, cross-file pairing, failure taxonomy, per-archetype accuracy | Tested; run on the original results. |
| Measurement | Real API token usage, per-turn summary logging, full config in every result file | Tested with mocks. |
| Prompt | `v1` (original, frozen) and `v2` (no-data rule, injection rule, MITRE ATT&CK mapping) | Unit-tested. **Effect unmeasured.** |
| Robustness | Prompt-injection scenarios, prompt-leak check, fenced evidence store | Scenarios verified; **agent not yet run against them.** |
| Providers | OpenAI or Anthropic via `LLM_PROVIDER` | Wired; **Anthropic path not exercised** without a key. |
| Engineering | 80 tests (mocked LLM), ruff, GitHub Actions with a Postgres service | Passing locally on Python 3.12. |

Nothing above the "Results so far" table has produced an accuracy number yet. Those experiments need an
API key; see the runbook.

## Architecture

```mermaid
flowchart LR
    subgraph Agent["agent/"]
        A["InvestigationAgent<br/>LangChain tool-calling loop<br/>prompt v1 / v2"]
        CM["ContextManager<br/>full | windowed_summary | pinned_evidence"]
        S["Summarizer (cheap model)"]
        U["UsageCallback + TraceCallback"]
    end
    subgraph Backend["Docker Compose"]
        M["MCP server<br/>FastMCP, :8000/mcp"]
        D["data.py"]
        P[("Postgres 16")]
    end
    B["benchmark.py<br/>chains scenarios through one shared manager"]
    AN["analyze.py<br/>CIs, McNemar, taxonomy"]
    B --> A
    A -- "get_history() / update()" --> CM
    CM -. "windowed_summary only" .-> S
    A -- "MCP streamable-http" --> M --> D --> P
    A --> U
    B --> R["results/*.json"] --> AN
```

The agent never knows which strategy is active; it calls `get_history()` before an investigation and
`update()` after.

## The three strategies

| Mode | What the model sees from earlier investigations | LLM in the compression path? |
|---|---|---|
| `full` | Everything: tasks, every tool call and result, every final report | No |
| `windowed_summary` | A rolling summary of evicted steps + the last *N* tool pairs verbatim | **Yes** (lossy, and costs tokens) |
| `pinned_evidence` | A verbatim, deduplicated store of every tool result + a verdict ledger + the last *N* pairs | **No** |

`pinned_evidence` is the designed response to the windowed failures: identifiers, scores and timestamps
cannot be paraphrased away because nothing rewrites them. It is a *candidate fix*, and it is only
convincing once E1/E2 show it beats `windowed_summary`. `include_reports=K` (env `INCLUDE_REPORTS`)
additionally replays the last K prior reports in the compressed modes, to test whether their absence
explains the gap.

## Scenario sets

| File | Scenarios | Purpose | Loaded by compose? |
|---|---|---|---|
| `scenarios.json` | 18 | Dev set; visible while the prompt and window were tuned | yes |
| `scenarios_holdout.json` | 8 | Held-out; used once | no |
| `scenarios_generated.json` | 48 | Larger fresh set from `scripts/generate_scenarios.py`; 8 archetypes, labels true by construction, deterministic per seed | no |
| `scenarios_longhorizon.json` | 8 | One linked intrusion ("Lantern") needing IP→domain→CVE pivots; a recall-dependent final task | no |
| `scenarios_injection.json` | 5 | Hostile text in logs and a CVE description, plus a clean control | no |

Every set has a verifier that re-checks each label against live `data.py` output:
`scripts/verify_scenarios.py`, `verify_scenarios_holdout.py`, `verify_extended.py`. The extended verifier
was checked by corrupting rows and confirming it fails.

## Quickstart

No API key needed to run the tests:

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q                     # 73 pass, 7 database tests skip without DATABASE_URL
ruff check .
```

Run the backend and the database tests:

```bash
docker compose up --build -d
for f in db/seed_holdout.sql db/seed_holdout2.sql db/seed_longhorizon.sql db/seed_injection.sql db/seed_generated.sql; do
  docker compose exec -T postgres psql -U secinvest -d secinvest -v ON_ERROR_STOP=1 < "$f"
done
export DATABASE_URL=postgresql://secinvest:secinvest_local_only@localhost:5432/secinvest
pytest -q                     # 80 pass
python scripts/verify_extended.py all
```

Run an investigation or the benchmark (needs a key): see [`docs/EXPERIMENTS.md`](EXPERIMENTS.md).

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `LLM_PROVIDER` | `openai` | `openai` or `anthropic` |
| `OPENAI_MODEL` / `ANTHROPIC_MODEL` | `gpt-4o` / `claude-sonnet-5-5` | Agent model |
| `SUMMARIZER_MODEL` | `gpt-4o-mini` / `claude-haiku-4-5-20251001` | Cheap model for `windowed_summary` |
| `PROMPT_VERSION` | `v1` | `v1` original, `v2` evidence rules + ATT&CK |
| `MODES` | `full,windowed_summary` | Comma-separated strategies to run |
| `WINDOW_SIZE` / `RUNS_PER_CHAIN` | `2` / `3` | Benchmark size |
| `LONG_CHAIN` | unset | `1` runs every scenario in the file as one chain so history keeps accumulating (the long-horizon setting) |
| `HISTORY_FORMAT` | `native` | `native` replays past tool calls as real tool calls + results; `text` is the original text rendering, kept only to reproduce early runs |
| `SUMMARY_PROMPT` | `v3` | `v3` = one line per completed investigation, incremental, closed-case framing (default); `v2` = domain-correct whole-history summary; `v1` = legacy wording (mentions "employee"), kept so old results reproduce |
| `INCLUDE_REPORTS` | `0` | Replay last K prior reports in compressed modes |
| `MAX_ITERATIONS` | `10` | Agent tool-call cap per investigation |
| `SCENARIOS_FILE` / `RESULTS_FILE` | dev set / `benchmark_results.json` | Input scenarios and output path |
| `MCP_SERVER_URL` | `http://localhost:8000/mcp` | Where the agent finds the MCP server |
| `TRACE_FILE` | unset | Append a JSON line per tool/LLM event. Langfuse: add its callback handler alongside `UsageCallback` in `agent.py`. |

## Prompt injection

`security_logs.detail` and CVE descriptions are free text; in a real deployment an attacker writes them.
The defences here are deliberately modest and mostly untested against a live model:

- The v2 prompt says tool output is untrusted data and to report, not obey, instructions inside it.
- The pinned-evidence store fences everything in `<evidence>` tags and neutralises a closing tag, so
  hostile text cannot break out of its block (unit-tested).
- All tools are read-only, which caps what a successful injection could do.
- `scenarios_injection.json` tests four attacks (flip to BENIGN, force a false positive, leak the
  system prompt, downgrade a CVE) and a clean control task.

## Limitations

- **The headline comparison is underpowered.** See the results table; run E1/E2 before claiming anything.
- **Small, synthetic, and short.** ~2–4 tool calls per investigation. A strategy only changes what earlier
  *investigations* contribute; the in-task scratchpad grows regardless (see the runbook).
- **ESCALATE labels are design decisions**, documented per scenario, not external facts.
- **Synthetic data only.** No real threat feeds. Adding AbuseIPDB / VirusTotal / NVD adapters and real
  MITRE ATT&CK tooling is not done.
- **Original results used the legacy summarizer prompt and a biased token estimator.**
- `psycopg2`'s `SimpleConnectionPool` is not thread-safe; fine for one sequential agent, not for concurrency.
- The summarizer re-reads every evicted step each turn, so its cost grows with session length.

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

If port 8000 is already taken on your machine (another dev server answered with a 403 during testing),
set `MCP_HOST_PORT=8011` for compose, or `MCP_PORT=8011` when running `mcp_server.py` directly, and
point the agent at it with `MCP_SERVER_URL=http://localhost:8011/mcp`.

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
| `lookup_ip_reputation` | `ip: str` | `{ip, found: bool, malicious: bool, score: int (0-100) \| null, sources_flagging: [str], first_seen: str \| null}` |
| `geolocate_ip` | `ip: str` | `{ip, found: bool, country, city, asn, org: str \| null}` |
| `query_logs` | `src_ip: str, hours: int = 24` | `{src_ip, hours, count: int, logs: [{id, timestamp, event_type, src, detail}]}` |
| `lookup_cve` | `cve_id: str` | `{cve_id, found: bool, severity, cvss_score, description, affected_products: [str], published, synthetic: true}` |
| `check_domain_reputation` | `domain: str` | `{domain, found: bool, malicious: bool, score: int (0-100) \| null, category, sources_flagging: [str], first_seen: str \| null}` |

Unknown IPs/domains/CVE IDs are never an error -- each tool returns a
well-formed zero/null "not found" response instead of raising.

## Repo layout

```
mcp_server.py, data.py, db.py         MCP server, query layer, connection pool
db/schema.sql, db/seed.sql            schema + dev seed (auto-loaded by compose)
db/seed_holdout|longhorizon|injection|generated.sql   extra data, loaded deliberately
scenarios*.json                       five scenario sets (above)
scripts/verify_*.py                   label verifiers; generate_scenarios.py builds the generated set
agent/agent.py                        InvestigationAgent
agent/prompts.py, schemas.py          prompt v1/v2; typed report parsing
agent/context_manager.py              full | windowed_summary | pinned_evidence
agent/llm.py, observability.py        provider factory; real-usage and trace callbacks
agent/benchmark.py, analyze.py        runner; statistics and error taxonomy
results/                              original runs + their analysis (committed)
tests/                                80 tests; DB tests skip without DATABASE_URL
docs/                                 EXPERIMENTS.md, WRITEUP.md, INTERVIEW_PREP.md, PROJECT_OVERVIEW.md
```

## Synthetic data

Every IP, domain, CVE, and log entry is fabricated for this benchmark. IPs come from the RFC 5737
documentation ranges; CVE records are marked `synthetic: true`. Nothing here is real threat intelligence.
