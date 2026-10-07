> **Superseded. Kept for history; read [../README.md](../README.md) instead.** This overview predates a
> statistical re-analysis and contains claims that did not survive it: (1) the 83% vs 62.5% held-out gap
> is *not* statistically significant (McNemar p = 0.125; CI on the difference includes 0); (2) the
> "windowing cost more tokens" claim rests on a token estimator that excluded the injected history;
> (3) "the summary lost evidence" is an untested explanation, and the failures were false positives
> (`MALICIOUS`), not vague answers; (4) the dev set actually favoured windowing (90% vs 85%).

# Context-Aware Threat Detection — Project Overview

## What this project is

This is a research-style engineering project with two halves:

1. **A synthetic security-investigation backend**, exposed as an [MCP](https://modelcontextprotocol.io)
   (Model Context Protocol) server — a mock threat-intelligence API that a
   tool-calling AI agent can query.
2. **An LLM agent + benchmark** that uses that backend to investigate
   security "tasks" (e.g. *"Is IP 185.220.101.5 malicious?"*) and produce a
   structured verdict — plus an experiment comparing **two different ways
   of managing an agent's conversation history** ("context management")
   to see which one gives the best accuracy for the least token/latency
   cost.

The central question the project set out to answer:

> When a tool-using LLM agent runs many investigations back-to-back, can
> you compress its accumulated history (instead of resending the entire
> transcript every turn) *without* making it less accurate?

This is essentially an applied test of ideas from the paper **"Less
Context, Better Agents: Efficient Context Engineering for Long-Horizon
Tool-Using LLM Agents"** (Lodha et al., arXiv:2606.10209), run on a
purpose-built, fully synthetic security-investigation task so the ground
truth is known and gradeable.

All data used anywhere in the project — IPs, domains, CVEs, log entries —
is **fabricated**. IPs are drawn from IANA/RFC 5737 documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) reserved for exactly
this kind of example use and never assigned to real hosts; CVE records are
marked `synthetic: true` and don't correspond to real vulnerabilities.
Nothing here is real threat intelligence.

## Why it's structured this way

A tool-calling agent that runs investigation after investigation
accumulates a growing transcript of past tool calls and results. Resending
that whole transcript on every single call (the naive/default approach)
gets expensive and slow as the history grows. The obvious fix — window the
history and summarize what falls out of the window with a cheaper model —
sounds free, but nobody had measured whether it actually costs accuracy
on this kind of task. So the project built:

- A **controlled environment** (the MCP server) where every fact is known
  and scripted, so any wrong verdict is unambiguously the agent's fault,
  not bad/ambiguous data.
- A **held-out evaluation set**, deliberately kept separate from the data
  used to write the prompt and tune parameters, specifically to avoid the
  trap of tuning a system until it looks good on the exact data you're
  measuring it against (see "Held-out evaluation" below — this was a
  scientific-rigor concern from early on in the project).

## Architecture

```
┌─────────────────────┐        MCP (streamable-http)        ┌───────────────────────┐
│   InvestigationAgent │ ───────────────────────────────────▶│   MCP server           │
│   (agent/agent.py)   │◀───────────────────────────────────│   (mcp_server.py)      │
│  LangChain tool-     │        5 read-only tools             │  FastMCP, port 8000    │
│  calling loop, GPT-4o│                                      └──────────┬────────────┘
└──────────┬───────────┘                                                 │
           │ get_history() / update()                                    ▼
           ▼                                                   ┌───────────────────┐
┌──────────────────────┐                                       │  data.py           │
│   ContextManager      │                                       │  (query layer)      │
│ (agent/context_manager│                                       └──────────┬─────────┘
│  .py) — "full" or      │                                                  ▼
│  "windowed_summary"    │                                       ┌───────────────────┐
└──────────┬────────────┘                                        │  Postgres (docker)  │
           │ (windowed_summary only)                             │  db/schema.sql +    │
           ▼                                                     │  db/seed.sql        │
   gpt-4o-mini summarizer                                        └───────────────────┘
           
┌──────────────────────┐
│  benchmark.py         │  runs scenarios.json through both context modes,
│                       │  N times each, and prints a comparison table
└──────────────────────┘
```

### 1. The MCP server (`mcp_server.py`, `data.py`, `db.py`, `db/`)

A mock security-investigation backend exposing **5 read-only tools** over
MCP's streamable-http transport, backed by Postgres:

| Tool | Purpose |
|---|---|
| `lookup_ip_reputation` | Threat score (0–100) + which feeds flagged an IP |
| `geolocate_ip` | Country, city, ASN, hosting org for an IP |
| `query_logs` | Security events (failed logins, port scans, outbound connections, downloads) generated by a source IP |
| `lookup_cve` | Severity/CVSS/description for a (synthetic) CVE ID |
| `check_domain_reputation` | Threat score + category (malware / phishing / c2 / suspicious / benign) for a domain |

Every tool is designed so an **unknown IP/domain/CVE is never an error** —
it returns a well-formed "no data" response (`malicious: false, score: 0`,
etc.) instead of raising. This matters a lot for the research question:
an agent that can't distinguish "no data available" from "confirmed
clean" will over-trust silence, and the held-out set specifically
includes a scenario testing exactly that.

Data flows: `mcp_server.py` (tool contracts) → `data.py` (query layer,
never touches the DB directly) → `db.py` (connection pool) → Postgres,
schema defined in `db/schema.sql`, seeded from `db/seed.sql`. The whole
thing is containerized (`docker-compose.yml` + `Dockerfile`) so it starts
with a single `docker compose up --build`.

### 2. The agent (`agent/agent.py`)

`InvestigationAgent` is a LangChain tool-calling agent (`gpt-4o`,
`temperature=0` for deterministic verdicts) that:

1. Connects to the MCP server and discovers its 5 tools.
2. Runs a bounded tool-calling loop (max 10 iterations) under a system
   prompt that enforces an **investigation protocol** — check IP
   reputation first; if the score is above a threshold, pull logs and
   geolocation; follow up on any CVE or domain mentioned in the logs;
   cross-reference everything before concluding.
3. Produces a fixed-format report ending in a parseable
   `VERDICT: MALICIOUS | BENIGN | ESCALATE` line.

`investigate(task)` returns the report, the extracted verdict, tool-call
count, an estimated token cost, and wall-clock duration — everything
`benchmark.py` needs to score a run.

### 3. The context-management research (`agent/context_manager.py`)

This is the project's actual research contribution. `ContextManager`
implements two strategies for what history the agent sees on each call,
and the agent itself is written to be **completely unaware** of which one
is active — it just calls `get_history()` before investigating and
`update()` after:

- **`full`** (baseline) — every past tool call/result is kept and resent
  verbatim, every turn. Simple, but grows unboundedly.
- **`windowed_summary`** (the paper's approach) — only the last
  `window_size` tool call/result pairs are kept verbatim; everything older
  is compressed into a rolling summary by a cheaper model (`gpt-4o-mini`),
  refreshed after each investigation. The summarizer is explicitly
  instructed to preserve concrete evidence (exact IPs, scores, timestamps,
  countries) rather than writing vague summaries like "the IP looked
  suspicious" — losing specifics is exactly the failure mode this guards
  against.

A subtle bug surfaced and got fixed during development: without a clear
task boundary marker in the windowed history, the model could silently
conflate an *older* investigation with the current one when the window
spanned a task boundary — confirmed by a case where two adjacent scenarios
referenced the same domain and the agent re-investigated the wrong one.
The fix was inserting an explicit `HumanMessage` task marker before each
task's steps in the windowed view, mirroring what the `full` mode already
did naturally.

### 4. The benchmark (`agent/benchmark.py`)

Originally, each scenario got a *fresh* `ContextManager`, so
`get_history()` was always empty and the two modes could never actually
differ — there was nothing to window or summarize yet. This was caught and
fixed by **chaining** scenarios: `scenarios.json`'s 18 scenarios are
grouped into 3 hand-picked chains of 6 (grouped so entity-linked scenarios
referencing the same IP/domain land in the same chain, and so tool-call
load is balanced across chains), and each chain runs through *one shared*
`ContextManager`, so history genuinely accumulates within a chain.

Each chain runs 3 times under each mode (`full` and `windowed_summary`),
and the benchmark reports: verdict accuracy, average tokens, average
latency, and average tool-call count, plus a per-scenario breakdown.
Results are checkpointed to disk after every single run (not just at the
end) so an interrupted benchmark (e.g. hitting an API rate limit) doesn't
lose completed work.

**Token accounting note:** `tokens_used` for `windowed_summary` mode
includes both the main agent's own (estimated) request *and* the real,
billed token cost of the `gpt-4o-mini` summarizer call that
`ContextManager.update()` triggers — otherwise `windowed_summary` would
look artificially cheaper than it actually is, since the summarizer calls
are real API requests with real cost.

### 5. Held-out evaluation

`scenarios.json` (the 18-scenario dev set) was visible while the agent's
system prompt was written and while `WINDOW_SIZE` was tuned — so scoring
well on it only proves the system was built to fit that exact data, not
that it generalizes. To test generalization honestly, the project built a
**second, disjoint batch**: `scenarios_holdout.json` (8 scenarios) plus
`db/seed_holdout.sql` (6 new IPs, 1 new domain, 1 new CVE), covering cases
the dev set didn't:

- A truly unseeded IP (does the agent treat "no data" as "confirmed
  clean," which would be wrong?)
- A reputation score sitting one point past the system prompt's own
  `score > 30` investigation-trigger threshold
- A CVE ID that only appears inside log content, not in the task text
  itself (tests whether the agent actually reads tool output rather than
  just the task string)
- A combined brute-force + port-scan pattern from one source

The held-out seed data is **deliberately not wired into**
`docker-compose.yml`'s auto-init — if it loaded on every `docker compose
up`, it would silently become more data to develop against, defeating the
entire point. It's loaded once, manually, at the very end, run through
the same `benchmark.py` via env-var overrides
(`SCENARIOS_FILE=../scenarios_holdout.json
RESULTS_FILE=benchmark_results_holdout.json`), and the project's own
documentation is explicit that if the held-out results come back bad, the
correct response is *not* to go tweak the prompt/window size and rerun —
that would just make the "held-out" set into another dev set. A fresh,
still-unseen third batch would be needed to test any such change.

## Results

The held-out run (24 investigations per mode: 8 scenarios × 3 repeats)
gave a clear, somewhat counter-intuitive answer:

| Metric | `full` (baseline) | `windowed_summary` |
|---|---|---|
| Verdict accuracy | **83.3%** (20/24) | 62.5% (15/24) |
| Avg tokens/investigation | 984 | 2,521 |
| Avg latency | 25.1s | **11.8s** |
| Avg tool calls | 2.0 | 2.0 |

**Conclusion: context compression *degraded* accuracy on this workload**,
and — contrary to the whole point of windowing — it did **not** even save
tokens on the held-out set; the summarizer's own real API calls made
`windowed_summary` more expensive in tokens, while being roughly twice as
fast in wall-clock time. Two scenarios (`H06`, `H08`) flipped from
correct to fully incorrect under `windowed_summary`: the summary lost
evidence that mattered (e.g. an `ESCALATE`-worthy ambiguity got
collapsed into a confident wrong verdict). This is a genuine negative
result for windowed-summary compression on short, evidence-dense
security-investigation tasks with small tool-call counts — the technique
may still make sense for longer-horizon tasks where the token savings
from windowing dominate, but at this task's scale (2 tool calls/
investigation on average) the summarization overhead outweighs any
windowing benefit, and losing exact evidence costs real accuracy.

## Tools & technology used

- **Language:** Python 3.12
- **LLM:** OpenAI `gpt-4o` (main investigation agent, `temperature=0`)
  and `gpt-4o-mini` (cheap summarizer in `windowed_summary` mode)
- **Agent framework:** LangChain (`langchain`, `langchain-openai`,
  `create_tool_calling_agent` / `AgentExecutor`)
- **Protocol:** [MCP (Model Context Protocol)](https://modelcontextprotocol.io)
  via `mcp[cli]` and `langchain-mcp-adapters`, using the
  **streamable-http** transport
- **MCP server framework:** `FastMCP` (`mcp.server.fastmcp`)
- **Database:** PostgreSQL 16, `psycopg2-binary` for the connection pool
- **Containerization:** Docker + Docker Compose (2 services: `postgres`,
  `mcp_server`)
- **Config/secrets:** `python-dotenv`, `.env.example` templates for both
  the root (DB credentials) and `agent/` (OpenAI key, model, MCP server
  URL)
- **Version control:** Git, hosted on GitHub
  (`Padma-Deepak/context-aware-threat-detection`)

## Repo layout

```
mcp_server.py, data.py, db.py         MCP server + data access layer
db/schema.sql, db/seed.sql            Postgres schema + synthetic seed (dev) data
db/seed_holdout.sql                   Disjoint held-out data (not auto-loaded)
scenarios.json                        18 verified investigation scenarios (dev set)
scenarios_holdout.json                8 held-out scenarios, never used to tune the agent
scripts/verify_scenarios.py           Re-verifies dev scenarios against live data.py
scripts/verify_scenarios_holdout.py   Re-verifies held-out scenarios against live data.py
agent/agent.py                        InvestigationAgent (the tool-calling loop)
agent/context_manager.py              full vs. windowed_summary context strategies
agent/benchmark.py                    Runs scenarios through both modes, compares
docker-compose.yml, Dockerfile        Containerized MCP server + Postgres
```

Note: this folder contains two snapshots of the repo — `repo/` (an earlier
state, dev-set only, no held-out evaluation yet) and `new-repo/` (the
current state, with the held-out set, holdout run log, and documentation
of the full end-to-end setup). `new-repo/` is the up-to-date one and is a
git checkout of the GitHub repo above.

## How to run it (from `new-repo/`)

```bash
# 1. Start the MCP server + Postgres backend
docker compose up --build -d

# 2. Set up the agent
cd agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in OPENAI_API_KEY

# 3. Run a single investigation
python agent.py

# 4. Or run the full benchmark (18 scenarios x 2 context modes x 3 repeats)
python benchmark.py
```
