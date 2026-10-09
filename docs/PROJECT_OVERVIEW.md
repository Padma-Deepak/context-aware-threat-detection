# SOC Triage Agent: Project Overview

*Last updated 2026-10-10. Status: **built and tested; main memory benchmark run; injection, triage and commercial-model runs still to do.***

## What this project is

An LLM agent that triages security alerts the way a tier-2 SOC analyst does. It investigates real Microsoft
Sentinel / Defender XDR logs with read-only SQL, checks threat intelligence, remembers what earlier cases found,
and returns a verdict in which **every claim cites the query that produced it**. It closes an alert on its own
only when a calibrated error bound holds; everything else goes to a human reviewer, whose decision becomes a
label for evaluation and recalibration.

It runs **free on a laptop** with a local model (Ollama or LM Studio). OpenAI is supported behind a spend cap.

The project grew out of an earlier experiment on compressing an agent's history (see "Origin" below). That
experiment could not show that summarising history is safe, and security work needs every identifier intact, so
this version **retrieves instead of compressing**: it keeps every tool result verbatim, indexes the entities in
it, and lets the agent look things up.

## Where things stand

| Area | Status |
|---|---|
| Real data loaded (ExCyTIn-Bench, 8 incidents, about 2.3 M rows) | ✅ Done, verified |
| Agent, memory, SQL guards, citations | ✅ Built, 174 tests |
| Benchmark runner, grader, statistics | ✅ Built and run |
| Sigma detection compiler | ✅ Built; 1,680 / 1,734 SigmaHQ Windows rules compile |
| Threat intel (NVD, CISA KEV, ATT&CK) | ✅ Live. AbuseIPDB / ThreatFox need free keys |
| Conformal escalation | ✅ Built; **automates 0%** (model confidence is unusable) |
| Analyst UI, CLI, MCP server, Docker | ✅ Built; UI checked in a browser |
| **Pilot benchmark** (5 per incident, 4 memory modes) | ✅ Run (too small to separate modes) |
| **Main benchmark** (25 per incident, 3 modes, 558 runs) | ✅ Run: memory helps; graph ties full replay |
| Prompt-injection run, triage on the alert queue | ⏳ Built, not run |
| Commercial-model check, public demo | ⏳ Not done |

## The main result

`gpt-oss:20b` locally, temperature 0, **186 questions per mode** (25 from each incident, 11 from the small one),
558 investigations, about 6.5 hours, **$0**. Questions run in order within each incident, so later ones can use
what earlier ones found.

| Memory mode | What the model sees from earlier questions | Accuracy (95% CI) | Gain vs none | McNemar p | Input tokens | Sec |
|---|---|---|---|---|---|---|
| `none` | nothing | 38.2% (31-45) | | | 36.0k | 45 |
| `full` | every earlier question, tool call and result | 46.8% (40-54) | +8.6 (+0.5 to +16.1) | 0.048 | 78.1k | 25 |
| **`graph`** | prior answers + automatic recall + `recall` / `search_memory` tools over an entity graph | 48.9% (42-56) | +10.8 (+2.7 to +18.8) | 0.013 | 39.3k | 55 |

**Graph vs full replay: +2.2 points (95% CI −6.5 to +10.2), p = 0.71. A tie on accuracy.**

**How to read it, honestly:**
- Memory helps: both modes beat no memory with intervals that exclude 0 (full only just).
- **Graph memory is not shown to be more accurate than replaying everything.** It matches it using about half the
  input tokens, which matters when context is the cost, but it takes about twice as long (9.6 tool calls vs 3.8)
  and cites slightly worse (83% vs 90% valid citations; 8% of graph runs never called submit vs 0% for full).
- Late in a chain, `none` fell to 26% while `full` held at 45% and `graph` at 50%; question order is a
  confound, so this is suggestive only.
- Results vary a lot by incident (graph: 73% on #38, 16% on #55, 32% on #166), one run per question.
- **Conformal escalation still certified nothing.** Confidence carries some signal (answers under 90 are right
  16% of the time, 90 or more 57%, 95 or more 66%) but nowhere near the reliability a 5-10% error target needs,
  so every alert would escalate. The guarantee works; this confidence signal is too weak.
- Answer accuracy from a small local model, not ExCyTIn's published partial-credit reward, so not comparable
  to the published chart.
- A smaller 5-per-incident pilot (`results/excytin/pilot_report.md`) pointed the same way.

Reports: `results/excytin/main_report.md`. Raw runs (without transcripts): `results/excytin/main_slim.jsonl`.

## Architecture

```
 ExCyTIn MySQL (8 incident DBs)        SigmaHQ rules ──compile──▶ SQL
        │  Defender alerts                    │ detections
        └──────────────┬──────────────────────┘
                       ▼
                 Alert queue (SQLite case store)
                       ▼
   LangGraph agent:  run_sql · describe_table · recall · search_memory · threat_intel
        │   model ⇄ tools loop → submit_verdict (Pydantic: verdict, confidence, claims + evidence ids)
        │                         ▲
        │              Case memory (entity graph, lossless, no LLM)
        ▼
   confidence ≥ calibrated threshold?  ── yes ──▶ auto-close / auto-confirm
        └─ no ──▶ human review UI ──▶ labels ──▶ eval set + recalibration
```

### Components

| Component | What it does | Where |
|---|---|---|
| Data | Loads ExCyTIn's 8 incidents into one MySQL container. The agent connects as a **SELECT-only** user | `triage/excytin/setup_db.py`, `docker-compose.excytin.yml` |
| SQL tool | One-statement allow-list, no `INTO OUTFILE` / `LOAD_FILE` / `SLEEP`, row and size caps, 30 s timeout | `triage/excytin/db.py` |
| Agent | LangGraph loop with nudges, a step limit that forces a submit-only tool set, bounded retries, a schema-validated submission, and a prose fallback | `triage/agent.py` |
| Memory | Regex + column-hint entity extraction (IPs, hosts, accounts, SIDs, hashes, URLs, files, processes), JSON-aware; SQLite graph with provenance; `recall`, `search`. A test checks that any extracted entity is recallable verbatim | `triage/memory.py` |
| Benchmark | Resumable chains of questions per incident, four memory modes, deterministic grader plus ExCyTIn's judge prompt, injection mode | `triage/excytin/run.py`, `grade.py` |
| Analysis | Cluster bootstrap, exact McNemar, early-vs-late split, conformal evaluation | `triage/excytin/analyze.py` |
| Conformal | Learn-then-Test over a fixed 21-point grid with Bonferroni correction | `triage/conformal.py` |
| Sigma | Sigma→SQL compiler for Defender `Device*` tables; refuses what it can't translate faithfully. 23 SigmaHQ rules vendored | `triage/sigma/` |
| Threat intel | NVD 2.0, CISA KEV, MITRE ATT&CK; AbuseIPDB and ThreatFox with keys; HTTP record/replay cache; private IPs never sent out | `triage/intel/` |
| Triage | Alert ingestion (643 alerts), triage agent, case store, CLI, review loop | `triage/alerts.py`, `triage_agent.py`, `cases.py`, `cli.py` |
| Interfaces | Streamlit analyst UI; MCP server; Docker image | `triage/ui/app.py`, `triage/mcp_server.py`, `Dockerfile.triage` |
| LLM client | Ollama / LM Studio / OpenAI, response cache (record/replay), spend cap, retry for known Ollama errors, OpenTelemetry tracing | `triage/llm.py`, `triage/tracing.py` |

### Key design decisions
1. **Retrieve, never compress** (above).
2. **The model writes SQL, so the database can't trust the model**: allow-list, SELECT-only user (DELETE tested as
   denied), server-side timeout.
3. **Citations are checked, not trusted**: an evidence id no tool produced is flagged.
4. **No calibration, no automation**: until a threshold is certified, everything escalates.
5. **Honest labels**: alerts in a confirmed incident are malicious; the dataset has no benign labels, so
   false-positive rate is measured only on reviewer-labelled alerts.
6. **Free by default and reproducible**: local model, response cache, record/replay so CI needs no key.

## Data

- **ExCyTIn-Bench** (Wu et al., ICML 2026, MIT): 8 attack incidents from a real Azure tenant under simulated
  attack, 34-54 Sentinel/Defender tables each, 589 test questions with answers. The agent answers by querying
  SQL. Not real company data, and IPs are anonymised.
- **643 alerts** ingested: 618 Defender alerts (610 in confirmed incidents, labelled malicious) + 25 Sigma
  detections (unlabelled until reviewed).
- **SigmaHQ** detection rules (Detection Rule License), vendored with attribution under `triage/sigma/rules/`.
- **Threat intel**: live NVD, CISA KEV and ATT&CK. IP reputation mostly returns "not found" here because the
  dataset's IPs are anonymised.

## Engineering quality
- **174 tests** with a scripted fake model; 10 of them run against the live ExCyTIn database when it is up.
- **CI** (GitHub Actions): lint + unit tests in replay mode, Postgres tests, Docker build. Needs no API key.
- **Secret-scan test** that fails if a key-shaped string is committed.
- **Bugs found and fixed while building** (each has a regression test): full-history mode replayed tool calls as
  text and the model imitated it; Ollama's tool-call parse errors killed about 10% of runs at step 0 and would
  have biased every mode; an IP at the end of a sentence wasn't recognised; JSON with lone backslashes lost
  hosts and accounts from alert entities; a first conformal method could never certify a threshold.

## How to run

Full runbook: [`EXCYTIN.md`](EXCYTIN.md). Short version, from `new-repo/`:

```bash
uv venv -p 3.12 .venv && source .venv/bin/activate && uv pip install -r requirements-dev.txt
pytest -q                                                       # no model, key or database needed
python -m triage.excytin.setup_db
EXCYTIN_DATA=~/excytin-data/data_anonymized/incidents docker compose -f docker-compose.excytin.yml up -d
OLLAMA_CONTEXT_LENGTH=65536 ollama serve &  ollama pull gpt-oss:20b
python -m triage.excytin.run --memory none,full,graph --per-incident 25 --out results/excytin/main.jsonl   # ~6.5 h
python -m triage.excytin.analyze results/excytin/main.jsonl
python -m triage.cli ingest && python -m triage.cli investigate --limit 40
streamlit run triage/ui/app.py
```

## Limitations
- Graph memory is **not** shown to be more accurate than simple full replay (a tie, p = 0.71); its advantage is half the input tokens, at twice the time per question.
- Escalation is currently 100% because the model's self-reported confidence is unusable.
- One small local model; no commercial-model result.
- ExCyTIn alerts are almost all true positives from simulated attacks in one tenant, unlike a real SOC.
- Prompt-injection robustness is built and measurable but not yet measured.
- Entity extraction is regex-based and misses entities with no recognisable shape.

## Next steps
1. Agreement-based confidence (repeated runs) and re-run conformal calibration.
2. Prompt-injection run and triage on the alert queue; review a few hundred alerts so false-positive rate is
   measurable.
3. Small commercial-model check under the spend cap.
4. Look into why graph is weak on incidents #55 and #166 and why 8% of graph runs never submit.
5. Deploy a read-only demo from a snapshot ([`DEPLOY.md`](DEPLOY.md)); record the README GIF.

## Origin: the v1 experiment (synthetic data, context compression)

The first version asked: *can you compress a tool-using agent's history (keep the last N tool calls, summarise
the rest with a cheaper model) without hurting accuracy?* It used a synthetic threat-intel backend served over
MCP (5 tools, Postgres), a GPT-4o agent returning `MALICIOUS | BENIGN | ESCALATE`, and a benchmark that chained
scenarios through one shared context manager. It lives in `agent/`, `mcp_server.py`, `data.py`, `db/` and
`scenarios*.json`, and is documented in [`V1_BENCHMARK.md`](V1_BENCHMARK.md). Motivated by Lodha et al.,
*Less Context, Better Agents* (arXiv:2606.10209).

**What v1 found, stated correctly** (an earlier version of this overview overstated it):
- Held-out: full history 20/24 = 83.3%, windowed 15/24 = 62.5%. The difference is **not statistically
  significant** (95% CI −58 to +8 points, exact McNemar p = 0.125). On the dev set it pointed the other way
  (85.2% vs 90.0%, p = 0.69). It is **a direction on eight scenarios, not a result.**
- The claim that windowing "cost more tokens" is **not valid**: the old token estimator excluded the injected
  history, the very thing the modes differ in. Real API usage is now recorded; old runs were not re-measured.
- "The summary lost evidence" is an **untested explanation**: under windowing the agent flipped to `MALICIOUS`
  (false positives), not to vague answers. Two hypotheses (summary framing; full mode replaying prior reports
  as few-shot examples) were instrumented but never tested.
- A never-seen IP was called `BENIGN` in every run of both modes. The backend returned `score: 0`, which looks
  clean. Unknown entities now return `found: false, score: null`.
- It also produced the benchmark-validity lessons carried into v2: chain questions so history actually
  accumulates, keep a held-out set, verify labels against live data, and audit what a metric measures.

**Why that led here:** v1 couldn't establish that compression is safe, and in security an exact IP, SID or
timestamp matters, so v2 keeps everything and retrieves.

## Credits
ExCyTIn-Bench (Wu et al., ICML 2026, [microsoft/SecRL](https://github.com/microsoft/SecRL), MIT). Sigma rules:
[SigmaHQ](https://github.com/SigmaHQ/sigma) (DRL 1.1). Conformal selection: Angelopoulos et al., *Learn then
Test*, 2021. Repository: `Padma-Deepak/context-aware-threat-detection`.
