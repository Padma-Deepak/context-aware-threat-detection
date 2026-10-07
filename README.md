# SOC Triage Agent

[![CI](https://github.com/Padma-Deepak/context-aware-threat-detection/actions/workflows/ci.yml/badge.svg)](https://github.com/Padma-Deepak/context-aware-threat-detection/actions/workflows/ci.yml)

An LLM agent that investigates security alerts the way a tier-2 analyst does: it queries real
Microsoft Sentinel / Defender XDR logs, checks threat intelligence, remembers what earlier cases found,
and returns a verdict in which **every claim cites the query that proves it**. It closes alerts on its
own only when a calibrated error guarantee holds; everything else goes to a human, whose decision
becomes training and evaluation data.

<!-- docs/demo.gif goes here after the first real run: see docs/DEPLOY.md -->

**Runs free on a laptop** with a local model (Ollama or LM Studio); OpenAI is optional and spend-capped.

## What it does

```mermaid
flowchart LR
    subgraph Sources
        D[(ExCyTIn MySQL<br/>8 real incidents<br/>2.3 M log rows)]
        S[SigmaHQ rules<br/>compiled to SQL]
        TI[Threat intel<br/>NVD · CISA KEV · ATT&CK<br/>AbuseIPDB · ThreatFox]
    end
    D -- Defender alerts --> Q[Alert queue]
    S -- detections --> Q
    Q --> A["LangGraph agent<br/>run_sql · recall · threat_intel<br/>→ cited verdict"]
    A <--> M[("Case memory<br/>entity graph, lossless")]
    A --> C{"confidence ≥ calibrated<br/>threshold?"}
    C -- yes --> X[Auto-close / auto-confirm]
    C -- no --> R[Human review UI]
    R -- labels --> E[Eval set + recalibration]
```

| Piece | What it is | Where |
|---|---|---|
| **Real data** | ExCyTIn-Bench (Microsoft, ICML 2026): 8 attack incidents from a real Azure tenant, 34-54 Sentinel/Defender tables each, 589 expert-graph questions | `triage/excytin/`, `docker-compose.excytin.yml` |
| **Detections** | A Sigma → SQL compiler for Defender tables. Compiles **1,680 of 1,734** SigmaHQ Windows rules (97%) in the mapped categories; refuses the rest with a reason instead of mistranslating. 23 SigmaHQ rules vendored; on the ransomware incident they fire on shadow-copy deletion, boot tampering and Mimikatz | `triage/sigma/` |
| **Agent** | LangGraph tool loop; read-only SQL (allow-list + SELECT-only DB user + timeout); Pydantic-validated verdict with per-claim evidence ids; bounded retries, step limit, prose fallback | `triage/agent.py`, `triage/triage_agent.py` |
| **Memory** | Lossless entity graph (IPs, hosts, accounts, SIDs, hashes, processes, URLs) built with regex + column hints, no LLM. Recall is guaranteed by test: any entity in any tool result is retrievable verbatim with its source row, even parts hidden by display truncation | `triage/memory.py` |
| **Escalation** | Conformal selective prediction (Learn-then-Test, Bonferroni over a fixed grid): auto-decide only above the threshold that keeps the error rate ≤ α with probability ≥ 1-δ | `triage/conformal.py` |
| **Threat intel** | NVD 2.0, CISA KEV, MITRE ATT&CK (free); AbuseIPDB, ThreatFox (free keys). Record/replay HTTP cache; private IPs are never sent out | `triage/intel/` |
| **Analyst UI** | Streamlit: queue, case view with cited findings, investigation timeline, entity graph, review form, metrics | `triage/ui/app.py` |
| **Interfaces** | CLI, MCP server (any MCP client can use the tools), Docker image | `triage/cli.py`, `triage/mcp_server.py` |
| **Engineering** | 160+ tests with a scripted model; LLM record/replay cassettes so CI needs no key; budget guard; OpenTelemetry tracing (Langfuse/Jaeger via OTLP); secret-scan test | `tests/`, `.github/` |

## Results

**No model results yet.** The pipeline is built and tested end to end against the real data with a
scripted model; the numbers come from running a local model (free) with the commands below. The
evaluation is designed so the result is trustworthy whichever way it comes out:

- **Memory benchmark** (ExCyTIn QA): accuracy by memory mode (`none`, `qa_notes`, `full`, `graph`) with
  question-level bootstrap CIs, a paired exact McNemar test, and an early-vs-late split (memory can only
  help questions that come after others in the same incident).
- **Triage**: malicious recall, misses (malicious called benign), false-positive rate on reviewed benign
  alerts, escalation rate, error of automatic decisions, citation validity, cost and time per alert.
- **Robustness**: prompt-injection success rate with a hostile row planted in tool output.

## Quickstart

```bash
uv venv -p 3.12 .venv && source .venv/bin/activate && uv pip install -r requirements-dev.txt
pytest -q                                   # no model, key or database needed
```

Full setup (data download, local model, benchmark, triage app): **[docs/EXCYTIN.md](docs/EXCYTIN.md)**.
The short version:

```bash
python -m triage.excytin.setup_db && EXCYTIN_DATA=~/excytin-data/data_anonymized/incidents \
  docker compose -f docker-compose.excytin.yml up -d
ollama pull gpt-oss:20b
python -m triage.excytin.run --memory none,graph --per-incident 25 --out results/excytin/main.jsonl
python -m triage.excytin.analyze results/excytin/main.jsonl
python -m triage.cli ingest && python -m triage.cli investigate --limit 40
streamlit run triage/ui/app.py
```

## Design decisions

- **Retrieve, never compress.** v1 of this project ([docs/V1_BENCHMARK.md](docs/V1_BENCHMARK.md)) compressed
  agent history with an LLM summary and could not show it was safe. Security work needs every
  identifier, so memory here is verbatim and indexed, and the agent asks for what it needs.
- **The model writes SQL, so the database cannot be trusted to the model.** Three independent guards:
  statement allow-list, a MySQL user with SELECT only (tested: DELETE is denied), server-side timeout.
- **Citations are checked, not trusted.** A claim citing an evidence id that no tool produced is flagged.
- **No calibration, no automation.** Until a threshold is calibrated on labelled cases, every alert
  escalates.
- **Labels are honest.** Defender alerts in a confirmed incident are labelled malicious. The dataset has no
  benign labels, so false-positive rate is reported only on reviewer-labelled alerts.
- **Free by default.** Local models; a response cache makes reruns and resumes free; paid calls stop at
  `TRIAGE_BUDGET_USD`.

## Limitations

- ExCyTIn is one tenant under simulated attack; alerts are mostly true positives. A real SOC's alert mix is
  dominated by false positives.
- The dataset's loader stripped backslashes from paths (upstream behaviour, kept for comparability), so
  Sigma path patterns are matched without them.
- ExCyTIn IPs are anonymised; external IP reputation mostly returns "not found" on this data.
- Accuracy here is answer accuracy; upstream's headline reward also gives partial credit for intermediate
  steps, so the numbers are not directly comparable to that reward.

## Repository

```
triage/            the agent, memory, conformal escalation, Sigma compiler, intel, case store, UI, CLI, MCP server
triage/excytin/    ExCyTIn loader, SQL tool, benchmark runner, grader, analysis, model bake-off
data/excytin/      ExCyTIn questions (MIT, vendored)
tests/             unit tests (scripted model) + live tests (-m excytin) + v1 tests
docs/              EXCYTIN.md runbook, DEPLOY.md, V1_BENCHMARK.md, EXPERIMENTS.md (v1)
agent/, mcp_server.py, data.py, db/, scenarios*.json    v1: the synthetic context-compression benchmark
```

## Credits

ExCyTIn-Bench: Wu et al., *ExCyTIn-Bench: Evaluating LLM agents on Cyber Threat Investigation*, ICML 2026
([code](https://github.com/microsoft/SecRL), MIT). Sigma rules: [SigmaHQ](https://github.com/SigmaHQ/sigma)
(DRL 1.1). Conformal selection: Angelopoulos et al., *Learn then Test*, 2021.
