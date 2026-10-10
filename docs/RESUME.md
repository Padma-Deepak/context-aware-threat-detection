# Resume and interview notes

Fill the brackets from `results/excytin/report.md` and `python -m triage.cli metrics` after the runs in
[EXCYTIN.md](EXCYTIN.md). Do not quote a number you have not produced.

## Bullets

- Built an LLM SOC triage agent (LangGraph, MCP, MySQL) that investigates Microsoft Sentinel/Defender alerts
  from ExCyTIn-Bench's real attack incidents (2.3M log rows), returning verdicts whose every claim cites the
  query that produced it; [X]% malicious recall, [Y]% of reports with valid citations, $0 per alert on a
  local model.
- Designed lossless graph memory (deterministic entity extraction, test-guaranteed verbatim recall) that
  changed answer accuracy on later questions in an incident by [+Z] pts vs no memory ([CI], McNemar p=[p],
  n=[n]).
- Added conformal escalation (Learn-then-Test) so the agent auto-closes only when a calibrated bound keeps
  automatic-decision error ≤ [α]; it handled [C]% of alerts automatically and escalated the rest.
- Wrote a Sigma→SQL compiler that runs 97% of SigmaHQ's Windows detection rules (1,680/1,734) on Defender
  tables, plus record/replay caches for LLM and threat-intel calls so CI runs 160+ tests with no API key.
- Measured prompt-injection robustness with hostile rows planted in tool output: [S]% attack success.

## Questions to be ready for

- Why not summarise history? (v1 tried, and after its bugs were fixed the summary window matched full history with
  39% fewer tokens on a small synthetic set, so it works; but a lossy summary can drop an exact IP, SID or
  timestamp, which matters in security, and retrieval gives a recall guarantee I can test.)
- What does the conformal guarantee actually promise, and what does it assume? (Exchangeability between
  calibration and new alerts; it bounds error among auto-decided alerts, not overall.)
- Where do labels come from, and what can't you measure? (Incident-linked alerts are malicious; benign only
  via review; false-positive rate needs reviews.)
- How do you stop the model from damaging the database? (Allow-list, SELECT-only user, timeout; tested.)
- What happens when the model never calls submit? (Two nudges, step limit forces submit-only tools, prose
  fallback with confidence 0, all recorded.)
