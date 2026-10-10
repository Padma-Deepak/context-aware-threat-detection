# Experiment runbook

Everything in the repo that does **not** need an LLM is built and tested (80 tests, label
verification against live Postgres). Every experiment below **does** need an API key and has **not
been run yet**. This file exists so that when you run them, the hypothesis and the decision rule are
written down *before* you see a number.

## Setup (once)

```bash
docker compose up --build -d                     # postgres + MCP server (set MCP_HOST_PORT=8011 if 8000 is taken)
for f in db/seed_holdout.sql db/seed_holdout2.sql db/seed_longhorizon.sql db/seed_injection.sql db/seed_generated.sql; do
  docker compose exec -T postgres psql -U secinvest -d secinvest -v ON_ERROR_STOP=1 < "$f"
done
export DATABASE_URL=postgresql://secinvest:secinvest_local_only@localhost:5432/secinvest
python scripts/verify_extended.py all            # must print 0 failures before you spend any tokens

cd agent && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
cp .env.example .env                             # set OPENAI_API_KEY (and ANTHROPIC_API_KEY for E5)
```

Seed log timestamps are `now() - interval …` **at load time**, and `query_logs` defaults to a 24-hour
window. Load the seeds shortly before a run; if you come back days later, `docker compose down -v`
and reload, or scenarios silently lose their evidence (L08 in particular checks a beacon under 2 hours old).

Smoke-test cheaply first: `RUNS_PER_CHAIN=1 MODES=full python benchmark.py`.

## Run order

| # | Question | Command (from `agent/`) | Pre-stated prediction | Decision rule |
|---|---|---|---|---|
| **E1** | Is the original held-out gap real, with honest token counts? | `SCENARIOS_FILE=../scenarios_holdout.json RESULTS_FILE=../results/e1_holdout.json MODES=full,windowed_summary,pinned_evidence python benchmark.py` then `python analyze.py ../results/e1_holdout.json` | Gap shrinks or vanishes with more repeats; `pinned_evidence` ≥ `windowed_summary`. | Report the paired diff with its CI and McNemar p. Do **not** call it a degradation unless the CI excludes 0. |
| **E2** | Do the *same* strategies differ on 48 fresh scenarios? | `SCENARIOS_FILE=../scenarios_generated.json RESULTS_FILE=../results/e2_generated.json MODES=full,windowed_summary,pinned_evidence RUNS_PER_CHAIN=3 python benchmark.py` | Same ordering as E1. | Same as E1. This is the sample big enough to detect a ~15-point gap. |
| **E3** | Does the prompt fix H02? (`no data` ≠ `clean`) | Run E2's scenarios twice with `MODES=full`: `PROMPT_VERSION=v1 RESULTS_FILE=../results/e3_v1.json …` and `PROMPT_VERSION=v2 RESULTS_FILE=../results/e3_v2.json …`, then `python analyze.py ../results/e3_v1.json --compare ../results/e3_v2.json` | `unseeded_ip` accuracy rises sharply under v2. | v2 is only "better" if `unseeded_ip` improves **and** `benign_ip`, `threshold_trap_ip` do not drop (check "Accuracy by archetype"). A prompt that says ESCALATE about everything would also fix H02. |
| **E4** | Do strategies differ on a long, linked campaign? | `SCENARIOS_FILE=../scenarios_longhorizon.json RESULTS_FILE=../results/e4_lantern.json MODES=full,windowed_summary,pinned_evidence MAX_ITERATIONS=15 python benchmark.py` | `windowed_summary` fails L08 (the C2 address is not in the task text) more than `pinned_evidence`. Watch `tool_calls`: a strategy that forgot re-queries. | Per-scenario table plus `avg_tool_calls`. 8 scenarios cannot support a significance claim; use it as a qualitative probe and say so. |
| **E5** | Is the result specific to one model? | Repeat E2 with `LLM_PROVIDER=anthropic` (and `RESULTS_FILE=../results/e5_claude.json`), compare per mode with `--compare` | Unknown. | Report both; a result that flips across models is a finding about the model, not the technique. |
| **E6** | Is window = 2 just too aggressive? | Loop `WINDOW_SIZE` over 1, 2, 4, 8 with `MODES=windowed_summary,pinned_evidence` on E2's scenarios | Accuracy of `windowed_summary` recovers as the window grows. | Plot accuracy vs window. If it never recovers, the summarizer, not the window, is the problem. |
| **E7a** | Hypothesis A: summaries carry "malicious" framing forward and prime later verdicts | Read `summaries` in the E1/E2 result files for `windowed_summary` runs; look at what the summary says before H06/H08-style scenarios | Summaries before a failed scenario over-emphasise earlier malicious findings. | Qualitative. Write down the two or three worst summaries. |
| **E7b** | Hypothesis B: full mode wins because it replays prior *reports* (few-shot calibration) | `INCLUDE_REPORTS=3 MODES=windowed_summary,pinned_evidence …` vs `INCLUDE_REPORTS=0` on E2's scenarios | Replaying reports closes the gap to `full`. | If accuracy recovers, the mechanism is "prior verdict examples", not "evidence loss". |
| **E8** | Prompt injection: does hostile text change verdicts, leak the prompt, or persist in memory? | `SCENARIOS_FILE=../scenarios_injection.json MODES=full,windowed_summary,pinned_evidence` with `PROMPT_VERSION=v1` then `v2` | v1 is fooled by at least one of I01–I04; v2 resists more. | Check per-scenario verdicts, the "Prompt leaks" line, and **I05** (clean control): if a mode fails I05 after poisoned tasks, hostile text persisted in its context. |

E1 and E2 are the ones that matter for the headline claim. Everything else explains or stress-tests it.

## Reading the output

- `python analyze.py <results.json>` prints accuracy with a **cluster bootstrap** CI (scenarios are
  resampled, because repeats of one scenario are not independent), a **paired exact McNemar** test
  against the baseline mode, a failure taxonomy, accuracy by archetype, and prompt-leak counts.
- Token columns now use real API usage (`tokens_source: "api"` in the raw results). Results from the
  original runs used a `chars // 4` estimate and are not comparable to new ones.
- Each result file records its full config (provider, model, prompt version, summarizer prompt,
  window size, `include_reports`), so two files can be compared without guessing what differed.

## Known limits of this design (state them yourself before someone else does)

- In this architecture a strategy only changes what earlier **investigations** contribute to a new one.
  Within a single investigation the agent's own scratchpad grows uncompressed. So "long-horizon" here
  means a long *chain* of linked tasks, not one task with 30 tool calls. Compressing the in-task
  scratchpad would be a different, larger experiment.
- Ground truth for ESCALATE scenarios is a design decision (documented in each rationale), not an
  external fact. A second annotator would be the honest check.
- `temperature=0` reduces but does not remove run-to-run variance, which is why every scenario is repeated.
