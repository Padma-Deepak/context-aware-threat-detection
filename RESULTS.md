# Results

Question: can a windowed-history + rolling-summary context strategy
(`windowed_summary`) match a keep-everything baseline (`full`) on verdict
accuracy while using fewer tokens, for a tool-using security investigation
agent working through a long chain of investigations?

All runs: `gpt-4o` agent, `gpt-4o-mini` summarizer, `temperature=0`,
`WINDOW_SIZE=2`, synthetic data only. Token counts are OpenAI-reported usage
for every call in the agent loop (including re-sent history) plus summarizer
calls.

## Headline (held-out set 2, the only result used for the claim)

`scenarios_holdout2.json`: 10 scenarios run as one continuous chain, 3 repeats
per mode (60 investigations). This set was written, verified, and committed
(`749c8d1`) before any of the code fixes below were run, so neither the data
nor the fixes were shaped by its results.

| Metric | `full` | `windowed_summary` |
|---|---|---|
| Verdict accuracy | 28/30 (93.3%) | 30/30 (100%) |
| Mean tokens / investigation | 16,574 | 10,043 (**−39%**) |
| Tokens on final (10th) investigation | ~38,500 | ~15,550 (**−60%**) |
| Median latency | 27.5 s | 16.4 s |

- Accuracy: windowed **matched** full. Read the 30/30 vs 28/30 difference as a
  tie, not a win. With `temperature=0` the repeats are nearly identical, so this
  is effectively ~10 independent items. Both of full's misses were the same
  hard cross-referencing scenario (J04, answered `ESCALATE` instead of
  `MALICIOUS`).
- Tokens: the savings grow with chain length, because `full` re-sends the whole
  history on every LLM call. That's the mechanism the method targets.
- Latency: mean latency (84.7 s vs 17.3 s) is distorted by one stalled OpenAI
  request (1,640 s) in the `full` run, so the medians above are the fair
  comparison.

## How we got here (all runs, including the ones that failed)

1. **Held-out set 1, original code:** `windowed_summary` *lost*. Accuracy was
   62.5% vs 83.3%, and windowed used more tokens. Debugging that result exposed
   real defects:
   - The token metric never counted the history that `full` re-sends on every
     call, which is the exact cost being studied.
   - The summarizer prompt was carried over from an unrelated domain (employee
     identity, role permissions). It also framed prior, closed investigations as
     evidence about the current target.
   - Windowed cases had no closing verdict, and every refresh re-summarized the
     entire history.

   Because these fixes came from looking at held-out set 1, that set is spent
   and can't validate them.
2. **Dev set (`scenarios.json`), 18-scenario chain, after those fixes:** windowed
   scored 100% vs full's 50%. That result was **not trusted**. Full mode's
   failures turned out to be a baseline bug: past tool calls were replayed as
   plain text, and in long chains the model imitated that text. It typed fake
   tool calls with invented results and ended with no verdict. Fixed by
   replaying history as native `tool_calls` + `ToolMessage` pairs, which made
   the baseline stronger.
3. **Dev set re-run with the fixed baseline:** 94.4% vs 100%, −60% tokens.
   Indicative only, since the fixes were developed against this set.
4. **Held-out set 2:** the headline above. A first attempt crashed on a stalled
   OpenAI call and was re-run from scratch rather than stitched together.

## Limitations

- Small N and fully synthetic data. The scenarios were hand-written by the
  same people who built the agent.
- One model pair (`gpt-4o` / `gpt-4o-mini`) and one window size. No sweep over
  `WINDOW_SIZE` or chain length.
- The windowed history includes an instruction to treat summarized cases as
  separate, closed investigations. That framing is part of the method being
  tested; `full` has no equivalent instruction.
- Independent of context strategy, the agent reads "no data found" as
  `BENIGN`. Held-out set 1's H02 failed in both modes. The system prompt was
  left unchanged so the comparison stays controlled.

## Reproducing

```bash
docker compose up -d --build
docker compose exec -T postgres psql -U secinvest -d secinvest < db/seed_holdout2.sql
cd agent   # with OPENAI_API_KEY in agent/.env
LONG_CHAIN=1 RUNS_PER_CHAIN=3 \
SCENARIOS_FILE=../scenarios_holdout2.json \
RESULTS_FILE=benchmark_results_holdout2.json \
    python benchmark.py
```
