# Does compressing an agent's memory make it worse? A small, honest experiment

*Draft. The sections marked **TODO** depend on experiments that need an API key and have not been run.*

## The question

Agents that run many investigations back to back accumulate a transcript of every tool call and result.
Resending all of it each turn is slow and expensive. The popular fix is to keep the last few tool calls
verbatim and have a cheaper model summarize the rest. It sounds free. I wanted to measure whether it is.

## The setup

A synthetic threat-intel backend (five tools served over MCP, backed by Postgres) so that ground truth is
known: every IP, domain and CVE is fabricated, and every scenario's label is re-verified against the live
data by a script. A GPT-4o agent investigates a task and ends with `MALICIOUS`, `BENIGN` or `ESCALATE`.
Scenarios run in *chains* through one shared context manager, so history genuinely accumulates.

That last sentence is a fix. The first version of the benchmark built a fresh context manager per scenario,
so history was always empty and the two strategies were mathematically identical. I noticed because the
two arms of the experiment gave suspiciously identical numbers. A separate bug, found later, let the model
confuse an older task with the current one whenever the verbatim window straddled a task boundary; it needed
an explicit task marker.

## What I found first

On an 8-scenario held-out set, full history got 20/24 correct and windowed-plus-summary got 15/24
(83% vs 62%). On the 18-scenario dev set it was the other way round: 85% vs 90%.

Then I ran the statistics I should have run first. On the held-out set the 95% confidence interval on the
difference is −58 to +8 points and the exact McNemar p-value is 0.125. On the dev set p is 0.69. **So the
honest summary is that I saw a direction, not an effect.** Eight scenarios cannot tell "compression hurts"
from noise. It is still worth noting that tuning on the dev set made compression look fine, and only the
held-out set disagreed, which is the reason held-out sets exist.

## Three things I got wrong

1. **The token comparison was invalid.** My estimator counted each investigation's own text and left out
   the injected history, which is precisely what the strategies differ in. Full history's real cost was
   invisible while the summarizer's cost was fully counted. The benchmark now records real API usage.
2. **My explanation was untested.** I wrote that "the summary lost evidence". The data does not say that.
   Under windowing the agent flipped to `MALICIOUS` (false positives), not to vague answers. Two hypotheses
   fit: the summary carries "malicious" framing forward, or full mode wins because it replays prior *reports*
   that act like few-shot examples of calibrated verdicts. I added a switch for the second and a per-turn
   summary log for the first, so both can be tested.
3. **One failure was not about context at all.** A never-seen IP was called `BENIGN` in every run of both
   strategies, because my prompt never said that "no data" is not evidence of safety.

## What I built in response

- `pinned_evidence`: a third strategy that keeps every tool result verbatim in a deduplicated store, with no
  language model in the compression path, so identifiers and scores cannot be paraphrased away.
- Statistics: cluster-bootstrap intervals (scenarios are resampled, because repeats are not independent),
  exact McNemar on paired runs, cross-file pairing for prompt or model comparisons, and a failure taxonomy.
- A deterministic scenario generator (48 scenarios across 8 archetypes, labels true by construction) and a
  verifier that I confirmed can fail by corrupting rows on purpose.
- A linked "campaign" scenario set that needs IP→domain→CVE pivots, and a final task whose key fact is not
  in its own text.
- Prompt-injection scenarios: hostile text in log lines and a CVE description, plus a clean control task to
  check whether poisoned text persists in memory. The evidence store fences quoted tool output and neutralises
  a closing tag, with a unit test proving hostile text cannot escape.
- 80 tests with the LLM mocked out, linting, and CI with a Postgres service.

## What I have not done

**TODO** Run the benchmark on the 48 generated scenarios with all three strategies and real token counts.
**TODO** Measure whether prompt v2 fixes the no-data failure without breaking the benign cases.
**TODO** Repeat on a second model family. **TODO** Sweep the window size.

I would rather publish the design and its decision rules before the numbers than fit a story to them afterwards;
the runbook in `docs/EXPERIMENTS.md` states each prediction in advance.

## Caveats that stay

Synthetic data and short tasks (2–4 tool calls each). A strategy only changes what *earlier investigations*
contribute; the in-task scratchpad still grows uncompressed. `ESCALATE` labels are design decisions, not facts.
And a negative result on a short task says little about long-horizon agents, which is the regime the original
paper studies.
