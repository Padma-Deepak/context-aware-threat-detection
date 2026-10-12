# Why graph memory is weak on some incidents

From the main run (`results/excytin/main.jsonl`, 186 questions per mode, `gpt-oss:20b`). Graph memory scored 73%
on incident 38 but only 16% on incident 55 and 32% on incident 166, where full replay scored 40% and 60%.
Reading the transcripts pointed to **SQL schema errors**. **That explanation was then tested (experiment E9, at the
bottom) and did not hold up: giving every mode the exact column names did not raise accuracy, and made graph memory
significantly worse.** The analysis below is kept because it is what motivated the test.

## What the data shows

| | none | full replay | graph |
|---|---|---|---|
| SQL queries that failed | 27% (434 / 1,632) | **10%** (68 / 674) | 31% (338 / 1,087) |
| `describe_table` calls per question | 1.26 | 0.18 | 0.91 |
| Incident 55: runs that hit the 15-step cap | 11 / 25 | 2 / 25 | 11 / 25 |
| Incident 166: runs that hit the 15-step cap | 8 / 25 | 2 / 25 | 13 / 25 |

- **87% of graph's failed queries (293 of 338) are "Unknown column"**: the model guesses a column that does not
  exist. The most common guess is an `Id` column (99 times), then `AlertId` (23), `CommandLine` (13),
  `Entities` (13), `UserPrincipalName` (11).
- **Failed queries use up the step budget.** In incident 55, graph and no-memory each ran out of steps on 11 of
  25 questions and scored the same (16%).
- **Full replay makes far fewer schema mistakes** (10%, and 12% even in the first third of a chain). It replays
  earlier queries and their results, so the model sees which columns exist and copies them. Graph memory stores
  entities and the rows they appeared in, not how to write a query that works.

## Accuracy by number of SQL errors in the run

| SQL errors in the run | none | full | graph |
|---|---|---|---|
| 0 | 30% (n = 10) | 48% (n = 142) | **77% (n = 47)** |
| 1-2 | 42% (n = 104) | 45% (n = 38) | 41% (n = 80) |
| 3 or more | 33% (n = 72) | 33% (n = 6) | 37% (n = 59) |

## How sure we are

- The error pattern is clear in the data (counts above).
- The link to accuracy is a **correlation**: easy questions may cause fewer errors, so "no errors → 77%" is not
  proof that fixing schema errors would lift graph to 77%.
- The `none` row shows no accuracy gain from zero errors (n = 10 is tiny), so schema knowledge alone does not
  explain everything.

## What was tested next

**Experiment E9** in [EXCYTIN.md](EXCYTIN.md) (`--schema full`); results below.

Give every mode the table and column names up front (a real triage tool would know its schema), then re-run
none, full and graph on the same questions. If graph gains most, schema fumbling was the bottleneck; if all
modes gain equally, it was not specific to memory. Also: store successful queries as memory so graph can reuse
patterns, which is what full replay does implicitly.

## Result of E9: the schema hypothesis was rejected

The same 558 questions and settings, except the prompt listed every table with its exact column names (about 6-7K
tokens). Report: [`results/excytin/schema_report.md`](../results/excytin/schema_report.md).

| Mode | Accuracy without → with schema | Change with schema (95% CI) | McNemar p | SQL queries failing | Input tokens |
|---|---|---|---|---|---|
| none | 38.2% → 38.2% | +0.0 (−7.0 to +7.0) | 1.000 | 26.6% → 21.3% | 36.0k → 98.4k |
| full | 46.8% → 47.8% | +1.1 (−5.9 to +8.6) | 0.888 | 10.1% → 14.2% | 78.1k → 106.5k |
| graph | 48.9% → **36.6%** | **−12.4 (−19.9 to −5.4)** | **0.002** | 31.1% → 22.4% | 39.3k → 97.6k |

**The pre-registered predictions were wrong:**

| Prediction | Outcome |
|---|---|
| P1: SQL error rate falls below 10% in every mode | **Wrong.** 21%, 14% and 22%; full replay's rate went *up* |
| P2: accuracy rises in every mode | **Wrong.** none unchanged, full +1.1 (not significant), graph −12.4 |
| P3: graph gains at least as much as full | **Wrong.** Graph lost 12 points; full gained 1 |
| P4: graph vs full stays inside noise | **Wrong under the schema.** full+schema beats graph+schema by 11.3 points (95% CI −19.4 to −2.7, McNemar p = 0.011). Without the schema (main run) it was a tie (+2.2, p = 0.71) |

**Why the schema did not help.** Of the 493 remaining "Unknown column" errors, **438 (89%) are columns that exist on
another table** in that incident, and only 55 (11%) are invented names. For example `AlertId` (the single most common
error, 145 times) belongs to `AlertInfo` and `AlertEvidence`, not `SecurityAlert`; `RemoteIP` belongs to the network
and logon tables, not `DeviceProcessEvents`. The schema removed most invented names but not the model's confusion
about **which table holds which column**, and a 6-7K-token list of every table's columns does not tell it that.

**Why graph got worse is not established.** Candidates (hypotheses, untested): the larger prompt crowds out the
memory block; graph runs that never submitted rose from 8.1% to 12.4%; per-incident swings were large (#34 60→32,
#38 73→36, #39 48→20). Single run per question, and `none` also moved by 10-12 points on some incidents between
runs with identical settings, so per-incident numbers are noisy; the pooled −12.4 is significant.

**Corrections to the analysis above.**
- "Runs with zero SQL errors scored 77%" was a selection effect (easy questions cause fewer errors), not a measure of
  what fixing errors would buy.
- Graph's token advantage over full replay (39k vs 78k input tokens) mostly disappears once the schema is included
  (97.6k vs 106.5k), because the schema dominates the prompt.

**What this leaves.** Schema fumbling is **not** the main bottleneck. Ideas not yet tried: a compact "which table holds
what" guide or join map instead of a raw column dump, few-shot working queries, or letting graph memory store
successful queries (what full replay does implicitly). Treat them as hypotheses.

