# Why graph memory is weak on some incidents

From the main run (`results/excytin/main.jsonl`, 186 questions per mode, `gpt-oss:20b`). Graph memory scored 73%
on incident 38 but only 16% on incident 55 and 32% on incident 166, where full replay scored 40% and 60%.
Reading the transcripts points to **SQL schema errors**, not the memory design.

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

## What to test next

**Pre-registered and set up as experiment E9** in [EXCYTIN.md](EXCYTIN.md) (`--schema full`).

Give every mode the table and column names up front (a real triage tool would know its schema), then re-run
none, full and graph on the same questions. If graph gains most, schema fumbling was the bottleneck; if all
modes gain equally, it was not specific to memory. Also: store successful queries as memory so graph can reuse
patterns, which is what full replay does implicitly.
