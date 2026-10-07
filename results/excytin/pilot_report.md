## Accuracy by memory mode

| Mode | n | Accuracy (95% CI) | Steps | Input tok | Cost | Sec | Used recall | No submit | Valid citations |
|---|---|---|---|---|---|---|---|---|---|
| full | 40 | 60.0% (45.0%–75.0%) | 5.0 | 56827 | $0.00 | 22 | 0.0% | 0.0% | 97.5% |
| graph | 40 | 50.0% (35.0%–65.0%) | 9.3 | 33683 | $0.00 | 54 | 75.0% | 2.5% | 82.5% |
| none | 40 | 35.0% (20.0%–50.0%) | 10.6 | 30630 | $0.00 | 43 | 0.0% | 2.5% | 90.0% |
| qa_notes | 40 | 47.5% (32.5%–62.5%) | 9.0 | 29421 | $0.00 | 43 | 0.0% | 2.5% | 92.5% |

## Paired comparison against `none`

| Mode | Pairs | Difference (95% CI) | Only baseline right | Only this right | McNemar p |
|---|---|---|---|---|---|
| qa_notes | 40 | +12.5% (-5.0% to +30.0%) | 4 | 9 | 0.267 |
| graph | 40 | +15.0% (-0.1% to +32.5%) | 3 | 9 | 0.146 |
| full | 40 | +25.0% (+10.0% to +40.0%) | 1 | 11 | 0.006 |

Call a difference real only if its CI excludes 0.

## Early vs late questions in each incident

Memory can only help questions that come after others in the same incident.

| Mode | Early half | Late half |
|---|---|---|
| full | 54.2% (n=24) | 68.8% (n=16) |
| graph | 50.0% (n=24) | 50.0% (n=16) |
| none | 33.3% (n=24) | 37.5% (n=16) |
| qa_notes | 45.8% (n=24) | 50.0% (n=16) |

## Conformal escalation (random 50/50 question splits)

| Mode | Score | Target error | Auto-answered | Error on auto-answered | Splits over target |
|---|---|---|---|---|---|
| full | confidence | 5.0% | 0.0% | 0.0% | 0.0% |
| full | confidence | 10.0% | 0.0% | 0.0% | 0.0% |
| full | confidence | 20.0% | 0.0% | 0.0% | 0.0% |
| graph | confidence | 5.0% | 0.0% | 0.0% | 0.0% |
| graph | confidence | 10.0% | 0.0% | 0.0% | 0.0% |
| graph | confidence | 20.0% | 0.0% | 0.0% | 0.0% |
| none | confidence | 5.0% | 0.0% | 0.0% | 0.0% |
| none | confidence | 10.0% | 0.0% | 0.0% | 0.0% |
| none | confidence | 20.0% | 0.0% | 0.0% | 0.0% |
| qa_notes | confidence | 5.0% | 0.0% | 0.0% | 0.0% |
| qa_notes | confidence | 10.0% | 0.0% | 0.0% | 0.0% |
| qa_notes | confidence | 20.0% | 0.0% | 0.0% | 0.0% |

## Accuracy by incident

| Mode | #5 | #34 | #38 | #39 | #55 | #134 | #166 | #322 |
|---|---|---|---|---|---|---|---|---|
| full | 60% (5) | 40% (5) | 60% (5) | 60% (5) | 20% (5) | 100% (5) | 100% (5) | 40% (5) |
| graph | 60% (5) | 100% (5) | 100% (5) | 0% (5) | 20% (5) | 40% (5) | 60% (5) | 20% (5) |
| none | 40% (5) | 40% (5) | 20% (5) | 0% (5) | 20% (5) | 80% (5) | 40% (5) | 40% (5) |
| qa_notes | 60% (5) | 40% (5) | 80% (5) | 20% (5) | 60% (5) | 20% (5) | 40% (5) | 60% (5) |
