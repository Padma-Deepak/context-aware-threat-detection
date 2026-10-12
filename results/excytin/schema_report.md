## Accuracy by memory mode

| Mode | n | Accuracy (95% CI) | Steps | Input tok | Cost | Sec | Used recall | No submit | Valid citations | SQL errors |
|---|---|---|---|---|---|---|---|---|---|---|
| full | 186 | 46.8% (39.8%–53.8%) | 3.8 | 78111 | $0.00 | 25 | 0.0% | 0.0% | 89.8% | 10.1% |
| full+schema | 186 | 47.8% (40.8%–54.8%) | 3.7 | 106466 | $0.00 | 31 | 0.0% | 0.0% | 90.9% | 14.2% |
| graph | 186 | 48.9% (41.9%–55.9%) | 9.6 | 39277 | $0.00 | 55 | 86.6% | 8.1% | 83.3% | 31.1% |
| graph+schema | 186 | 36.6% (29.6%–43.5%) | 8.9 | 97590 | $0.00 | 46 | 93.0% | 12.4% | 83.9% | 22.4% |
| none | 186 | 38.2% (31.2%–45.2%) | 10.1 | 35995 | $0.00 | 45 | 0.0% | 6.5% | 91.4% | 26.6% |
| none+schema | 186 | 38.2% (31.2%–44.6%) | 9.9 | 98375 | $0.00 | 57 | 0.0% | 1.6% | 89.8% | 21.3% |

## Paired comparison against `none`

| Mode | Pairs | Difference (95% CI) | Only baseline right | Only this right | McNemar p |
|---|---|---|---|---|---|
| full | 186 | +8.6% (+0.5% to +16.1%) | 21 | 37 | 0.048 |
| graph | 186 | +10.8% (+2.7% to +18.8%) | 20 | 40 | 0.013 |
| none+schema | 186 | +0.0% (-7.0% to +7.0%) | 20 | 20 | 1.000 |
| full+schema | 186 | +9.7% (+1.1% to +18.3%) | 24 | 42 | 0.036 |
| graph+schema | 186 | -1.6% (-9.1% to +5.9%) | 27 | 24 | 0.780 |

Call a difference real only if its CI excludes 0.

## Effect of giving the agent the schema up front

Same questions, same mode, with vs without every table's exact column names.

| Mode | Pairs | Change with schema (95% CI) | Only without right | Only with right | McNemar p |
|---|---|---|---|---|---|
| none | 186 | +0.0% (-7.0% to +7.0%) | 20 | 20 | 1.000 |
| full | 186 | +1.1% (-5.9% to +8.6%) | 24 | 26 | 0.888 |
| graph | 186 | -12.4% (-19.9% to -5.4%) | 37 | 14 | 0.002 |

## Early vs late questions in each incident

Memory can only help questions that come after others in the same incident.

| Mode | Early half | Late half |
|---|---|---|
| full | 47.4% (n=97) | 46.1% (n=89) |
| full+schema | 46.4% (n=97) | 49.4% (n=89) |
| graph | 45.4% (n=97) | 52.8% (n=89) |
| graph+schema | 36.1% (n=97) | 37.1% (n=89) |
| none | 42.3% (n=97) | 33.7% (n=89) |
| none+schema | 40.2% (n=97) | 36.0% (n=89) |

## Conformal escalation (random 50/50 question splits)

| Mode | Score | Target error | Auto-answered | Error on auto-answered | Splits over target |
|---|---|---|---|---|---|
| full | confidence | 5.0% | 0.0% | 0.0% | 0.0% |
| full | confidence | 10.0% | 0.0% | 0.0% | 0.0% |
| full | confidence | 20.0% | 0.0% | 0.0% | 0.0% |
| full+schema | confidence | 5.0% | 0.0% | 0.0% | 0.0% |
| full+schema | confidence | 10.0% | 0.0% | 0.0% | 0.0% |
| full+schema | confidence | 20.0% | 0.0% | 0.0% | 0.0% |
| graph | confidence | 5.0% | 0.0% | 0.0% | 0.0% |
| graph | confidence | 10.0% | 0.0% | 0.0% | 0.0% |
| graph | confidence | 20.0% | 0.0% | 0.0% | 0.0% |
| graph+schema | confidence | 5.0% | 0.0% | 0.0% | 0.0% |
| graph+schema | confidence | 10.0% | 0.0% | 0.0% | 0.0% |
| graph+schema | confidence | 20.0% | 0.0% | 0.0% | 0.0% |
| none | confidence | 5.0% | 0.0% | 0.0% | 0.0% |
| none | confidence | 10.0% | 0.0% | 0.0% | 0.0% |
| none | confidence | 20.0% | 0.0% | 0.0% | 0.0% |
| none+schema | confidence | 5.0% | 0.0% | 0.0% | 0.0% |
| none+schema | confidence | 10.0% | 0.0% | 0.0% | 0.0% |
| none+schema | confidence | 20.0% | 0.0% | 0.0% | 0.0% |

## Accuracy by incident

| Mode | #5 | #34 | #38 | #39 | #55 | #134 | #166 | #322 |
|---|---|---|---|---|---|---|---|---|
| full | 36% (25) | 40% (25) | 27% (11) | 36% (25) | 40% (25) | 64% (25) | 60% (25) | 60% (25) |
| full+schema | 36% (25) | 48% (25) | 73% (11) | 44% (25) | 28% (25) | 68% (25) | 52% (25) | 48% (25) |
| graph | 40% (25) | 60% (25) | 73% (11) | 48% (25) | 16% (25) | 76% (25) | 32% (25) | 60% (25) |
| graph+schema | 36% (25) | 32% (25) | 36% (11) | 20% (25) | 24% (25) | 60% (25) | 40% (25) | 44% (25) |
| none | 32% (25) | 40% (25) | 36% (11) | 36% (25) | 16% (25) | 56% (25) | 40% (25) | 48% (25) |
| none+schema | 40% (25) | 52% (25) | 45% (11) | 24% (25) | 32% (25) | 44% (25) | 32% (25) | 40% (25) |
