## Accuracy by memory mode

| Mode | n | Accuracy (95% CI) | Steps | Input tok | Cost | Sec | Used recall | No submit | Valid citations |
|---|---|---|---|---|---|---|---|---|---|
| full | 186 | 46.8% (39.8%–53.8%) | 3.8 | 78111 | $0.00 | 25 | 0.0% | 0.0% | 89.8% |
| graph | 186 | 48.9% (41.9%–55.9%) | 9.6 | 39277 | $0.00 | 55 | 86.6% | 8.1% | 83.3% |
| none | 186 | 38.2% (31.2%–45.2%) | 10.1 | 35995 | $0.00 | 45 | 0.0% | 6.5% | 91.4% |

## Paired comparison against `none`

| Mode | Pairs | Difference (95% CI) | Only baseline right | Only this right | McNemar p |
|---|---|---|---|---|---|
| full | 186 | +8.6% (+0.5% to +16.1%) | 21 | 37 | 0.048 |
| graph | 186 | +10.8% (+2.7% to +18.8%) | 20 | 40 | 0.013 |

Call a difference real only if its CI excludes 0.

## Early vs late questions in each incident

Memory can only help questions that come after others in the same incident.

| Mode | Early half | Late half |
|---|---|---|
| full | 47.4% (n=97) | 46.1% (n=89) |
| graph | 45.4% (n=97) | 52.8% (n=89) |
| none | 42.3% (n=97) | 33.7% (n=89) |

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

## Accuracy by incident

| Mode | #5 | #34 | #38 | #39 | #55 | #134 | #166 | #322 |
|---|---|---|---|---|---|---|---|---|
| full | 36% (25) | 40% (25) | 27% (11) | 36% (25) | 40% (25) | 64% (25) | 60% (25) | 60% (25) |
| graph | 40% (25) | 60% (25) | 73% (11) | 48% (25) | 16% (25) | 76% (25) | 32% (25) | 60% (25) |
| none | 32% (25) | 40% (25) | 36% (11) | 36% (25) | 16% (25) | 56% (25) | 40% (25) | 48% (25) |
