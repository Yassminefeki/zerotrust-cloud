# Drift report summary

Source: [`drift-report.json`](drift-report.json) (`make test-8`, live N×N probe of the policy matrix).

- probes: 194
- sources: 8, destinations: 7
- probes whose result differs from the policy: 0

| Expected | Observed | Probes |
|---|---|---|
| allow | reached | 21 |
| deny | err:101 | 51 |
| deny | timeout | 122 |
