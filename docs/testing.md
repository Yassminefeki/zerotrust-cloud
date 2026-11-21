# Testing

## Two levels

| Level | Location | Needs | Command |
|---|---|---|---|
| Offline | [`tests/unit/`](../tests/unit/) | Python 3 only; PostgreSQL, Chromium (Playwright) and NSS tools unlock more tests | `make test-0` |
| Live | [`tests/host/`](../tests/host/), [`infra/`](../tests/infra/), [`ca/`](../tests/ca/), [`firewall/`](../tests/firewall/), [`wireguard/`](../tests/wireguard/), [`pki/`](../tests/pki/), [`services/`](../tests/services/), [`final/`](../tests/final/), [`actors/`](../tests/actors/), [`bank/`](../tests/bank/), [`web/`](../tests/web/), [`edge/`](../tests/edge/), [`attacks/`](../tests/attacks/) | the running VMs | `make test-1` … `make test-13`, `make test` |
| Attack catalogue | [`tests/attacks/catalogue.yaml`](../tests/attacks/catalogue.yaml) | the running VMs | `make attacks` |
| Remote client | [`remote-client/attack.py`](../remote-client/attack.py) | the second machine | `python3 remote-client/attack.py` |

## Stage to test map

| Stage | Command | Folder |
|---|---|---|
| 0 policy and generator | `make test-0` | `tests/unit/` |
| 1 cloud host | `make test-1` | `tests/host/` |
| 2 networks and VMs | `make test-2` | `tests/infra/` |
| 3 CA | `make test-3` | `tests/ca/` |
| 4 firewalls | `make test-4` | `tests/firewall/` |
| 5 WireGuard | `make test-5` | `tests/wireguard/` |
| 6 certificates | `make test-6` | `tests/pki/` |
| 7 services | `make test-7` | `tests/services/` |
| 8 confidentiality and drift | `make test-8` | `tests/final/` |
| 9 actors and routes | `make test-9` | `tests/actors/` |
| 10 bank | `make test-10` | `tests/bank/` |
| 11 website | `make test-11` | `tests/web/` |
| 12 bot and partner | `make test-12` | `tests/edge/` |
| 13 live attacks | `make test-13` | `tests/attacks/` |

## Principles

- every refusal is tested as much as every success;
- tests that prove "nothing in clear" also capture a deliberate clear-text control packet;
- the live configuration is compared with a fresh generation (drift);
- the hostile test peer routes every network into the tunnel, so a refusal proves the gateway blocks;
- no test prints a key: secret checks compare booleans;
- the repository is scanned for personal data on every offline run.

## Results

| Run | Result | Evidence |
|---|---|---|
| Offline suite, development container (Python 3, PostgreSQL 16, Chromium available) | see file | [evidence/unit-tests.txt](evidence/unit-tests.txt) |
| Live N×N matrix (`make test-8`) | 194 probes, 0 deviations from the policy | [evidence/drift-summary.md](evidence/drift-summary.md) |
| Remote client B1–B6 | 6/6 DEFENDED | [evidence/remote-client-report.json](evidence/remote-client-report.json) |
| Attack catalogue A1–A11 | TODO[measure]: `make attacks && make evidence` | written to `docs/evidence/attacks.md` |
| Full live suite `make test` | TODO[measure]: `make test 2>&1 \| tee build/reports/live-tests.txt`, then copy it to `docs/evidence/` | — |

## Related documents

[security.md](security.md) · [deployment.md](deployment.md) · [20-tests.md](20-tests.md) (FR)
