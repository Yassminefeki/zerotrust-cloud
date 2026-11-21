# High availability

## Current state

The system runs one instance of every role on one laptop. Availability is explicitly not a goal of
this project ([THREAT-MODEL.md](THREAT-MODEL.md), residual risk 6); the design favours failing closed.

| Component | Instances | If it fails | Detection | Recovery time |
|---|---|---|---|---|
| Cloud host | 1 | everything stops | — | TODO[measure]: time `make up` from VMs off |
| Gateway | 1 | no tunnel, no partner traffic | `make test-5`, `infra-view.py wg` | `virsh start gateway` |
| Frontend | 1 | no website, no partner API | `make test-7` | systemd restart / `make services` |
| Service-a, service-b | 1 each | 502 at the frontend | frontend journal | systemd restart / `make services` |
| Database | 1 | 5xx everywhere | `make test-7` | restart; restore from `pg_dump` ([database.md](database.md)) |
| CA | 1 | no enrolment/renewal; after 24 h without CRL refresh every service answers 503 | `make audit` | restart; [ca.md](ca.md) |

## Fail-closed behaviours

- missing or stale revocation list → every mTLS service refuses every request (503);
- expired certificate → the peer refuses the handshake;
- unreachable next hop → 502, nothing is cached or retried with weaker checks.

## What a highly available version would need

| Need | Approach | Status |
|---|---|---|
| more than one gateway | two gateways with the same WireGuard peers, keepalived/VRRP on wan | not implemented |
| stateless services scaled out | two frontends/service-a/service-b behind the gateway, allow-lists by identity (already address-independent except the source check) | not implemented |
| database replica | PostgreSQL streaming replication, same `pg_hba` certificate rule | not implemented |
| CA resilience | CRL validity long enough to cover CA maintenance (currently 24 h), offline root | partially (24 h CRL validity) |
| multi-host | VMs spread over several hypervisors | out of scope |

## When to revisit

When the system leaves a single laptop, or when a measured availability target exists
(TODO[measure]: define an SLO and measure recovery times above).

## Related documents

[architecture.md](architecture.md) · [deployment.md](deployment.md) · [revocation.md](revocation.md)
