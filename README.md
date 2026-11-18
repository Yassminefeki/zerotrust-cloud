# zerotrust-cloud

Cloud side (i5) of a zero-trust mini-cloud: 6 KVM/libvirt VMs where only the
declared caller reaches each service, every hop is encrypted (WireGuard, then
mTLS with TLS 1.3), and the "who talks to whom" rule is written once in
`policy.yaml`, generated into enforcement, and tested.

> Status: **stage 0** (policy + generator + offline tests). The full README
> (architecture diagram, operations, troubleshooting) is written in stage 8.

## Two files, two jobs

| File | Versioned | Contains |
|---|---|---|
| `policy.yaml` | yes | networks, VMs and their IPs, services, allowed flows, PKI and WireGuard peers. Network-independent. |
| `env.yaml` | **no** (gitignored) | what depends on *this* machine: `entry_point` (a hostname, never an IP), `wan_interface`, `wan_port`, libvirt pool, SSH user/key. Copy it from `env.example.yaml`. |

Moving the i5 to another Wi-Fi? Nothing changes. Different interface name
(e.g. Ethernet)? Change `wan_interface` in `env.yaml` and re-run `make up`:
only the host DNAT and the exported client template change; every VM ruleset
stays byte-identical (this is tested).

## The generator

`tools/gen_rules.py` reads both files and writes `build/` (gitignored):

- `nodes/<vm>/nftables.conf`: default **drop** on input/forward/output, drops logged, rules on every VM
- `nodes/<vm>/mtls.json`: SPIFFE identity, the IDs allowed to call each service, expected ID of each upstream
- `nodes/database/pg_hba.conf`, `pg_ident.conf`: `hostssl ... cert clientcert=verify-full`, service-b only
- `host/nftables-zt.conf`: DNAT `iifname "<wan_interface>" udp dport <wan_port>` to the gateway
- `wireguard/*.j2`: server and client configs (keys are injected by Ansible, never committed)
- `terraform.tfvars.json`, `inventory.yml`: so Terraform and Ansible never repeat an IP
- `matrix.json`: every source × every listening port, with the expected verdict (the drift test)

It refuses: an IP as `entry_point`, infra flows outside mgmt, business flows on
mgmt, IPs outside their network, duplicate IPs, flows between VMs that share
no network (VMs are never routed; only the gateway forwards, and only
tunnel → frontend:8443).

## Quick start (so far)

```bash
cp env.example.yaml env.yaml   # set wan_interface (ip -br link)
make test-0                    # offline tests
make gen                       # writes build/
```
