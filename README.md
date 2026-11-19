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
cp env.example.yaml env.yaml   # set wan_interface (ip -br link) and entry_point (<hostname>.local)
make test-0                    # stage 0: offline tests
make host                      # stage 1: prepare the i5 (sudo password asked once)
make test-1                    # stage 1: preflight tests
make infra                     # stage 2: networks + 6 VMs (terraform), waits for cloud-init
make test-2                    # stage 2: networks, IPs, routes, isolation
ssh -F build/ssh_config frontend   # SSH to any VM over mgmt
make destroy                   # remove VMs/networks (host prep stays)
make ca                        # stage 3: step-ca on the CA VM
make test-3                    # stage 3: CA tests (issuance + refusals)
make firewall                  # stage 4: nftables default-drop on every VM
make test-4                    # stage 4: live rulesets + NxN TCP probes
```

## Host preparation (stage 1) — what `make host` changes on the i5

| Change | Why |
|---|---|
| installs qemu-kvm, libvirt, avahi-utils, libnss-mdns, apt-cacher-ng, wireguard-tools, tcpdump | VMs, `entry_point` over mDNS, packages for the isolated VMs, tests |
| stops + disables libvirt's `default` network (refuses if a VM uses it) | it uses 192.168.122.0/24, the range of `zt-wan` |
| `net.ipv4.ip_forward=1` in `/etc/sysctl.d/90-zerotrust.conf` | DNAT from the Wi-Fi to the gateway VM |
| avahi `allow-interfaces=<wan_interface>` | announce `entry_point` only on the client-facing interface, not on Docker/libvirt bridges |
| nftables table `inet zt_host` (own table, **never** `flush ruleset`, never default-drop) | DNAT `iifname "<wan_interface>" udp dport <wan_port>` → gateway; apt cache reachable only from `virbr-zt-mgmt` |
| `/etc/libvirt/hooks/network.d/zerotrust` (+ libvirtd drop-in) | libvirt's NAT chain `LIBVIRT_FWI` rejects new inbound traffic, and an accept in another table cannot override a reject. libvirt rebuilds that chain at will, so the single WireGuard accept is placed in `FORWARD` **before the jump** to `LIBVIRT_FWI` (libvirt never reorders that jump). Re-applied at boot, on network start and on libvirtd start |
| `zerotrust-host.service` | re-applies both at boot, after libvirtd and docker |

Docker coexists: its rules are not touched (its FORWARD policy only affects its own bridges).
Undo: `sudo systemctl disable --now zerotrust-host` and `sudo rm /etc/libvirt/hooks/network.d/zerotrust`.

## Networks and VMs (stage 2)

`terraform/` reads only `build/terraform.tfvars.json`. Provider: `dmacvicar/libvirt ~> 0.8.3`
(the 0.9 line is a rewrite with a still-moving schema).

| libvirt network | mode | host address | role |
|---|---|---|---|
| zt-wan (virbr-zt-wan) | nat | 192.168.122.1 | only the gateway; target of the DNAT |
| zt-dmz / zt-app / zt-data | isolated (`none`) | **none** (pure L2) | data planes, the host cannot reach them |
| zt-mgmt (virbr-zt-mgmt) | isolated | 10.50.0.1 | SSH/Ansible, step-ca enrolment, apt cache |

No DHCP and no DNS on any network. Each VM gets static addresses from cloud-init
(netplan matched by MAC, NICs renamed `wan0 dmz0 app0 data0 mgmt0`), IPv6 off,
`rp_filter=1`, redirects off, `ip_forward=1` only on the gateway. Only two routes
exist in the whole cloud: the gateway's default route via the libvirt NAT and the
frontend's route back to the tunnel via the gateway.

## Internal CA (stage 3)

step-ca runs on the CA VM, as an unprivileged `step` user under a hardened systemd unit,
listening **only** on its mgmt address (`10.50.0.10:9000`), **TLS 1.3 only**.

- Packages: downloaded once on the i5 (`build/artifacts/`, VMs have no internet), override
  the URLs in `env.yaml` (`step_cli_deb_url`, `step_ca_deb_url`) to pin a version.
- Secrets: the key password and the JWK provisioner password are random, generated by
  Ansible into `ansible/.secrets/` (0600, gitignored) and copied 0400 to the CA.
- Lifetime: `defaultTLSCertDuration = maxTLSCertDuration = 24h` (from `policy.yaml: cert.lifetime`);
  renewal over mTLS with the current certificate, never after expiry.
- **Issuance policy** (`build/pki/pki.json`, generated from `policy.yaml`): the CA itself refuses
  any URI outside `spiffe://cloud.local/…`, any name that is not a declared identity, any IP
  that is not a declared data-plane address (mgmt can never be certified), and any lifetime > 24h.
- Trust anchor: `build/pki/root_ca.crt` + `root_ca.fingerprint` (checked against the CA by the tests).

Identities (SPIFFE ID → SANs) exist only for nodes that take part in an mTLS flow
(frontend, service-a, service-b, database) and the tunnel clients (`client/i7`, `client/test-peer`).

## Firewall on every VM (stage 4)

Each VM loads `build/nodes/<vm>/nftables.conf` (generated from `policy.yaml`): one table
`inet zt`, **policy drop** on input, forward and output, conntrack for replies, and a
rate-limited `log` before every drop (`journalctl -k | grep zt-drop-`). A flow is open only
if both ends allow it: the source's output chain and the destination's input chain.

Anti lock-out: SSH from the i5 over mgmt is part of the policy (`infra: admin-ssh`, checked
by the unit tests). On top of that, `zt-nft-apply` saves the live ruleset and arms a 120 s
systemd timer that restores it, then loads the new rules; Ansible opens a *fresh* SSH
connection and only then disarms the timer. A ruleset that cuts SSH undoes itself.

Tests probe real TCP connections for every source x destination x port of
`build/matrix.json`: allowed = handshake or RST (nothing listening yet), denied = timeout
or no route. The i5 has SSH only: it cannot reach the CA, and that is tested too.
