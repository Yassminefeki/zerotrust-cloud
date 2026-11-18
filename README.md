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
```

## Host preparation (stage 1) — what `make host` changes on the i5

| Change | Why |
|---|---|
| installs qemu-kvm, libvirt, avahi-utils, libnss-mdns, apt-cacher-ng, wireguard-tools, tcpdump | VMs, `entry_point` over mDNS, packages for the isolated VMs, tests |
| stops + disables libvirt's `default` network (refuses if a VM uses it) | it uses 192.168.122.0/24, the range of `zt-wan` |
| `net.ipv4.ip_forward=1` in `/etc/sysctl.d/90-zerotrust.conf` | DNAT from the Wi-Fi to the gateway VM |
| avahi `allow-interfaces=<wan_interface>` | announce `entry_point` only on the client-facing interface, not on Docker/libvirt bridges |
| nftables table `inet zt_host` (own table, **never** `flush ruleset`, never default-drop) | DNAT `iifname "<wan_interface>" udp dport <wan_port>` → gateway; apt cache reachable only from `virbr-zt-mgmt` |
| `/etc/libvirt/hooks/network.d/zerotrust` | libvirt's NAT chain `LIBVIRT_FWI` rejects new inbound traffic; an accept in another table cannot override a reject, so the hook re-inserts the WireGuard accept at the top of libvirt's chain each time libvirt rebuilds it |
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
