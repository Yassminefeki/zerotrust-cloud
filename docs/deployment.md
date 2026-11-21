# Deployment

This guide builds the full system on a cloud host and connects a remote client. The offline mode
(no VM) is in the README's quick start.

## 1. Requirements

| Machine | Requirement |
|---|---|
| Cloud host | x86-64 CPU with virtualisation enabled (VT-x/AMD-V), ≥ 16 GB RAM recommended (VMs use 7 GB, see `memory_mb` in [`policy.yaml`](../policy.yaml)), ≥ 40 GB free disk, Ubuntu 22.04 or 24.04 |
| Remote client | Linux with Firefox, `wireguard-tools`, `libnss3-tools`, `python3-yaml`, `openssl` |
| Network | both on the same LAN; mDNS (`.local`) allowed, or a `/etc/hosts` entry on the remote client |

## 2. Software on the cloud host

```bash
sudo apt update
sudo apt install -y git make python3-venv python3-pip pipx openssl netcat-openbsd
pipx install --include-deps ansible-core          # ansible-core >= 2.15 (checked by tests/host)
pipx ensurepath
```

Terraform ≥ 1.5 from HashiCorp's apt repository:

```bash
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor --yes -o /usr/share/keyrings/hashicorp.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y terraform
[ -f ~/.ssh/id_ed25519.pub ] || ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
```

KVM, libvirt, avahi, WireGuard tools, apt-cacher-ng and tcpdump are installed by `make host`.

## 3. Describe the machine (`env.yaml`)

```bash
git clone <repository-url> zerotrust-cloud && cd zerotrust-cloud
cp -n env.example.yaml env.yaml
ip -br link          # find the Wi-Fi (or Ethernet) interface name
hostname             # the mDNS name will be <hostname>.local
```

Edit `env.yaml`: `entry_point: <hostname>.local` (a name, never an IP — the generator refuses an IP)
and `wan_interface: <interface>`. Everything else can stay as in
[`env.example.yaml`](../env.example.yaml). Then:

```bash
make check     # expected output: policy OK
make test-0    # offline tests
```

## 4. Build, stage by stage

Every target is idempotent. Run each stage's test before the next.

```bash
make host       && make test-1     # cloud host: DNAT by interface name, hook, mDNS, apt cache (sudo)
make infra      && make test-2     # 5 networks + 6 VMs (Terraform; Ubuntu 24.04 cloud image, SHA-256 checked)
make ca         && make test-3     # step-ca
make firewall   && make test-4     # nftables on every VM, automatic rollback
make wireguard  && make test-5     # keys, gateway, exports
make certs      && make test-6     # VM certificates + renewal timers
make services   && make test-7     # PostgreSQL + mTLS services + revocation fetcher
                   make test-8     # confidentiality captures, drift, N×N matrix
                   make test-9     # actors × routes
                   make test-10    # the bank end to end
                   make test-11    # website, CSRF, Firefox bundles
make bot        && make test-12    # bot namespace, partner webhook
                   make test-13    # live attacks A1, A2, A5
```

Or at once: `make up && make test`. Full attack catalogue and evidence:

```bash
make attacks && make audit && make evidence     # reports copied, anonymised, to docs/evidence/
```

## 5. Connect the remote client

On the cloud host, `make wireguard client-certs` writes `build/export/remote-client/`: `wg0.conf` and
one folder per actor (`alice/`, `dev/`) with certificate, key, root, Firefox bundle (`.p12`) and its
password. Copy it over a trusted channel (scp, USB). On the remote client:

```bash
sudo apt install -y wireguard-tools libnss3-tools python3-yaml openssl
sudo install -m 600 wg0.conf /etc/wireguard/wg0.conf && sudo wg-quick up wg0
firefox -CreateProfile zt-alice
P=$(ls -d ~/snap/firefox/common/.mozilla/firefox/*.zt-alice 2>/dev/null || ls -d ~/.mozilla/firefox/*.zt-alice)
certutil -A -d sql:"$P" -n "ZT Bank root" -t "C,," -i zt-alice/root_ca.crt
pk12util -i zt-alice/alice.p12 -d sql:"$P" -W "$(cat zt-alice/p12-password.txt)" && rm -f zt-alice/p12-password.txt
firefox -P zt-alice --no-remote https://10.20.0.10:8443/
```

Remote attack suite: `python3 remote-client/attack.py --cloud-host <cloud host address>` — see
[`remote-client/README.md`](../remote-client/README.md).

## 6. Day-2 operations

| Task | Command |
|---|---|
| certificates after > 24 h off | `make certs client-certs services`, then re-export to the remote client |
| revoke a person or a VM | `make revoke ACTOR=alice` / `make revoke NODE=service-a`, then `make client-certs` / `make certs` |
| audit | `make audit SINCE="2 hours ago"` |
| live view | `make infra-live` (browser map at http://127.0.0.1:8099), `make dashboard`, `make infra-view` |
| rebuild VMs | `make recreate-vms` |
| tear down | `make destroy` (keeps host preparation and secrets), `make clean` (removes `build/`) |

## 7. Production considerations (not implemented)

This is a single-laptop lab. A production deployment would need: redundant gateways and services
([high-availability.md](high-availability.md)), an offline root CA and an HSM-backed intermediate
([ca.md](ca.md)), managed backups for the database ([database.md](database.md)), a host firewall on the
hypervisor ([cloud-host.md](cloud-host.md)), and a secrets vault instead of `ansible/.secrets/`.

## Related documents

[architecture.md](architecture.md) · [testing.md](testing.md) · [security.md](security.md) ·
[03-reproduire-pas-a-pas.md](03-reproduire-pas-a-pas.md) (FR, step by step) · [22-depannage.md](22-depannage.md) (FR, troubleshooting)
