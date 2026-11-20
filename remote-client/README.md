# Remote client — attack suite

For the **remote client** (the second laptop on the same Wi-Fi). Nothing here installs anything
or keeps running; B3 changes your own WireGuard routes and puts them back.

## Once

```bash
git clone <the repo> && cd zerotrust-cloud      # or: git pull
sudo apt install -y python3-yaml openssl        # usually already there on Ubuntu
```

You need the tunnel (`sudo wg-quick up wg0`) and the folders the cloud host gave you:
`~/Downloads/zt-alice/` (and `~/Downloads/zt-dev/`) with `client.crt`, `client.key`, `root_ca.crt`.
Certificates live 24 h: ask for a fresh export if they expired. Elsewhere? `--alice DIR --dev DIR`.

## Run

```bash
python3 remote-client/attack.py --list
python3 remote-client/attack.py --cloud-host <cloud host Wi-Fi address>   # B1 B2 B4 B5 (B1 scans 65535 ports)
python3 remote-client/attack.py --quick         # B1 scans only 1-1024 + the bank's ports
sudo python3 remote-client/attack.py B3         # lateral movement + address spoofing (needs root)
```

| | What you try | Expected |
|---|---|---|
| B1 | scan every TCP port of the cloud host from the Wi-Fi (outside the tunnel), then ask each open port for its certificate | only the partner API 8444 presents the bank's certificate; other open ports are the cloud host's own services, listed (WireGuard is UDP and never answers a scan) |
| B2 | the website with no certificate, with self-signed certificates claiming Alice / Dev, and TLS 1.2 | handshake refused every time |
| B3 | route **every** bank network into your tunnel and knock on the inside (DB, services, CA, SSH); then spoof another VPN client's address | silence: the gateway alone stops you |
| B4 | as Alice: read Bob's history, pay from Bob's account, forge identity headers, staff/bot routes, cross-site POSTs; as Dev: customer data | 404 / 403 / 415, your own accounts only |
| B5 | forged payment notifications to the partner API from the internet: no certificate, self-signed "PayFlow", Alice's real certificate | refused, Alice's balance unchanged |
| B6 | the stolen-laptop drill: keeps calling the bank as Alice while the cloud host revokes her | refused (403 "revoked") within the minute |

Each probe prints `REFUSED (as expected)` or `BREACH`; the summary gives DEFENDED / BREACH /
SKIPPED per check, and the exit code is 1 on any breach.

## The revocation demo (B6)

1. Here: open the bank in Firefox (profile `zt-alice`): it works. Then
   `python3 remote-client/attack.py B6` (it waits up to 10 minutes).
2. On the cloud host: `make revoke ACTOR=alice REASON="stolen laptop"`.
3. Here: B6 reports the refusal and the delay; reload Firefox: refused too.
4. On the cloud host: `make client-certs` issues Alice a new key and certificate in
   `build/export/remote-client/alice/`: copy it here and import the new `alice.p12` in Firefox.

## Report

`remote-client-report.json` (in the current folder, git-ignored): send it to the cloud host, into
`build/reports/`, and `make audit` includes it.
