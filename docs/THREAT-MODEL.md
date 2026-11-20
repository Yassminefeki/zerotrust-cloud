# ZT Bank — threat model

What we protect, from whom, how, how we know it holds, and what is **not** covered.
Every defence named here is generated from `policy.yaml` and proven by a live test; the attack
catalogue (`tests/attacks/catalogue.yaml`) links each attack to those tests, and
`make attacks` replays them and writes `build/reports/attacks.md`.

## 1. What is worth stealing

| Asset | Where | Why it matters |
|---|---|---|
| Customers' money (balances, transfers) | PostgreSQL on `database`, written only through `bank.*` functions | moving it is the attacker's goal |
| Customers' data (accounts, history) | same | privacy; also the map for fraud |
| Identities: client and workload keys | each VM's `/etc/zt/pki/cert.key`; actors' keys in `ansible/.secrets/pki` on the cloud host | a key = the right to speak as someone |
| The CA (intermediate key, provisioner password) | `ca` VM only | can mint any identity of the policy |
| WireGuard keys + pre-shared keys | gateway; `ansible/.secrets/wireguard` on the cloud host; the remote client | the way in |
| PayFlow's webhook secret | frontend (`/etc/zt/partners/payflow.key`, readable by the service only) and the cloud host | can credit accounts |
| The policy itself | the git repository | it *is* the security configuration |

## 2. Trust boundaries

```
 internet / Wi-Fi ─┬─ UDP 51820 ──► gateway (WireGuard) ──► tunnel ──► frontend :8443 (website, mTLS)
                   └─ TCP 8444 ───► gateway (DNAT+SNAT) ─────────────► frontend :8444 (partner API, mTLS)
 frontend ──mTLS──► service-a ──mTLS──► service-b ──TLS 1.3 + client cert──► PostgreSQL
 every VM ──► CA (enrolment/renewal) and apt cache, on mgmt only; SSH only from the cloud host
```

Each arrow is the **only** way across; everything else is dropped silently and logged, on every
VM (not just at the edge). A packet that crosses a boundary must pass three locks: the network
(nftables), the transport (WireGuard outside, TLS 1.3 inside) and the identity (a 24 h SPIFFE
certificate from our CA *and* on the receiver's allow-list, then the route's role check).

## 3. Attackers and attacks

| | Attacker | Attack | Stopped by | Proven by |
|---|---|---|---|---|
| A1 | thief of Alice's laptop | uses her certificate from elsewhere | revocation (CRL every 60 s, fail-closed), CA refuses renewal, device binding (bot), 24 h / 1 h lifetimes | `make attack A=1`, remote B6 |
| A2 | root on the frontend | pivots to the DB, the ledger, the CA | per-VM firewall, per-service allow-lists, no foreign key on the VM, DB functions + append-only | `make attack A=2` |
| A3 | a VPN client gone hostile | lateral movement, spoofing another client | gateway forwards tunnel → website only; cryptokey routing (/32 per key) | `make attack A=3`, remote B3 |
| A4 | forger | own-CA, expired, missing, other-identity certificates | pinned root, TLS 1.3, SPIFFE allow-lists, CA issuance policy | `make attack A=4`, remote B2 |
| A5 | anyone on the Wi-Fi / in the tunnel | port scans | default drop, silent; only 51820/udp and 8444/tcp published | `make attack A=5`, remote B1 |
| A6 | holder of a WireGuard private key without the PSK, or a random key | joins the tunnel | WireGuard: no answer without a valid key **and** PSK | `make attack A=6` |
| A7 | a genuine customer | IDOR, forged identity headers, other roles' routes | identity from the certificate only, routes per role, RLS, 404 for others' accounts | `make attack A=7`, remote B4 |
| A8 | a malicious web page in Alice's browser | CSRF transfer | JSON-only POST (415) + same-origin check (403), never forwarded | `make attack A=8`, remote B4 |
| A9 | internet attacker | forged / replayed payment notification | partner mTLS identity, HMAC over ts.nonce.body, ±300 s, nonce once, reference once | `make attack A=9`, remote B5 |
| A10 | flooding client | requests / connection bursts | per-identity token bucket (429), per-peer conn limit at the gateway | `make attack A=10` |
| A11 | eavesdropper | captures traffic, offers TLS 1.2 / plaintext | TLS 1.3 everywhere incl. PostgreSQL; plaintext refused | `make attack A=11` |

## 4. Revocation, precisely

* `make revoke ACTOR=<a>` / `NODE=<vm>`: the serial is read from the current certificate, a one-time
  revocation token is minted **on the CA** (the provisioner password never leaves it), the CA
  revokes and regenerates its CRL at once, then every mTLS service fetches it immediately.
* `zt-crl` (every 60 s, systemd timer, root, `ProtectSystem=strict`, writes only `/etc/zt/pki`)
  downloads the CRL over TLS 1.3 pinned to our root, **verifies its signature** against our chain,
  refuses a CRL from the future and a CRL whose number goes **down** (rollback), then publishes the
  serials. `zt-mtls` checks the caller's serial before anything else, and also the serial of every
  upstream it calls.
* **Fail-closed:** no list, an unreadable list, or a list past the CRL's next update (24 h) → every
  request gets 503. Blocking the CA can therefore deny service, never bypass a revocation.
* Why not OpenSSL's built-in CRL check: step-ca's CRL carries an Issuing Distribution Point and our
  certificates carry no CRL Distribution Point, so OpenSSL rejects it ("different CRL scope").

## 5. Residual risks (honest list)

1. **A compromised frontend can act as any customer.** The frontend is the one that turns a
   customer's certificate into "customer = alice" for service-a. Root on the frontend can therefore
   call service-a as any customer — within the customer routes, the per-transfer and daily limits,
   and every such call is logged by service-a as coming from the frontend's identity. It cannot reach the ledger or the
   database, cannot mint certificates, and holds no other key (A2 tests). Mitigation beyond this
   project: end-to-end signed requests (the customer's key signs the transfer and service-a checks
   it), or token exchange so the inner services see the user's own credential.
2. **The cloud host is the root of everything.** It holds the actors' keys, the WireGuard keys, the
   PayFlow secret and SSH access to every VM; it is the hypervisor. Whoever owns it owns the bank.
   Its own services on the Wi-Fi (e.g. its SSH) are outside the bank's policy: B1 lists them.
   Mitigations: full-disk encryption, a hardware token for SSH, keys in a vault/HSM.
3. **The CA VM.** Its root and intermediate keys are on its disk (encrypted, with the password
   on the same VM). Compromise = any identity of the policy can be minted. Mitigations: take the
   root key offline after `make ca`, HSM / KMS for the intermediate; short lifetimes (already 24 h)
   bound how long minted certificates live once the CA is rebuilt.
4. **Revocation latency ≤ ~60 s** (timer) — immediate when revoked through `make revoke`. A stolen
   certificate also dies on its own within 24 h (1 h for the bot).
5. **PostgreSQL does not check the CRL.** Its only client is service-b, pinned by identity and
   source address; revoking service-b is handled by re-enrolling it (`make revoke NODE=service-b`
   then `make certs`), and service-a stops talking to the revoked service-b at once.
6. **Availability is not the goal.** One VM per role, no redundancy; a flood can still saturate the
   Wi-Fi or the laptop. Rate limits protect the bank's logic, not the link.
7. **TLS and WireGuard are not post-quantum here** (X25519 / P-256): recorded traffic could be
   decrypted by a future quantum computer. WireGuard's PSK adds a symmetric layer to the tunnel.
8. **The remote client is out of scope**: its OS, browser and the person using it. A malware on it
   acts as Alice; revocation and short lifetimes are the answer.
9. **Supply chain**: packages from Ubuntu through the apt cache, step-ca and Python from upstream;
   checked by signatures/checksums, not audited.

## 6. Detection

`make audit` gathers, read-only: every identity's requests; every refusal with its reason and the
real identity (route, CSRF, revoked, rate limit, TLS handshake); the CRL each service enforces;
certificate expiry; the nftables drops of every VM; the bank's own audit table and the ledger
balance; and the latest attack reports (cloud host and remote client). It exits non-zero on any
finding (stale CRL, services on different CRLs, unbalanced ledger, an attack not defended).
