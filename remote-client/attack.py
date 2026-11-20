#!/usr/bin/env python3
"""ZT Bank — attacks played from the REMOTE CLIENT (the friend's laptop on the Wi-Fi).

The cloud host plays A1-A11 against itself (`make attacks`). This script plays what only a real
second machine can: an outsider on the same Wi-Fi, and a VPN client that turns hostile.

    cd zerotrust-cloud && git pull
    python3 remote-client/attack.py --list
    python3 remote-client/attack.py                 # B1 B2 B4 B5 (no root needed)
    sudo python3 remote-client/attack.py B3         # B3 changes your WireGuard routes (restored after)
    python3 remote-client/attack.py B6              # while the cloud host runs `make revoke ACTOR=alice`

Everything is read from policy.yaml in this repository: no address is written here. You need
the WireGuard tunnel up (wg-quick up wg0) for B2-B4/B6, Alice's (and optionally Dev's) folder as
exported by the cloud host (client.crt, client.key, root_ca.crt), python3-yaml and openssl.

Each probe prints REFUSED (as expected) or BREACH. A report is written to
remote-client-report.json: send it back to the cloud host (build/reports/) for `make audit`.
Nothing here prints a key or a password.
"""
import argparse
import http.client
import json
import os
import pwd
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tests"))

try:
    import yaml
except ImportError:
    sys.exit("python3-yaml is missing: sudo apt install python3-yaml")

CHECKS = {
    "B1": "Outsider on the Wi-Fi scans the cloud host",
    "B2": "Forged identity at the website (through the tunnel)",
    "B3": "VPN client turns hostile: lateral movement and address spoofing (sudo)",
    "B4": "Alice oversteps: Bob's money, forged headers, other roles, cross-site requests",
    "B5": "Forged payment notification from the internet (partner API)",
    "B6": "Revocation watch: Alice's laptop is declared stolen",
}
DEFAULT = ["B1", "B2", "B4", "B5"]


# ------------------------------------------------------------------ context --
def home():
    """The invoking user's home, even under sudo (the certificates live there, not in /root)."""
    u = os.environ.get("SUDO_USER")
    return Path(pwd.getpwnam(u).pw_dir) if u else Path.home()


class Ctx:
    def __init__(self, a):
        p = yaml.safe_load((REPO / "policy.yaml").read_text())
        self.policy, self.td = p, p["trust_domain"]
        svc = p["services"]

        def addr(name):
            s = svc[name]
            return p["nodes"][s["node"]]["interfaces"][s["network"]], s["port"]

        self.web_ip, self.web_port = addr("https")
        self.partner_port = a.partner_port or svc["partner-api"]["port"]
        self.cloud_host = a.cloud_host
        self.iface = a.iface
        self.quick = a.quick
        self.minutes = a.minutes
        self.poll = getattr(a, "poll", 5)
        self.actors = {}
        for actor, d in (("alice", a.alice), ("dev", a.dev)):
            d = Path(d).expanduser() if d else home() / "Downloads" / f"zt-{actor}"
            if (d / "client.crt").exists() and (d / "client.key").exists():
                self.actors[actor] = d
        ca = [d / "root_ca.crt" for d in self.actors.values() if (d / "root_ca.crt").exists()]
        self.root = ca[0] if ca else None
        self.customers = {k: v.get("customer") for k, v in p["actors"].items() if v["role"] == "customer"}
        # every TCP service of the policy except the website: what a tunnel client must never reach
        self.inside = []
        for name, s in svc.items():
            if s.get("proto", "tcp") != "tcp" or name == "https":
                continue
            nodes = list(p["nodes"]) if s["node"] == "*" else [s["node"]]
            for n in nodes:
                ip = (p["networks"][s["network"]].get("host_ip") if n == "host"
                      else p["nodes"][n]["interfaces"].get(s["network"]))
                if ip and s["network"] != "wan":
                    self.inside.append((ip, s["port"], f"{name}@{n}"))
        self.inside += [(self.web_ip, 22, "ssh@frontend (website address)")]
        self.inside_ports = sorted({s["port"] for n, s in svc.items()
                                    if s.get("proto", "tcp") == "tcp" and n != "partner-api"})
        self.nets = [n["cidr"] for k, n in p["networks"].items() if k != "wan"]
        self.other_peer_ip = next(x["ip"] for x in p["wireguard"]["peers"] if x["name"] != "remote-client")

    def creds(self, actor):
        d = self.actors.get(actor)
        return (str(d / "client.crt"), str(d / "client.key")) if d else (None, None)


# ------------------------------------------------------------------ helpers --
class Result:
    def __init__(self, cid):
        self.id, self.title, self.probes, self.notes, self.skipped = cid, CHECKS[cid], [], [], None

    def probe(self, what, refused, detail):
        self.probes.append({"probe": what, "refused": bool(refused), "detail": detail})
        tag = "REFUSED (as expected)" if refused else "BREACH"
        print(f"   [{tag:21}] {what}\n   {'':23} -> {detail}")

    def note(self, text):
        self.notes.append(text)
        print(f"   [{'INFO':21}] {text}")

    def skip(self, why):
        self.skipped = why
        print(f"   [{'SKIPPED':21}] {why}")

    @property
    def verdict(self):
        if self.skipped and not self.probes:
            return "SKIPPED"
        return "DEFENDED" if all(p["refused"] for p in self.probes) else "BREACH"

    def as_dict(self):
        return {"id": self.id, "title": self.title, "verdict": self.verdict, "probes": self.probes,
                "notes": self.notes, "skipped": self.skipped}


def https(host, port, path, method="GET", cert=None, key=None, ca=None, body=None, headers=None,
          tls12=False, source=None, timeout=8):
    """One HTTPS request. {"status": int, "body": ...} or {"status": None, "error": "..."} if the
    connection or the handshake was refused. Never goes through a proxy."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    if ca:
        ctx.load_verify_locations(ca)
    else:
        ctx.verify_mode = ssl.CERT_NONE
    if tls12:
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if cert:
        ctx.load_cert_chain(cert, key)
    h = {"Accept": "application/json", **(headers or {})}
    data = None
    if body is not None:
        data = body if isinstance(body, (bytes, str)) else json.dumps(body)
        h.setdefault("Content-Type", "application/json")
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout,
                                       source_address=(source, 0) if source else None)
    try:
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        raw = r.read()
        try:
            b = json.loads(raw)
        except ValueError:
            b = raw[:120].decode(errors="replace")
        return {"status": r.status, "body": b}
    except (ssl.SSLError, OSError, http.client.HTTPException) as e:
        return {"status": None, "error": f"{type(e).__name__}: {str(e)[:120]}"}
    finally:
        conn.close()


def show(r):
    if r["status"] is None:
        return f"no answer / handshake refused ({r['error']})"
    b = r["body"]
    msg = b.get("reason") or b.get("error") if isinstance(b, dict) else b
    return f"HTTP {r['status']}: {msg}"


def tcp(ip, port, timeout=3, source=None):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        if source:
            s.bind((source, 0))
        s.connect((ip, port))
        return "open"
    except ConnectionRefusedError:
        return "refused (RST)"
    except (socket.timeout, TimeoutError):
        return "silent"
    except OSError as e:
        return f"error {e.errno}"
    finally:
        s.close()


def fake_cert(tmp, uri, cn):
    """Self-signed certificate claiming a real identity of the bank (what a forger can make)."""
    c, k = Path(tmp) / f"{cn}.crt", Path(tmp) / f"{cn}.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-subj", f"/CN={cn}", "-addext", f"subjectAltName=URI:{uri}",
                    "-addext", "extendedKeyUsage=clientAuth", "-days", "1", "-keyout", str(k), "-out", str(c)],
                   check=True, capture_output=True)
    return str(c), str(k)


def cert_state(crt):
    if not shutil.which("openssl"):
        return "unknown"
    r = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-checkend", "0"], capture_output=True)
    return "valid" if r.returncode == 0 else "expired"


def tunnel_up(ctx):
    return tcp(ctx.web_ip, ctx.web_port) == "open"


def need_alice(ctx, res):
    if "alice" not in ctx.actors:
        res.skip("Alice's folder not found (client.crt + client.key): --alice DIR")
        return False
    if cert_state(ctx.creds("alice")[0]) == "expired":
        res.skip("Alice's certificate has expired (24 h): ask the cloud host for a fresh export")
        return False
    if not tunnel_up(ctx):
        res.skip(f"the website {ctx.web_ip}:{ctx.web_port} does not answer: is the tunnel up (sudo wg-quick up wg0)?")
        return False
    r = https(ctx.web_ip, ctx.web_port, "/api/me", cert=ctx.creds("alice")[0], key=ctx.creds("alice")[1], ca=ctx.root)
    if r["status"] != 200:
        res.skip(f"Alice's own certificate is not accepted ({show(r)}); revoked? ask for a fresh export")
        return False
    return True


# ------------------------------------------------------------------- checks --
def b1(ctx, res):
    import asyncio
    from port_scan import raise_nofile, scan
    try:
        ip = socket.gethostbyname(ctx.cloud_host)
    except OSError:
        return res.skip(f"{ctx.cloud_host} does not resolve: --cloud-host <the cloud host's Wi-Fi address>")
    ports = list(range(1, 1025)) + ctx.inside_ports + [ctx.partner_port] if ctx.quick else list(range(1, 65536))
    ports = sorted(set(ports))
    print(f"   scanning {len(ports)} TCP ports of {ctx.cloud_host} ({ip}) from outside the tunnel...")
    t0 = time.time()
    v = asyncio.run(scan(ip, ports, 1.5, min(2000, raise_nofile() - 64)))
    open_ = sorted(p for p, s in v.items() if s == "open")
    res.note(f"{len(ports)} ports in {time.time() - t0:.0f} s; open: {open_ or 'none'}")
    for p in ctx.inside_ports:
        res.probe(f"bank-internal port {p}/tcp on the cloud host from the Wi-Fi", p not in open_,
                  "closed" if p not in open_ else "OPEN: an internal service is exposed to the Wi-Fi")
    res.note(f"partner API {ctx.partner_port}/tcp: " + ("published, mTLS-protected (B5)" if ctx.partner_port in open_
                                                         else "not reachable (port forwarding off?)"))
    others = [p for p in open_ if p not in ctx.inside_ports and p != ctx.partner_port]
    if others:
        res.note(f"other open ports {others}: the cloud host's OWN services (not the bank's); "
                 "review them in docs/THREAT-MODEL.md, 'the cloud host'")
    res.note("WireGuard (UDP 51820) is invisible to a scan: it never answers a packet without a valid key")


def b2(ctx, res):
    if not tunnel_up(ctx):
        return res.skip("the tunnel is down: sudo wg-quick up wg0")
    host, port = ctx.web_ip, ctx.web_port
    r = https(host, port, "/api/me", ca=ctx.root)
    res.probe("website with NO client certificate", r["status"] in (None, 401, 403), show(r))
    with tempfile.TemporaryDirectory() as tmp:
        alice_uri = f"spiffe://{ctx.td}/customer/alice"
        c, k = fake_cert(tmp, alice_uri, "customer-alice")
        r = https(host, port, "/api/accounts", cert=c, key=k, ca=ctx.root)
        res.probe(f"self-signed certificate claiming {alice_uri}", r["status"] in (None, 401, 403), show(r))
        c, k = fake_cert(tmp, f"spiffe://{ctx.td}/staff/dev", "staff-dev")
        r = https(host, port, "/api/status", cert=c, key=k, ca=ctx.root)
        res.probe("self-signed certificate claiming staff/dev", r["status"] in (None, 401, 403), show(r))
    if "alice" in ctx.actors:
        r = https(host, port, "/api/me", cert=ctx.creds("alice")[0], key=ctx.creds("alice")[1], ca=ctx.root, tls12=True)
        res.probe("Alice's real certificate but TLS 1.2 only (downgrade)", r["status"] is None, show(r))


def b3(ctx, res):
    if os.geteuid() != 0:
        return res.skip("needs root to change your own WireGuard routes: sudo python3 remote-client/attack.py B3")
    if not shutil.which("wg"):
        return res.skip("wg not installed")
    if not tunnel_up(ctx):
        return res.skip("the tunnel is down: sudo wg-quick up wg0")
    out = subprocess.run(["wg", "show", ctx.iface, "allowed-ips"], capture_output=True, text=True, check=True).stdout
    peer, saved = next(((l.split()[0], l.split()[1:]) for l in out.splitlines()
                        if f"{ctx.web_ip}/32" in l.split()[1:]), (None, None))
    if not peer:
        return res.skip(f"no peer of {ctx.iface} routes {ctx.web_ip}/32")
    res.note(f"routing EVERY bank network into the tunnel ({', '.join(ctx.nets)}): the gateway alone must stop us")
    added_routes, added_addr = [], False
    try:
        subprocess.run(["wg", "set", ctx.iface, "peer", peer, "allowed-ips", ",".join(saved + ctx.nets)], check=True)
        for n in ctx.nets:
            if subprocess.run(["ip", "route", "add", n, "dev", ctx.iface], capture_output=True).returncode == 0:
                added_routes.append(n)
        res.note(f"control: the website still answers -> {tcp(ctx.web_ip, ctx.web_port)}")
        with ThreadPoolExecutor(32) as ex:
            got = list(ex.map(lambda t: tcp(t[0], t[1]), ctx.inside))
        for (ip, port, what), v in zip(ctx.inside, got):
            res.probe(f"{what} {ip}:{port} through the tunnel", v not in ("open", "refused (RST)"), v)
        subprocess.run(["ip", "addr", "add", f"{ctx.other_peer_ip}/32", "dev", ctx.iface], check=True)
        added_addr = True
        v = tcp(ctx.web_ip, ctx.web_port, source=ctx.other_peer_ip)
        res.probe(f"spoofing another VPN client's address {ctx.other_peer_ip} toward the website",
                  v != "open", v)
    finally:
        if added_addr:
            subprocess.run(["ip", "addr", "del", f"{ctx.other_peer_ip}/32", "dev", ctx.iface], capture_output=True)
        for n in added_routes:
            subprocess.run(["ip", "route", "del", n, "dev", ctx.iface], capture_output=True)
        subprocess.run(["wg", "set", ctx.iface, "peer", peer, "allowed-ips", ",".join(saved)], check=True)
        res.note("your WireGuard routes are restored")


def b4(ctx, res):
    if not need_alice(ctx, res):
        return
    c, k = ctx.creds("alice")

    def call(method, path, body=None, headers=None, who=(c, k)):
        return https(ctx.web_ip, ctx.web_port, path, method, who[0], who[1], ctx.root, body,
                     {"Origin": f"https://{ctx.web_ip}:{ctx.web_port}", "Sec-Fetch-Site": "same-origin",
                      **(headers or {})} if method == "POST" else headers)

    mine = call("GET", "/api/accounts")
    own = [a["id"] for a in mine["body"].get("accounts", [])] if mine["status"] == 200 else []
    res.note(f"Alice's own accounts: {own}")
    others = [f"ZTB-{v.upper()}-01" for k_, v in ctx.customers.items() if k_ != "alice" and v]
    for acct in others:
        r = call("GET", f"/api/accounts/{acct}/transactions")
        res.probe(f"read {acct}'s history (IDOR)", r["status"] == 404, show(r))
        r = call("POST", "/api/transfers", {"from": acct, "to": own[0] if own else "ZTB-ALICE-01",
                                            "amount": "1.00", "idempotency_key": secrets.token_hex(8)})
        res.probe(f"transfer FROM {acct} to Alice", r["status"] in (403, 404), show(r))
    r = call("GET", "/api/accounts", headers={"X-ZT-Customer": "bob", "X-ZT-Role": "staff",
                                               "X-ZT-Actor": f"spiffe://{ctx.td}/customer/bob"})
    got = [a["id"] for a in r["body"].get("accounts", [])] if r["status"] == 200 else []
    res.probe("forged identity headers (X-ZT-Customer: bob ...)", got == own, f"still only {got}")
    for path, role in (("/api/status", "staff"), ("/api/statements", "bot"), ("/chain", "staff")):
        r = call("GET", path)
        res.probe(f"{role}-only route {path}", r["status"] in (403, 404), show(r))
    body = {"from": own[0] if own else "", "to": others[0] if others else "", "amount": "0.01"}
    r = https(ctx.web_ip, ctx.web_port, "/api/transfers", "POST", c, k, ctx.root,
              "from=x&to=y&amount=1", {"Content-Type": "application/x-www-form-urlencoded",
                                       "Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
    res.probe("cross-site FORM post (classic CSRF)", r["status"] in (403, 415), show(r))
    r = https(ctx.web_ip, ctx.web_port, "/api/transfers", "POST", c, k, ctx.root, body,
              {"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
    res.probe("cross-site JSON post (fetch from a malicious page)", r["status"] == 403, show(r))
    if "dev" in ctx.actors and cert_state(ctx.creds("dev")[0]) == "valid":
        r = call("GET", "/api/accounts", who=ctx.creds("dev"))
        res.probe("Dev (staff) reads customer accounts", r["status"] == 403, show(r))


def b5(ctx, res):
    host, port = ctx.cloud_host, ctx.partner_port
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return res.skip(f"{host} does not resolve: --cloud-host <the cloud host's Wi-Fi address>")
    if tcp(ip, port) != "open":
        return res.skip(f"{host}:{port} does not answer (partner port forwarding off?)")
    before = None
    if "alice" in ctx.actors and tunnel_up(ctx):
        r = https(ctx.web_ip, ctx.web_port, "/api/accounts", cert=ctx.creds("alice")[0], key=ctx.creds("alice")[1], ca=ctx.root)
        before = r["body"].get("accounts") if r["status"] == 200 else None
    payment = {"reference": f"PF-FORGED-{secrets.token_hex(4)}", "to": "ZTB-ALICE-01", "amount": "1000.00"}
    forged = {"X-ZT-Timestamp": str(int(time.time())), "X-ZT-Nonce": secrets.token_hex(16),
              "X-ZT-Signature": "v1=" + "0" * 64}
    r = https(host, port, "/webhook", "POST", body=payment, headers=forged, ca=ctx.root)
    res.probe("signed-looking webhook, NO client certificate", r["status"] in (None, 401, 403), show(r))
    with tempfile.TemporaryDirectory() as tmp:
        c, k = fake_cert(tmp, f"spiffe://{ctx.td}/partner/payflow", "partner-payflow")
        r = https(host, port, "/webhook", "POST", c, k, ctx.root, payment, forged)
        res.probe("self-signed certificate claiming PayFlow", r["status"] in (None, 401, 403), show(r))
    if "alice" in ctx.actors:
        r = https(host, port, "/webhook", "POST", *ctx.creds("alice"), ctx.root, payment, forged)
        res.probe("Alice's genuine certificate on the partner API", r["status"] in (401, 403), show(r))
    if before is not None:
        r = https(ctx.web_ip, ctx.web_port, "/api/accounts", cert=ctx.creds("alice")[0], key=ctx.creds("alice")[1], ca=ctx.root)
        res.probe("Alice's balance after the forged payments", r["body"].get("accounts") == before, "unchanged")


def b6(ctx, res):
    if not need_alice(ctx, res):
        return
    c, k = ctx.creds("alice")
    print("   Alice is in. Now, on the cloud host:  make revoke ACTOR=alice REASON='stolen laptop'")
    print(f"   polling every {ctx.poll:g} s for {ctx.minutes} min (Ctrl-C to stop); Firefox as Alice will be refused too")
    t0 = time.time()
    while time.time() - t0 < ctx.minutes * 60:
        r = https(ctx.web_ip, ctx.web_port, "/api/me", cert=c, key=k, ca=ctx.root)
        if r["status"] != 200:
            dt = time.time() - t0
            revoked = isinstance(r.get("body"), dict) and "revoked" in str(r["body"].get("reason", ""))
            res.probe(f"stolen copy of Alice's certificate, {dt:.0f} s after the start", revoked, show(r))
            return res.note("reload the bank in Firefox (profile zt-alice): the same refusal")
        time.sleep(ctx.poll)
    res.note(f"still accepted after {ctx.minutes} min: was `make revoke ACTOR=alice` run on the cloud host?")
    res.skip("no revocation observed")


RUN = {"B1": b1, "B2": b2, "B3": b3, "B4": b4, "B5": b5, "B6": b6}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("checks", nargs="*", help="B1..B6 (default: B1 B2 B4 B5)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--cloud-host", default="cloud-host.local", help="name or address of the cloud host on the Wi-Fi")
    ap.add_argument("--partner-port", type=int, default=0, help="published partner API port (default: from the policy)")
    ap.add_argument("--alice", help="folder with Alice's client.crt/client.key/root_ca.crt (default ~/Downloads/zt-alice)")
    ap.add_argument("--dev", help="folder with Dev's files (default ~/Downloads/zt-dev)")
    ap.add_argument("--iface", default="wg0")
    ap.add_argument("--quick", action="store_true", help="B1: ports 1-1024 + the bank's ports only")
    ap.add_argument("--minutes", type=float, default=10, help="B6: how long to wait for the revocation")
    ap.add_argument("--report", default="remote-client-report.json")
    a = ap.parse_args()
    if a.list:
        for k, v in CHECKS.items():
            print(f"{k}  {v}")
        return 0
    chosen = [c.upper() for c in a.checks] or DEFAULT
    bad = [c for c in chosen if c not in CHECKS]
    if bad:
        sys.exit(f"unknown check(s) {bad}; known: {', '.join(CHECKS)}")
    ctx = Ctx(a)
    print(f"ZT Bank attacks from the remote client — website {ctx.web_ip}:{ctx.web_port} (tunnel), "
          f"cloud host {ctx.cloud_host}; identities found: {sorted(ctx.actors) or 'none'}")
    results = []
    for cid in chosen:
        print(f"\n== {cid}: {CHECKS[cid]}")
        res = Result(cid)
        try:
            RUN[cid](ctx, res)
        except KeyboardInterrupt:
            res.skip("interrupted")
        results.append(res)
    print("\n================ summary ================")
    for r in results:
        print(f"  {r.id}  {r.verdict:9} {r.title}")
    # one report for the whole session: each run updates its own checks, the others are kept
    # (B3 needs sudo and B6 needs the cloud host, so they are usually separate runs)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    previous = {}
    try:
        previous = {x["id"]: x for x in json.loads(Path(a.report).read_text()).get("results", [])}
    except (OSError, ValueError):
        pass
    for r in results:
        if r.verdict == "SKIPPED" and previous.get(r.id, {}).get("verdict") not in (None, "SKIPPED"):
            continue                       # an interrupted re-run does not erase a real result
        previous[r.id] = {**r.as_dict(), "when": now}
    report = {"when": now, "machine": socket.gethostname(),
              "results": [previous[k] for k in sorted(previous, key=lambda c: int(c[1:]))]}
    Path(a.report).write_text(json.dumps(report, indent=1))
    if os.environ.get("SUDO_UID"):
        os.chown(a.report, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
    print(f"  report: {Path(a.report).resolve()}  (copy it to the cloud host: build/reports/)")
    return 1 if any(r.verdict == "BREACH" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
