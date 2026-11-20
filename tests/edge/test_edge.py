"""Stage 12 — the edges of the bank, live. Run with `make test-12` (on the i5).

The statements bot: its own network namespace (zt-bot) whose only way out is its own WireGuard
peer; its certificate is bound to that device; the frontend limits each identity's request rate
and the gateway limits the bot's connection rate.

The payment partner PayFlow: calls the webhook from OUTSIDE, without the VPN (from the i5's own
namespace, through the gateway's published port: the same path as from the Wi-Fi after the i5's
port forwarding, which is checked separately). Signed, time-boxed, each request accepted once.
"""
import json
import re
import subprocess
import time
import uuid

import pytest

import payflow
from ztlib import BUILD, ROOT, run
from ztlive import (PKI, ROOT_CA, VMs, actor_creds, actor_identity, ensure_ns, ensure_peer, frontend_node,
                    frontend_url, probe_tunnel)

pytestmark = pytest.mark.edge

TESTS = ROOT / "tests"
BOT_NS = PKI["identities"]["bot-statements"]["netns"]
BOT = actor_identity("statements")["uri"]
PAYFLOW = actor_identity("payflow")["uri"]
HOST = json.loads((BUILD / "host/host.json").read_text())
PUBLISHED = next(d for d in HOST["dnat"] if d["flow"] == "partner-webhook")
SECRETS = ROOT / "ansible/.secrets"


@pytest.fixture(scope="module")
def peer():
    return ensure_peer()


@pytest.fixture(scope="module")
def bot():
    return ensure_ns(BOT_NS)


@pytest.fixture(scope="module")
def vm():
    return VMs()


def in_ns(ns, args, timeout=120):
    r = subprocess.run(["sudo", "-n", "ip", "netns", "exec", ns, *map(str, args)],
                       capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, r.stderr
    return r.stdout


def burst(ns, mode, url, actor=None, **kw):
    args = ["python3", TESTS / "burst_probe.py", mode, "--url", url]
    if actor:
        c, k = actor_creds(actor)
        args += ["--cert", c, "--key", k, "--ca", ROOT_CA]
    for k_, v in kw.items():
        args += [f"--{k_}", v]
    return json.loads(in_ns(ns, args))


def journal(h, since):
    return h.check_output(f"journalctl -u zt-mtls --since '{since}' --no-pager")


def now(h):
    t = h.check_output("date '+%Y-%m-%d %H:%M:%S'").strip()
    time.sleep(1)
    return t


# ------------------------------------------------------------------------------- the bot --
def test_bot_namespace_has_only_its_tunnel(bot):
    links = run(["ip", "-n", bot, "-br", "link"], sudo=True, check=True).stdout.split("\n")
    assert sorted(l.split()[0] for l in links if l.strip()) == ["lo", f"wg-{bot}"]
    routes = [l.strip() for l in run(["ip", "-n", bot, "route"], sudo=True, check=True).stdout.split("\n") if l.strip()]
    assert routes == [f"10.20.0.10 dev wg-{bot} scope link"], "a real client: the frontend only"


def test_bot_has_its_own_peer_on_the_gateway(vm):
    pub = (SECRETS / "wireguard/bot.pub").read_text().strip()
    allowed = vm("gateway").check_output("wg show wg0 allowed-ips")
    assert f"{pub}\t10.10.0.3/32" in allowed


def test_bot_run_writes_the_statements(bot, tmp_path):
    c, k = actor_creds("statements")
    out = in_ns(bot, ["python3", ROOT / "tools/zt-bot.py", "--cert", c, "--key", k, "--ca", ROOT_CA,
                      "--url", PKI["identities"]["bot-statements"]["web_url"], "--out", tmp_path])
    assert "statements for" in out
    f = next(tmp_path.glob("statements-*.json"))
    data = json.loads(run(["cat", str(f)], sudo=True, check=True).stdout)
    assert len(data["statements"]) >= 3 and len(data["sha256"]) == 64


@pytest.mark.parametrize("target", ["10.30.0.11:9443", "10.40.0.10:5432", "10.50.0.10:9000", "10.20.0.1:22"])
def test_bot_reaches_nothing_but_the_frontend(bot, target):
    r = burst(bot, "tcp", f"tcp://{target}", n="1", timeout="2")
    assert r == {"connected": 0, "failed": 1}


def test_bot_identity_works_from_its_device(bot):
    r = probe_tunnel(frontend_url("/api/statements"), *actor_creds("statements"))
    assert r["status"] == 200, r


def test_stolen_bot_certificate_is_useless_on_another_machine(peer, vm):
    since = now(vm(frontend_node()))
    r = probe_tunnel(frontend_url("/api/statements"), *actor_creds("statements"), ns=peer)
    assert r["status"] == 403 and "not allowed from 10.10.0.200" in r["body"]["reason"], r
    assert f"identity {BOT} not allowed from 10.10.0.200" in journal(vm(frontend_node()), since)


def test_rate_limit_per_identity(bot, peer, vm):
    since = now(vm(frontend_node()))
    # ~4 requests/s: under the gateway's connection limit (5/s), far above 20/min. A full bucket is
    # 20 tokens, plus ~3 refilled during the burst: the last ones must be refused.
    r = burst(bot, "https", frontend_url("/api/me"), actor="statements", n="32", interval="0.2")
    codes = r["statuses"]
    assert codes.count(429) >= 5 and codes.count(200) <= 25 and set(codes) <= {200, 429}, codes
    retry = int(next(ra for s, ra in zip(codes, r["retry_after"]) if s == 429))
    assert 1 <= retry <= 3
    assert probe_tunnel(frontend_url("/api/me"), *actor_creds("alice"))["status"] == 200, "per identity"
    assert f"rate-limited {BOT}: above 20 requests/min" in journal(vm(frontend_node()), since)
    time.sleep(retry + 1)
    assert probe_tunnel(frontend_url("/api/me"), *actor_creds("statements"))["status"] == 200, "back after Retry-After"


def test_gateway_limits_the_bots_connection_bursts(bot, peer, vm):
    url = frontend_url("/").replace("https://", "tcp://").rstrip("/")
    limited = burst(bot, "tcp", url, n="40", timeout="0.8")
    control = burst(peer, "tcp", url, n="30", timeout="0.8")
    assert limited["connected"] <= 15 and limited["failed"] >= 25, limited
    assert control["connected"] >= 28, f"the test peer has no limit: {control}"
    rule = vm("gateway").check_output("nft list chain inet zt forward")
    assert "ip saddr 10.10.0.3 ct state new limit rate over 5/second burst 10 packets drop" in rule
    time.sleep(3)          # let the bucket refill


# ---------------------------------------------------------------------------- the partner --
def pay(payment=None, *, actor="payflow", secret=None, ts=None, nonce=None, body=None, headers=None):
    """PayFlow from outside the VPN: the i5 itself, to the gateway's published address."""
    secret = secret or bytes.fromhex((SECRETS / "partners/payflow.key").read_text().strip())
    payment = payment or {"reference": f"PF-{uuid.uuid4().hex[:10]}", "to": "ZTB-ALICE-01", "amount": "0.07",
                          "description": "live test"}
    b, h = payflow.signed(secret, payment, ts=ts, nonce=nonce)
    b, h = (body if body is not None else b), (headers if headers is not None else h)
    c, k = actor_creds(actor)
    host, port = PUBLISHED["to"].rsplit(":", 1)
    s, out = payflow.send(host, int(port), payflow.context(c, k, ROOT_CA), b, h)
    return s, out, (b, h)


def alice_balance():
    r = probe_tunnel(frontend_url("/api/accounts"), *actor_creds("alice"))
    return {a["id"]: a["balance"] for a in r["body"]["accounts"]}["ZTB-ALICE-01"]


def test_published_by_interface_name_on_the_i5():
    live = run(["nft", "list", "table", "inet", "zt_host"], sudo=True, check=True).stdout
    env_iface = re.search(r'iifname "([^"]+)" udp dport', live).group(1)
    assert f'iifname "{env_iface}" tcp dport 8444 dnat ip to {PUBLISHED["to"]}' in live


def test_partner_payment_from_outside_credits_the_customer(vm):
    before = float(alice_balance())
    since = now(vm(frontend_node()))
    ref = f"PF-{uuid.uuid4().hex[:10]}"
    s, out, _ = pay({"reference": ref, "to": "ZTB-ALICE-01", "amount": "0.07", "description": "live"})
    assert s == 201 and out["replayed"] is False, out
    assert round(float(alice_balance()) - before, 2) == 0.07
    hist = probe_tunnel(frontend_url("/api/accounts/ZTB-ALICE-01/transactions"), *actor_creds("alice"))["body"]
    assert hist["entries"][0]["description"] == f"PayFlow SAS: live ({ref})"
    # the frontend only ever sees the gateway (SNAT), never the outside address
    assert re.search(rf'zt-mtls 10\.20\.0\.1 {re.escape(PAYFLOW)} "POST /webhook HTTP/1\.1" 201',
                     journal(vm(frontend_node()), since))


def test_partner_request_played_twice_is_refused():
    s, out, (b, h) = pay()
    assert s == 201, out
    before = alice_balance()
    s, out, _ = pay(body=b, headers=h)
    assert s == 409 and "nonce already used" in out["error"], out
    assert alice_balance() == before


def test_partner_retry_is_answered_not_paid():
    p = {"reference": f"PF-{uuid.uuid4().hex[:10]}", "to": "ZTB-ALICE-01", "amount": "0.03"}
    assert pay(p)[0] == 201
    before = alice_balance()
    s, out, _ = pay(p)
    assert s == 200 and out["replayed"] is True
    assert alice_balance() == before


def test_partner_refusals():
    before = alice_balance()
    assert pay(ts=int(time.time()) - 600)[0] == 401, "stale"
    assert pay(ts=int(time.time()) + 600)[0] == 401, "future"
    assert pay(secret=b"\x02" * 32)[1] == {"error": "bad signature"}
    b, h = payflow.signed(bytes.fromhex((SECRETS / "partners/payflow.key").read_text().strip()),
                          {"reference": "PF-TAMPER01", "to": "ZTB-ALICE-01", "amount": "0.01"})
    assert pay(body=b.replace(b'"0.01"', b'"4999.00"'), headers=h)[0] == 401, "tampered after signing"
    s, out, _ = pay(actor="alice")
    assert s == 403 and "not allowed" in out["reason"], "only the partner's certificate"
    assert alice_balance() == before


def test_partner_reaches_only_the_webhook():
    gw = PUBLISHED["to"].rsplit(":", 1)[0]
    for port in (8443, 9443, 22, 5432):
        r = subprocess.run(["python3", TESTS / "burst_probe.py", "tcp", "--url", f"tcp://{gw}:{port}", "--n", "1",
                            "--timeout", "2"], capture_output=True, text=True, timeout=30)
        assert json.loads(r.stdout) == {"connected": 0, "failed": 1}, f"{gw}:{port} answered from outside"
    c, k = actor_creds("payflow")
    host, port = PUBLISHED["to"].rsplit(":", 1)
    s, out = payflow.send(host, int(port), payflow.context(c, k, ROOT_CA), b"{}",
                          {"Content-Type": "application/json"}, path="/api/accounts")
    assert s == 404


def test_partner_identity_refused_through_the_tunnel(peer):
    r = probe_tunnel(frontend_url("/api/me"), *actor_creds("payflow"))
    assert r["status"] == 403, r


def test_partner_secret_only_on_the_frontend(vm):
    secret = (SECRETS / "partners/payflow.key").read_text().strip()
    f = vm(frontend_node()).file("/etc/zt/partners/payflow.key")
    assert (f.user, f.group, f.mode) == ("root", "zt-app", 0o640)
    same = f.content_string.strip() == secret          # booleans: a failure must not print the secret
    assert same, "deployed secret differs from ansible/.secrets/partners/payflow.key"
    for node in ("service-a", "service-b", "database"):
        assert not vm(node).file("/etc/zt/partners").exists
    logs = vm(frontend_node()).check_output("journalctl -u zt-mtls --since '-2h' --no-pager")
    leaked = secret in logs
    assert not leaked, "the webhook secret appears in the frontend's journal"
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    assert "partners/" not in tracked


def test_incoming_payment_audited_in_the_database(vm):
    ref = f"PF-{uuid.uuid4().hex[:10]}"
    assert pay({"reference": ref, "to": "ZTB-ALICE-01", "amount": "0.02"})[0] == 201
    out = vm("database").check_output(
        "sudo -u postgres psql -d appdb -At -c \"SELECT actor || '|' || (detail->>'partner') FROM bank.audit "
        f"WHERE action = 'incoming_payment' AND detail->>'reference' = '{ref}'\"")
    assert out.strip() == f"{PAYFLOW}|payflow"
    st = probe_tunnel(frontend_url("/api/status"), *actor_creds("dev"))["body"]
    assert st["ledger_balanced"] is True
