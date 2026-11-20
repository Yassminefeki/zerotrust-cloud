"""Stage 10 — ZT Bank, live, through the WireGuard tunnel. Run with `make test-10` (on the cloud host).

The client is the test peer (netns zt-peer) presenting the actors' real certificates; the bank
runs on the real VMs (frontend -> service-a -> service-b -> PostgreSQL).

Transfers here use small amounts (cents) so that repeated runs on the same day stay far below the
daily limit; the limit itself is proven offline against a real PostgreSQL (tests/unit).
"""
import json
import re
import time
import uuid

import pytest

from ztlive import VMs, actor_creds, actor_identity, ensure_peer, frontend_node, frontend_url, mtls, probe_tunnel, run_script

pytestmark = pytest.mark.bank


@pytest.fixture(scope="module")
def peer():
    return ensure_peer()


@pytest.fixture(scope="module")
def vm():
    return VMs()


def call(actor, method, path, body=None):
    r = probe_tunnel(frontend_url(path), *actor_creds(actor), method=method,
                     data=json.dumps(body) if body is not None else None)
    return r["status"], r["body"]


def accounts(actor):
    s, b = call(actor, "GET", "/api/accounts")
    assert s == 200, b
    return {a["id"]: a for a in b["accounts"]}


def dec(s):
    return round(float(s) * 100)


def send(actor, src, dst, amount, key=None, desc="live test"):
    return call(actor, "POST", "/api/transfers", {"from": src, "to": dst, "amount": amount, "description": desc,
                                                  "idempotency_key": key or uuid.uuid4().hex})


# --------------------------------------------------------------------- reading --
def test_each_customer_sees_only_their_accounts(peer):
    assert set(accounts("alice")) == {"ZTB-ALICE-01", "ZTB-ALICE-02"}
    assert set(accounts("bob")) == {"ZTB-BOB-01"}


def test_history(peer):
    s, b = call("alice", "GET", "/api/accounts/ZTB-ALICE-01/transactions")
    assert s == 200 and b["entries"] and b["entries"][0]["balance_after"] == b["balance"]
    assert any(e["description"] == "Salary - ACME Robotics" for e in b["entries"])


def test_idor_someone_elses_account_is_not_found(peer):
    assert call("bob", "GET", "/api/accounts/ZTB-ALICE-01/transactions") == (404, {"error": "account not found"})
    assert call("bob", "GET", "/api/accounts/ZTB-NOBODY-01/transactions") == (404, {"error": "account not found"})


def test_identity_headers_from_the_client_are_ignored(peer):
    """Bob sends the very headers the inner services trust, claiming to be Alice."""
    alice = actor_identity("alice")["uri"]
    r = probe_tunnel(frontend_url("/api/accounts"), *actor_creds("bob"),
                     extra=["--header", "X-ZT-Customer: alice", "--header", "X-ZT-Role: customer",
                            "--header", f"X-ZT-Actor: {alice}"])
    assert r["status"] == 200 and [a["id"] for a in r["body"]["accounts"]] == ["ZTB-BOB-01"]


# -------------------------------------------------------------------- transfers --
def test_transfer_alice_to_bob(peer):
    a0, b0 = accounts("alice")["ZTB-ALICE-01"]["balance"], accounts("bob")["ZTB-BOB-01"]["balance"]
    s, b = send("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "0.37", desc="Coffee")
    assert s == 201 and b["amount"] == "0.37" and b["currency"] == "EUR"
    assert dec(accounts("alice")["ZTB-ALICE-01"]["balance"]) == dec(a0) - 37
    assert dec(accounts("bob")["ZTB-BOB-01"]["balance"]) == dec(b0) + 37
    s, h = call("bob", "GET", "/api/accounts/ZTB-BOB-01/transactions")
    assert (h["entries"][0]["amount"], h["entries"][0]["counterparty"], h["entries"][0]["description"]) == \
        ("0.37", "ZTB-ALICE-01", "Coffee")


def test_retry_pays_once(peer):
    k, a0 = uuid.uuid4().hex, accounts("alice")["ZTB-ALICE-01"]["balance"]
    s1, b1 = send("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "0.05", key=k)
    s2, b2 = send("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "0.05", key=k)
    assert (s1, s2) == (201, 200) and b1["transfer_id"] == b2["transfer_id"] and b2["replayed"]
    assert dec(accounts("alice")["ZTB-ALICE-01"]["balance"]) == dec(a0) - 5


@pytest.mark.parametrize("who,src,dst,amount,status,msg", [
    ("bob", "ZTB-ALICE-01", "ZTB-BOB-01", "1.00", 404, "unknown source account"),
    ("alice", "ZTB-ALICE-01", "ZTB-NOBODY-01", "1.00", 404, "unknown destination"),
    ("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "-5.00", 400, "positive decimal"),
    ("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "6000.00", 422, "maximum per transfer"),
    ("alice", "ZTB-ALICE-01", "ZTB-ALICE-01", "1.00", 400, "same account"),
])
def test_transfer_refusals(peer, who, src, dst, amount, status, msg):
    s, b = send(who, src, dst, amount)
    assert s == status and msg in b["error"], b


# ------------------------------------------------------------------- other roles --
def test_bot_statements(peer):
    s, b = call("statements", "GET", "/api/statements?month=" + time.strftime("%Y-%m"))
    assert s == 200
    for r in b["statements"]:
        assert dec(r["closing"]) == dec(r["opening"]) + dec(r["credits"]) - dec(r["debits"])
    closing = {r["account"]: r["closing"] for r in b["statements"]}
    assert closing["ZTB-BOB-01"] == accounts("bob")["ZTB-BOB-01"]["balance"]


def test_staff_status(peer):
    s, b = call("dev", "GET", "/api/status")
    assert s == 200 and b["ledger_balanced"] is True and b["unbalanced_transfers"] == 0
    assert b["limits"]["max_transfer"] == "5000.00"
    assert not re.search(r"alice|bob|ZTB-", json.dumps(b), re.I), "no customer data for support staff"


# ------------------------------------------------------------- inside the database --
@pytest.fixture(scope="module")
def ledger_db(vm):
    """Queries as the application role, from service-b, with service-b's own certificate."""
    node = next(n for n in ("service-a", "service-b", "frontend")
                if any(c.get("protocol") == "postgres" for c in mtls(n)["calls"].values()))
    call_ = next(c for c in mtls(node)["calls"].values() if c.get("protocol") == "postgres")
    host, port = call_["address"].rsplit(":", 1)
    h = vm(node)

    def q(sql, customer=None):
        args = ["--host", host, "--port", port, "--db", call_["db_name"], "--user", call_["db_user"],
                "--ca", "/etc/zt/pki/root_ca.crt", "--cert", "/etc/zt/pki/cert.crt", "--key", "/etc/zt/pki/cert.key",
                "--sql", sql]
        if customer:
            args += ["--customer", customer]
        return run_script(h, "pg_probe.py", args)
    return q


def test_row_level_security_in_the_real_database(ledger_db):
    r = ledger_db("SELECT id FROM bank.accounts ORDER BY id", customer="bob")
    assert r["ok"] and r["rows"] == [["ZTB-BOB-01"]], r
    r = ledger_db("SELECT count(*) FROM bank.accounts")
    assert r["ok"] and r["rows"] == [["0"]], "no customer set: no rows at all"


@pytest.mark.parametrize("sql", [
    "UPDATE bank.accounts SET label = 'pwned'",
    "INSERT INTO bank.customers VALUES ('eve', 'Eve')",
    "DELETE FROM bank.entries",
    "SELECT * FROM bank.audit",
])
def test_application_role_cannot_write_directly(ledger_db, sql):
    r = ledger_db(sql, customer="alice")
    assert not r["ok"] and r["sqlstate"] == "42501", r     # insufficient_privilege


def test_history_is_append_only_even_for_the_dba(vm):
    r = vm("database").run("sudo -u postgres psql -d appdb -tAc \"UPDATE bank.entries SET amount_cents = 1\"")
    assert r.rc != 0 and "append-only" in r.stderr, r.stderr


def test_audit_records_the_certificate_identity(peer, vm):
    send("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "0.01", desc="audit check")
    out = vm("database").check_output(
        "sudo -u postgres psql -d appdb -tAc \"SELECT actor FROM bank.audit ORDER BY id DESC LIMIT 1\"")
    assert out.strip() == actor_identity("alice")["uri"]


def test_refusals_name_the_real_actor_at_every_layer(peer, vm):
    since = vm(frontend_node()).check_output("date '+%Y-%m-%d %H:%M:%S'").strip()
    time.sleep(1)
    call("bob", "GET", "/api/accounts/ZTB-ALICE-01/transactions")
    time.sleep(1)
    bob = actor_identity("bob")["uri"]
    logs = {n: vm(n).check_output(f"journalctl -u zt-mtls --since '{since}' --no-pager")
            for n in ("frontend", "service-a", "service-b")}
    assert f"denied {bob} GET /api/accounts/ZTB-ALICE-01/transactions: 404" in logs["frontend"]
    assert f"denied {bob} via spiffe://cloud.local/frontend GET /accounts/ZTB-ALICE-01" in logs["service-a"]
    assert f"denied {bob} via spiffe://cloud.local/service-a GET /ledger/accounts/ZTB-ALICE-01" in logs["service-b"]


def test_ledger_balanced_at_the_end(peer):
    assert call("dev", "GET", "/api/status")[1]["ledger_balanced"] is True
