"""Stage 10 (offline) — the ZT Bank database itself: schema, row-level security, append-only
ledger and every rule of bank.transfer(), against a REAL PostgreSQL.

Needs a PostgreSQL server: set ZT_TEST_PG_DSN (a superuser DSN, e.g.
"host=/tmp port=54329 user=postgres"), or have initdb/pg_ctl on the PATH (non-root) and the test
starts a throwaway cluster. Skipped otherwise. Each run uses a fresh database.
"""
import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest
import yaml

from unit_helpers import ROOT

jinja2 = pytest.importorskip("jinja2")

psycopg2 = pytest.importorskip("psycopg2")
from psycopg2 import errors  # noqa: E402

TEMPLATES = ROOT / "ansible/roles/postgres/templates"
SEED = ROOT / "ansible/roles/postgres/files/seed.yaml"
ALICE, BOB = "spiffe://cloud.local/customer/alice", "spiffe://cloud.local/customer/bob"


def _pg_bin(name):
    for d in [os.environ.get("ZT_PG_BIN", "")] + sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True):
        if d and (Path(d) / name).exists():
            return str(Path(d) / name)
    return shutil.which(name)


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """A superuser DSN to some PostgreSQL server."""
    if os.environ.get("ZT_TEST_PG_DSN"):
        yield os.environ["ZT_TEST_PG_DSN"]
        return
    initdb, pg_ctl = _pg_bin("initdb"), _pg_bin("pg_ctl")
    if not initdb or not pg_ctl or os.geteuid() == 0:
        pytest.skip("no PostgreSQL server: set ZT_TEST_PG_DSN or install postgresql (run as non-root)")
    d = tmp_path_factory.mktemp("pg")
    subprocess.run([initdb, "-D", str(d / "data"), "-U", "postgres", "-A", "trust"], check=True,
                   capture_output=True)
    subprocess.run([pg_ctl, "-D", str(d / "data"), "-w", "-o", f"-p 54331 -k {d} -c listen_addresses=''",
                    "-l", str(d / "log"), "start"], check=True, capture_output=True)
    yield f"host={d} port=54331 user=postgres"
    subprocess.run([pg_ctl, "-D", str(d / "data"), "-m", "fast", "stop"], capture_output=True)


def render(build):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)), keep_trailing_newline=True)
    return env.get_template("bank.sql.j2").render(
        bank=json.loads((build / "bank/bank.json").read_text()),
        seed=yaml.safe_load(SEED.read_text()), db_user="service_b")


def psql(dsn, sql_text, db):
    r = subprocess.run([_pg_bin("psql") or "psql", f"{dsn} dbname={db}", "-q", "-v", "ON_ERROR_STOP=1",
                        "-c", "SET client_min_messages = warning", "-f", "-"],
                       input=sql_text, text=True, capture_output=True)
    assert r.returncode == 0, r.stderr
    return r


@pytest.fixture(scope="module")
def db(server, build):
    name = f"bank_test_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(f"{server} dbname=postgres")
    admin.autocommit = True
    with admin.cursor() as c:
        c.execute("SELECT 1 FROM pg_roles WHERE rolname = 'service_b'")
        if not c.fetchone():
            c.execute("CREATE ROLE service_b LOGIN")
        c.execute("SELECT 1 FROM pg_roles WHERE rolname = 'intruder'")
        if not c.fetchone():
            c.execute("CREATE ROLE intruder LOGIN")
        c.execute(f"CREATE DATABASE {name}")
    sql_text = render(build)
    psql(server, sql_text, name)
    yield {"server": server, "name": name, "sql": sql_text}
    with admin.cursor() as c:
        c.execute(f"DROP DATABASE {name} WITH (FORCE)")
    admin.close()


def connect(db, user="service_b"):
    conn = psycopg2.connect(f"{db['server']} dbname={db['name']} user={user}")
    return conn


def as_customer(db, customer, sql_text, args=()):
    """Run one query as the application role, with zt.customer set for this transaction only."""
    conn = connect(db)
    try:
        with conn, conn.cursor() as c:
            if customer is not None:
                c.execute("SELECT set_config('zt.customer', %s, true)", (customer,))
            c.execute(sql_text, args)
            return c.fetchall()
    finally:
        conn.close()


def transfer(db, customer, actor, key, src, dst, cents, desc="test"):
    return as_customer(db, None, "SELECT * FROM bank.transfer(%s,%s,%s,%s,%s,%s,%s)",
                       (customer, actor, key, src, dst, cents, desc))[0]


def balance(db, account):
    conn = psycopg2.connect(f"{db['server']} dbname={db['name']}")
    with conn, conn.cursor() as c:
        c.execute("SELECT coalesce(sum(amount_cents),0) FROM bank.entries WHERE account_id=%s", (account,))
        b = c.fetchone()[0]
    conn.close()
    return b


def key():
    return uuid.uuid4().hex[:16]


def sqlstate(exc_info):
    return exc_info.value.pgcode


# ------------------------------------------------------------------- schema and seed --
def test_applies_again_without_change(db):
    before = as_customer(db, "alice", "SELECT count(*) FROM bank.entries")[0][0]
    psql(db["server"], db["sql"], db["name"])
    assert as_customer(db, "alice", "SELECT count(*) FROM bank.entries")[0][0] == before


def test_seed_matches_the_policy_customers(policy):
    seed = yaml.safe_load(SEED.read_text())
    customers = {a["customer"] for a in policy["actors"].values() if a["role"] == "customer"}
    assert set(seed) == customers, "every customer actor has demo data, and only them"


def test_status_is_balanced_and_anonymous(db):
    s = as_customer(db, None, "SELECT bank.status()")[0][0]
    assert s["ledger_balanced"] is True and s["unbalanced_transfers"] == 0
    assert s["customers"] == 2 and s["accounts"] == 3
    assert "alice" not in json.dumps(s).lower() and "martin" not in json.dumps(s).lower()


# --------------------------------------------------------------- row level security --
def test_no_customer_set_no_rows(db):
    for t in ("customers", "accounts", "entries", "transfers"):
        assert as_customer(db, None, f"SELECT count(*) FROM bank.{t}")[0][0] == 0, t


def test_select_without_where_returns_only_own_rows(db):
    """Even a query that forgets `WHERE customer = ...` only sees the customer's own rows."""
    assert [r[0] for r in as_customer(db, "bob", "SELECT id FROM bank.accounts ORDER BY id")] == ["ZTB-BOB-01"]
    assert [r[0] for r in as_customer(db, "bob", "SELECT id FROM bank.customers")] == ["bob"]
    accts = {r[0] for r in as_customer(db, "bob", "SELECT DISTINCT account_id FROM bank.entries")}
    assert accts == {"ZTB-BOB-01"}
    alice = {r[0] for r in as_customer(db, "alice", "SELECT id FROM bank.accounts")}
    assert alice == {"ZTB-ALICE-01", "ZTB-ALICE-02"}


def test_another_customers_account_is_invisible(db):
    assert as_customer(db, "bob", "SELECT * FROM bank.accounts WHERE id = 'ZTB-ALICE-01'") == []
    assert as_customer(db, "bob", "SELECT * FROM bank.entries WHERE account_id = 'ZTB-ALICE-01'") == []


@pytest.mark.parametrize("stmt", [
    "INSERT INTO bank.entries (transfer_id, account_id, amount_cents) SELECT transfer_id, account_id, 1 FROM bank.entries LIMIT 1",
    "UPDATE bank.accounts SET label = 'x'",
    "DELETE FROM bank.transfers",
    "INSERT INTO bank.customers VALUES ('eve', 'Eve')",
    "SELECT * FROM bank.audit",
    "SELECT * FROM bank.settings",
])
def test_application_role_cannot_write_or_read_the_audit(db, stmt):
    with pytest.raises(errors.InsufficientPrivilege):
        as_customer(db, "alice", stmt)


def test_other_roles_cannot_even_call_the_functions(db):
    conn = connect(db, "intruder")
    try:
        with pytest.raises(errors.InsufficientPrivilege):
            with conn, conn.cursor() as c:
                c.execute("SELECT * FROM bank.transfer('alice', %s, 'abcdefgh1', 'ZTB-ALICE-01', 'ZTB-BOB-01', 1, 'x')",
                          (ALICE,))
    finally:
        conn.close()


def test_ledger_is_append_only_even_for_the_owner(db):
    conn = psycopg2.connect(f"{db['server']} dbname={db['name']}")   # superuser
    try:
        for stmt in ("UPDATE bank.entries SET amount_cents = 999999", "DELETE FROM bank.transfers",
                     "TRUNCATE bank.audit CASCADE"):
            with pytest.raises(psycopg2.Error) as e:
                with conn, conn.cursor() as c:
                    c.execute(stmt)
            assert e.value.pgcode == "ZT405", stmt
    finally:
        conn.close()


# ------------------------------------------------------------------- bank.transfer --
def test_transfer_moves_money_with_double_entry(db):
    a0, b0 = balance(db, "ZTB-ALICE-01"), balance(db, "ZTB-BOB-01")
    tid, replayed, bal = transfer(db, "alice", ALICE, key(), "ZTB-ALICE-01", "ZTB-BOB-01", 12345, "Dinner")
    assert replayed is False and bal == a0 - 12345
    assert balance(db, "ZTB-ALICE-01") == a0 - 12345 and balance(db, "ZTB-BOB-01") == b0 + 12345
    rows = as_customer(db, "bob", "SELECT amount_cents FROM bank.entries WHERE transfer_id = %s", (tid,))
    assert rows == [(12345,)], "Bob sees his credit, not Alice's debit"
    s = as_customer(db, None, "SELECT bank.status()")[0][0]
    assert s["ledger_balanced"] is True


def test_transfer_is_audited_with_the_identity(db):
    tid = transfer(db, "alice", ALICE, key(), "ZTB-ALICE-01", "ZTB-ALICE-02", 100)[0]
    conn = psycopg2.connect(f"{db['server']} dbname={db['name']}")
    with conn, conn.cursor() as c:
        c.execute("SELECT actor, action, detail->>'from' FROM bank.audit WHERE detail->>'transfer' = %s", (str(tid),))
        assert c.fetchone() == (ALICE, "transfer", "ZTB-ALICE-01")
    conn.close()


def test_same_key_twice_moves_money_once(db):
    k, a0 = key(), balance(db, "ZTB-ALICE-01")
    t1 = transfer(db, "alice", ALICE, k, "ZTB-ALICE-01", "ZTB-BOB-01", 500)
    t2 = transfer(db, "alice", ALICE, k, "ZTB-ALICE-01", "ZTB-BOB-01", 500)
    assert t1[0] == t2[0] and t1[1] is False and t2[1] is True
    assert balance(db, "ZTB-ALICE-01") == a0 - 500


def test_same_key_for_another_transfer_is_refused(db):
    k = key()
    transfer(db, "alice", ALICE, k, "ZTB-ALICE-01", "ZTB-BOB-01", 700)
    with pytest.raises(psycopg2.Error) as e:
        transfer(db, "alice", ALICE, k, "ZTB-ALICE-01", "ZTB-BOB-01", 70000)
    assert sqlstate(e) == "ZT409"


@pytest.mark.parametrize("args,code", [
    (("bob", BOB, "ZTB-ALICE-01", "ZTB-BOB-01", 100), "ZT404"),        # not his account
    (("alice", ALICE, "ZTB-ALICE-01", "ZTB-NOBODY-01", 100), "ZT404"),  # unknown destination
    (("alice", ALICE, "ZTB-ALICE-01", "ZTB-ALICE-01", 100), "ZT400"),   # same account
    (("alice", ALICE, "ZTB-ALICE-01", "ZTB-BOB-01", 0), "ZT400"),       # zero
    (("alice", ALICE, "ZTB-ALICE-01", "ZTB-BOB-01", -500), "ZT400"),    # negative = stealing
    (("alice", ALICE, "ZTB-ALICE-01", "ZTB-BOB-01", 500001), "ZT422"),  # above max per transfer
    (("bob", BOB, "ZTB-BOB-01", "ZTB-ALICE-01", 499999), "ZT422"),      # more than Bob has
    (("", ALICE, "ZTB-ALICE-01", "ZTB-BOB-01", 100), "ZT400"),          # no customer
    (("alice", "alice", "ZTB-ALICE-01", "ZTB-BOB-01", 100), "ZT400"),   # identity is not a SPIFFE ID
])
def test_transfer_rules(db, args, code):
    customer, actor, src, dst, cents = args
    with pytest.raises(psycopg2.Error) as e:
        transfer(db, customer, actor, key(), src, dst, cents)
    assert sqlstate(e) == code, e.value


def test_bad_idempotency_key_refused(db):
    with pytest.raises(psycopg2.Error) as e:
        transfer(db, "alice", ALICE, "x';--", "ZTB-ALICE-01", "ZTB-BOB-01", 100)
    assert sqlstate(e) == "ZT400"


def test_daily_limit_applies_to_money_leaving_the_customer(db, build):
    limit = json.loads((build / "bank/bank.json").read_text())["daily_limit_cents"]
    # moving between her own accounts is not limited (savings -> current, above the daily limit)
    transfer(db, "alice", ALICE, key(), "ZTB-ALICE-02", "ZTB-ALICE-01", limit + 100000)
    conn = psycopg2.connect(f"{db['server']} dbname={db['name']}")
    with conn, conn.cursor() as c:
        c.execute("""SELECT coalesce(sum(t.amount_cents),0) FROM bank.transfers t JOIN bank.accounts d
                      ON d.id = t.to_account WHERE t.customer_id = 'alice'
                      AND t.created_at >= date_trunc('day', now()) AND d.customer_id IS DISTINCT FROM 'alice'""")
        today = c.fetchone()[0]
    conn.close()
    left = limit - today
    transfer(db, "alice", ALICE, key(), "ZTB-ALICE-01", "ZTB-BOB-01", left)        # exactly up to the limit
    with pytest.raises(psycopg2.Error) as e:
        transfer(db, "alice", ALICE, key(), "ZTB-ALICE-01", "ZTB-BOB-01", 1)       # one cent more
    assert sqlstate(e) == "ZT422" and "daily limit" in str(e.value)


def test_concurrent_transfers_cannot_double_spend(db, build):
    """Four transfers of just over HALF the savings, launched at the same instant. Each alone is
    valid (own accounts: no daily limit; under the per-transfer maximum); any two together exceed
    the balance. The row lock in bank.transfer() must let exactly one through."""
    src, dst = "ZTB-ALICE-02", "ZTB-ALICE-01"
    max_cents = json.loads((build / "bank/bank.json").read_text())["max_transfer_cents"]
    # setup: bring the savings under 2 x max, so that half of them is a valid single transfer
    while balance(db, src) > 2 * max_cents - 2:
        transfer(db, "alice", ALICE, key(), src, dst, min(max_cents, balance(db, src) - (2 * max_cents - 1000)))
    have = balance(db, src)
    amount = have // 2 + 1
    assert 0 < amount <= max_cents and 2 * amount > have
    results, barrier = [], threading.Barrier(4)

    def spend():
        barrier.wait()
        try:
            transfer(db, "alice", ALICE, key(), src, dst, amount)
            results.append("ok")
        except psycopg2.Error as e:
            results.append(f"{e.pgcode} {e.diag.message_primary}")

    threads = [threading.Thread(target=spend) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(results) == ["ZT422 insufficient funds"] * 3 + ["ok"], results
    assert balance(db, src) == have - amount >= 0


# ------------------------------------------------------------------ statements --
def test_statement_closing_is_the_balance(db):
    month = time.strftime("%Y-%m")
    rows = {r[0]: r for r in as_customer(db, None, "SELECT * FROM bank.statements(%s)", (month,))}
    assert set(rows) == {"ZTB-ALICE-01", "ZTB-ALICE-02", "ZTB-BOB-01"}, "customer accounts only"
    for acct, r in rows.items():
        _, _, cur, opening, credits, debits, closing = r
        assert cur == "EUR" and closing == opening + credits - debits
        assert closing == balance(db, acct)


@pytest.mark.parametrize("month", ["2026-13", "26-11", "2026-11'; DROP TABLE bank.entries;--", ""])
def test_statement_month_validated(db, month):
    with pytest.raises(psycopg2.Error) as e:
        as_customer(db, None, "SELECT * FROM bank.statements(%s)", (month,))
    assert sqlstate(e) == "ZT400"
