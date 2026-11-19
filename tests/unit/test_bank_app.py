"""Stage 10 (offline) — ZT Bank end to end: frontend (web) -> service-a (core) -> service-b
(ledger) -> PostgreSQL, with the REAL programs (zt-mtls + zt_bank.py), the REAL generated routes
(build/nodes/*/mtls.json) and a REAL PostgreSQL that only accepts service-b's certificate over
TLS 1.3. Every client is an actor of policy.yaml with its own certificate.

Needs PostgreSQL binaries (initdb, pg_ctl, postgres) and psycopg2; skipped otherwise. As root, set
ZT_TEST_PG_RUNAS=<user> to run the database as that user.
"""
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import jinja2
import pytest
import yaml

from unit_helpers import ROOT

pytest.importorskip("psycopg2")
SERVICE = ROOT / "ansible/roles/app/files/zt-mtls"
TD = "spiffe://cloud.local"
IP = {"frontend": "127.0.0.10", "service-a": "127.0.0.11", "service-b": "127.0.0.12", "database": "127.0.0.13"}

PKI_SH = r"""
set -e
k(){ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
cat > ext.cnf <<'EOF'
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=${ENV::SAN}
EOF
k root.key; openssl req -x509 -new -key root.key -subj /CN=root -days 2 -out root.crt \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
k int.key; openssl req -new -key int.key -subj /CN=int -out int.csr
SAN=URI:x openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -days 2 -extfile ext.cnf -extensions ca -out int.crt 2>/dev/null
leaf(){ k "$1.key"; openssl req -new -key "$1.key" -subj "/CN=$1" -out "$1.csr"
  SAN="$2" openssl x509 -req -in "$1.csr" -CA int.crt -CAkey int.key -days 1 -extfile ext.cnf -extensions leaf -out "$1.leaf" 2>/dev/null
  cat "$1.leaf" int.crt > "$1.crt"; }
leaf frontend  "URI:$TD/frontend,IP:127.0.0.10"
leaf service-a "URI:$TD/service-a,IP:127.0.0.11"
leaf service-b "URI:$TD/service-b,IP:127.0.0.12"
leaf database  "URI:$TD/database,IP:127.0.0.13"
leaf alice     "URI:$TD/customer/alice,DNS:customer-alice"
leaf bob       "URI:$TD/customer/bob,DNS:customer-bob"
leaf dev       "URI:$TD/staff/dev,DNS:staff-dev"
leaf bot       "URI:$TD/bot/statements,DNS:bot-statements"
"""


def free_port(ip):
    s = socket.socket()
    s.bind((ip, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(ip, port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection((ip, port), timeout=0.3).close()
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"{ip}:{port}")


def pg_bin(name):
    for d in sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True):
        if (d / name).exists():
            return str(d / name)
    return shutil.which(name)


@pytest.fixture(scope="module")
def bank(build, tmp_path_factory):
    runas = os.environ.get("ZT_TEST_PG_RUNAS")
    if not (pg_bin("initdb") and pg_bin("pg_ctl")) or (os.geteuid() == 0 and not runas):
        pytest.skip("needs PostgreSQL binaries (and ZT_TEST_PG_RUNAS when running as root)")
    d = tmp_path_factory.mktemp("bankapp")
    subprocess.run(["bash", "-c", PKI_SH], cwd=d, check=True, capture_output=True, env={"TD": TD, "PATH": os.environ["PATH"]})

    # ------------------------------------------------------------- PostgreSQL, like on the VM --
    pre = ["runuser", "-u", runas, "--"] if os.geteuid() == 0 else []
    # the database user must be able to reach its folder (pytest's tmp dirs are 0700)
    pg = Path(tempfile.mkdtemp(prefix="zt-pg-")) if pre else d / "pg"
    pg.mkdir(exist_ok=True)
    for f in ("database.crt", "database.key", "root.crt"):
        shutil.copy(d / f, pg / f)
    (pg / "database.key").chmod(0o600)
    if pre:
        subprocess.run(["chown", "-R", runas, str(pg)], check=True)
    port = free_port(IP["database"])
    subprocess.run(pre + [pg_bin("initdb"), "-D", str(pg / "data"), "-U", "postgres", "-A", "trust"],
                   check=True, capture_output=True)
    conf = pg / "data/postgresql.conf"
    conf.write_text(conf.read_text() + f"""
listen_addresses = '{IP["database"]}'
port = {port}
unix_socket_directories = '{pg}'
ssl = on
ssl_cert_file = '{pg}/database.crt'
ssl_key_file = '{pg}/database.key'
ssl_ca_file = '{pg}/root.crt'
ssl_min_protocol_version = 'TLSv1.3'
""")
    # the generated pg_hba/pg_ident, with the loopback address the test client really uses
    hba = (build / "nodes/database/pg_hba.conf").read_text().replace("10.40.0.11/32", "127.0.0.1/32")
    (pg / "data/pg_hba.conf").write_text(hba.replace("local    all       postgres            peer",
                                                     "local    all       postgres            trust"))
    shutil.copy(build / "nodes/database/pg_ident.conf", pg / "data/pg_ident.conf")
    if pre:
        subprocess.run(["chown", "-R", runas, str(pg)], check=True)
    subprocess.run(pre + [pg_bin("pg_ctl"), "-D", str(pg / "data"), "-w", "-l", str(pg / "log"), "start"],
                   check=True, capture_output=True)
    psql = [pg_bin("psql") or "psql", "-h", str(pg), "-p", str(port), "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q"]
    subprocess.run(psql + ["-c", "CREATE ROLE service_b LOGIN", "-c", "CREATE DATABASE appdb"], check=True,
                   capture_output=True)
    sql_text = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROOT / "ansible/roles/postgres/templates")),
                                  keep_trailing_newline=True).get_template("bank.sql.j2").render(
        bank=json.loads((build / "bank/bank.json").read_text()),
        seed=yaml.safe_load((ROOT / "ansible/roles/postgres/files/seed.yaml").read_text()), db_user="service_b")
    r = subprocess.run(psql + ["-d", "appdb", "-c", "SET client_min_messages=warning", "-f", "-"],
                       input=sql_text, text=True, capture_output=True)
    assert r.returncode == 0, r.stderr

    # ---------------------------------------- the three services, from the generated mtls.json --
    ports = {n: free_port(IP[n]) for n in ("frontend", "service-a", "service-b")}
    nxt = {"frontend": ("service-a", "api-a"), "service-a": ("service-b", "api-b")}
    procs = []
    for node in ("service-b", "service-a", "frontend"):
        m = json.loads((build / f"nodes/{node}/mtls.json").read_text())
        for s in m["serves"].values():
            s["listen"], s["port"] = f"{IP[node]}:{ports[node]}", ports[node]
            s["allowed_sources"] = ["127.0.0.0/8"] if node == "frontend" else ["127.0.0.1"]
        for name, c in m["calls"].items():
            if c.get("protocol") == "postgres":
                c["address"] = f"{IP['database']}:{port}"
            else:
                tgt = nxt[node][0]
                c["address"] = f"{IP[tgt]}:{ports[tgt]}"
        nd = d / node
        nd.mkdir()
        shutil.copy(d / f"{node}.crt", nd / "cert.crt")
        shutil.copy(d / f"{node}.key", nd / "cert.key")
        shutil.copy(d / "root.crt", nd / "root_ca.crt")
        (nd / "cert.key").chmod(0o600)
        (nd / "mtls.json").write_text(json.dumps(m))
        procs.append(subprocess.Popen([sys.executable, str(SERVICE), str(nd / "mtls.json"), str(nd)],
                                      stdout=open(d / f"{node}.log", "w"), stderr=subprocess.STDOUT,
                                      env=dict(os.environ, ZT_WWW=str(d / "www"))))
        wait_port(IP[node], ports[node])
    yield {"dir": d, "url": f"{IP['frontend']}:{ports['frontend']}", "ports": ports, "pg": (pg, port, psql)}
    for p in procs:
        p.terminate()
        p.wait(5)
    subprocess.run(pre + [pg_bin("pg_ctl"), "-D", str(pg / "data"), "-m", "fast", "stop"], capture_output=True)


def call(bank, who, method, path, body=None, headers=None, to="frontend", raw=None):
    d = bank["dir"]
    host = IP[to]
    port = bank["ports"][to] if to != "frontend" else int(bank["url"].rsplit(":", 1)[1])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(d / "root.crt")
    ctx.load_cert_chain(d / f"{who}.crt", d / f"{who}.key")
    c = http.client.HTTPSConnection(host, port, context=ctx, timeout=20)
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    c.request(method, path, body=data, headers=headers or {})
    r = c.getresponse()
    text = r.read()
    c.close()
    try:
        return r.status, json.loads(text or b"null"), dict(r.getheaders())
    except ValueError:
        return r.status, text, dict(r.getheaders())


def accounts(bank, who):
    s, b, _ = call(bank, who, "GET", "/api/accounts")
    assert s == 200, b
    return {a["id"]: a for a in b["accounts"]}


def send(bank, who, src, dst, amount, key=None, desc="test"):
    return call(bank, who, "POST", "/api/transfers",
                {"from": src, "to": dst, "amount": amount, "description": desc,
                 "idempotency_key": key or uuid.uuid4().hex})


def dec(s):
    return round(float(s) * 100)


# ---------------------------------------------------------------- reading --
def test_customer_sees_own_accounts_only(bank):
    a = accounts(bank, "alice")
    assert set(a) == {"ZTB-ALICE-01", "ZTB-ALICE-02"}
    assert a["ZTB-ALICE-02"]["label"] == "Savings account" and a["ZTB-ALICE-01"]["currency"] == "EUR"
    assert set(accounts(bank, "bob")) == {"ZTB-BOB-01"}


def test_history_with_running_balance(bank):
    s, b, _ = call(bank, "alice", "GET", "/api/accounts/ZTB-ALICE-01/transactions")
    assert s == 200 and b["account"] == "ZTB-ALICE-01"
    e = b["entries"]
    assert e[0]["balance_after"] == b["balance"], "newest first, ends at the current balance"
    for newer, older in zip(e, e[1:]):
        assert dec(newer["balance_after"]) - dec(newer["amount"]) == dec(older["balance_after"])
    assert any(x["description"] == "Rent - November" for x in e)


def test_someone_elses_account_looks_like_a_missing_one(bank):
    """IDOR: Bob changes the account number in the URL. Same 404 as a non-existent account."""
    s1, b1, _ = call(bank, "bob", "GET", "/api/accounts/ZTB-ALICE-01/transactions")
    s2, b2, _ = call(bank, "bob", "GET", "/api/accounts/ZTB-NOBODY-01/transactions")
    assert (s1, b1) == (s2, b2) == (404, {"error": "account not found"})


def test_client_cannot_choose_who_it_is(bank):
    """Bob sends the identity headers the inner services use: the frontend ignores them."""
    s, b, _ = call(bank, "bob", "GET", "/api/accounts",
                   headers={"X-ZT-Customer": "alice", "X-ZT-Role": "customer",
                            "X-ZT-Actor": f"{TD}/customer/alice"})
    assert s == 200 and {a["id"] for a in b["accounts"]} == {"ZTB-BOB-01"}


# ---------------------------------------------------------------- transfers --
def test_transfer_between_customers(bank):
    a0, b0 = accounts(bank, "alice"), accounts(bank, "bob")
    s, b, _ = send(bank, "alice", "ZTB-ALICE-01", "ZTB-BOB-01", "12.50", desc="Lunch <script>x</script>")
    assert s == 201 and b["amount"] == "12.50" and b["replayed"] is False
    a1, b1 = accounts(bank, "alice"), accounts(bank, "bob")
    assert dec(a1["ZTB-ALICE-01"]["balance"]) == dec(a0["ZTB-ALICE-01"]["balance"]) - 1250
    assert dec(b1["ZTB-BOB-01"]["balance"]) == dec(b0["ZTB-BOB-01"]["balance"]) + 1250
    _, h, _ = call(bank, "bob", "GET", "/api/accounts/ZTB-BOB-01/transactions")
    top = h["entries"][0]
    assert (top["amount"], top["counterparty"]) == ("12.50", "ZTB-ALICE-01")
    assert top["description"] == "Lunch <script>x</script>", "stored as text; the UI must escape it"


def test_retry_with_the_same_key_pays_once(bank):
    k, a0 = uuid.uuid4().hex, accounts(bank, "alice")["ZTB-ALICE-01"]["balance"]
    s1, b1, _ = send(bank, "alice", "ZTB-ALICE-01", "ZTB-BOB-01", "3.00", key=k)
    s2, b2, _ = send(bank, "alice", "ZTB-ALICE-01", "ZTB-BOB-01", "3.00", key=k)
    assert (s1, s2) == (201, 200) and b1["transfer_id"] == b2["transfer_id"] and b2["replayed"] is True
    assert dec(accounts(bank, "alice")["ZTB-ALICE-01"]["balance"]) == dec(a0) - 300


@pytest.mark.parametrize("who,src,dst,amount,status,msg", [
    ("bob", "ZTB-ALICE-01", "ZTB-BOB-01", "10.00", 404, "unknown source account"),   # not his
    ("alice", "ZTB-ALICE-01", "ZTB-NOBODY-01", "1.00", 404, "unknown destination"),
    ("alice", "ZTB-ALICE-01", "ZTB-ALICE-01", "1.00", 400, "same account"),
    ("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "-5.00", 400, "positive decimal"),
    ("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "0", 400, "must be positive"),
    ("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "1e3", 400, "positive decimal"),
    ("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "0.001", 400, "positive decimal"),
    ("alice", "ZTB-ALICE-01", "ZTB-BOB-01", "6000.00", 422, "maximum per transfer"),
    ("bob", "ZTB-BOB-01", "ZTB-ALICE-01", "4999.99", 422, "insufficient funds"),
    ("alice", "ZTB-ALICE-01'--", "ZTB-BOB-01", "1.00", 400, "account ids"),
])
def test_transfer_refusals(bank, who, src, dst, amount, status, msg):
    s, b, _ = send(bank, who, src, dst, amount)
    assert s == status and msg in b["error"], (s, b)


@pytest.mark.parametrize("body,status", [
    ({"from": "ZTB-ALICE-01", "to": "ZTB-BOB-01", "amount": "1.00"}, 400),                         # no key
    ({"from": "ZTB-ALICE-01", "to": "ZTB-BOB-01", "amount": "1.00", "idempotency_key": "short"}, 400),
    ({"from": "ZTB-ALICE-01", "to": "ZTB-BOB-01", "amount": 1, "idempotency_key": "abcdefgh12"}, 400),  # number
    ({"from": "ZTB-ALICE-01", "to": "ZTB-BOB-01", "amount": "1.00", "idempotency_key": "abcdefgh12",
      "customer": "bob"}, 400),                                                                       # extra field
])
def test_malformed_transfers(bank, body, status):
    s, b, _ = call(bank, "alice", "POST", "/api/transfers", body)
    assert s == status, b


def test_non_json_and_oversized_bodies(bank):
    assert call(bank, "alice", "POST", "/api/transfers", raw=b"not json")[0] == 400
    assert call(bank, "alice", "POST", "/api/transfers", raw=b"[1,2]")[0] == 400
    assert call(bank, "alice", "POST", "/api/transfers", raw=b"x" * 9000)[0] == 413


def test_daily_limit(bank, build):
    limit = json.loads((build / "bank/bank.json").read_text())["daily_limit_cents"]
    # top Bob's account up from Alice's savings (Alice -> Bob counts against ALICE's limit only)
    send(bank, "alice", "ZTB-ALICE-02", "ZTB-ALICE-01", "3000.00")
    s = 201
    sent = 0
    while s == 201:
        s, b, _ = send(bank, "alice", "ZTB-ALICE-01", "ZTB-BOB-01", "400.00")
        sent += 40000 if s == 201 else 0
    assert s == 422 and "daily limit" in b["error"]
    assert sent <= limit


# ------------------------------------------------------------- other roles --
def test_bot_gets_statements_without_counterparties(bank):
    s, b, _ = call(bank, "bot", "GET", "/api/statements?month=" + time.strftime("%Y-%m"))
    assert s == 200 and b["month"] == time.strftime("%Y-%m")
    rows = {r["account"]: r for r in b["statements"]}
    assert set(rows) == {"ZTB-ALICE-01", "ZTB-ALICE-02", "ZTB-BOB-01"}
    for r in rows.values():
        assert dec(r["closing"]) == dec(r["opening"]) + dec(r["credits"]) - dec(r["debits"])
        assert set(r) == {"account", "customer", "currency", "opening", "credits", "debits", "closing"}
    assert call(bank, "bot", "GET", "/api/statements?month=2026-13")[0] == 400


def test_staff_status_has_no_customer_data(bank):
    s, b, _ = call(bank, "dev", "GET", "/api/status")
    assert s == 200 and b["ledger_balanced"] is True and b["unbalanced_transfers"] == 0
    assert b["limits"]["currency"] == "EUR"
    text = json.dumps(b).lower()
    assert "alice" not in text and "bob" not in text and "ztb-" not in text


@pytest.mark.parametrize("who,method,path", [
    ("dev", "GET", "/api/accounts"), ("bot", "POST", "/api/transfers"), ("alice", "GET", "/api/status"),
    ("alice", "GET", "/api/statements"), ("bob", "GET", "/chain"),
])
def test_roles_cannot_use_other_routes(bank, who, method, path):
    s, b, _ = call(bank, who, method, path, body={} if method == "POST" else None)
    assert s == 403 and b["reason"].startswith("route "), b


def test_core_rechecks_the_role(bank):
    """Defense in depth: even with the frontend's own certificate, core refuses a staff identity
    on a customer operation (a compromised frontend cannot just relabel itself)."""
    s, b, _ = call(bank, "frontend", "GET", "/accounts", to="service-a",
                   headers={"X-ZT-Actor": f"{TD}/staff/dev", "X-ZT-Role": "staff", "X-ZT-Customer": ""})
    assert s == 403 and "for role customer" in b["error"]


def test_chain_reaches_a_balanced_ledger(bank):
    s, b, _ = call(bank, "dev", "GET", "/chain?marker=m")
    assert s == 200 and b["next"]["next"]["next"]["ledger_balanced"] is True
    assert b["next"]["next"]["next"]["client_dn"].endswith("CN=service-b")


def test_api_responses_carry_security_headers(bank):
    _, _, h = call(bank, "alice", "GET", "/api/accounts")
    assert "default-src 'self'" in h["Content-Security-Policy"] and h["X-Content-Type-Options"] == "nosniff"
    assert h["Cache-Control"] == "no-store", "account data is never cached"


def test_transfers_are_logged_with_the_identity(bank):
    send(bank, "alice", "ZTB-ALICE-01", "ZTB-BOB-01", "1.00")
    time.sleep(0.3)
    log = (bank["dir"] / "service-b.log").read_text()
    assert f"done by {TD}/customer/alice: ZTB-ALICE-01 -> ZTB-BOB-01 100" in log
    # Bob's attempt on Alice's account, earlier: every layer names BOB, not just the calling service
    fe, core, ledg = ((bank["dir"] / f"{n}.log").read_text() for n in ("frontend", "service-a", "service-b"))
    assert f"denied {TD}/customer/bob GET /api/accounts/ZTB-ALICE-01/transactions: 404" in fe
    assert f"denied {TD}/customer/bob via {TD}/frontend GET /accounts/ZTB-ALICE-01/transactions: 404" in core
    assert f"denied {TD}/customer/bob via {TD}/service-a GET /ledger/accounts/ZTB-ALICE-01/entries: 404" in ledg


def test_ledger_still_balanced_after_everything(bank):
    _, b, _ = call(bank, "dev", "GET", "/api/status")
    assert b["ledger_balanced"] is True and b["unbalanced_transfers"] == 0
