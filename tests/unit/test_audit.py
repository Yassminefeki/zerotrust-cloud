"""Stage 13 — `make audit`: the log parsers and the report, offline (the collection runs over SSH)."""
import importlib.util
import time
from collections import Counter

from unit_helpers import ROOT

spec = importlib.util.spec_from_file_location("zt_audit", ROOT / "tools/zt-audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

A = "spiffe://cloud.local/customer/alice"
B = "spiffe://cloud.local/customer/bob"
FE = "spiffe://cloud.local/frontend"
MTLS = [
    f'zt-mtls 10.10.0.2 {A} "GET /api/me HTTP/1.1" 200 -',
    f'zt-mtls 10.10.0.2 {A} "GET /api/accounts HTTP/1.1" 200 -',
    f'zt-mtls 10.10.0.200 {B} "GET /api/status HTTP/1.1" 403 -',
    f"zt-mtls refused 10.10.0.200: route status (GET /api/status) not allowed for {B}",
    f"zt-mtls refused 10.10.0.200: certificate 62C2BB79B0AB of ['{A}'] is revoked",
    f"zt-mtls refused 10.10.0.200: certificate 062C2BB79B0AB of ['{A}'] is revoked",
    "zt-mtls refused 10.10.0.200: tls handshake: [SSL: TLSV1_ALERT_UNKNOWN_CA] unknown ca",
    f"zt-mtls denied {B} GET /api/accounts/ZTB-ALICE-01/transactions: 404 account not found",
    f"zt-mtls denied {B} via {FE} GET /accounts/ZTB-ALICE-01/transactions: 404 account not found",
    "zt-mtls rate-limited spiffe://cloud.local/bot/statements: above 20 requests/min, retry after 3s",
    "zt-mtls next hop refused on GET /api/accounts: certificate 1F of spiffe://cloud.local/service-a is revoked",
    "zt-mtls serving https on 10.20.0.10:8443 as ...",
]


def test_mtls_journal_is_counted_per_identity_and_reason():
    m = audit.parse_mtls(MTLS)
    assert m["requests"] == Counter({A: 2, B: 1})
    assert m["status"]["403"] == 1
    assert m["revoked_attempts"] == Counter({("62C2BB79B0AB", f"['{A}']"): 2})
    assert m["refused"][("10.10.0.200", f"certificate <serial> of ['{A}'] is revoked")] == 2
    assert (B, "GET /api/accounts/ZTB-ALICE-01/transactions", "404", "account not found") in m["denied"]
    assert (B, "GET /accounts/ZTB-ALICE-01/transactions", "404", "account not found") in m["denied"]
    assert m["rate_limited"]["spiffe://cloud.local/bot/statements"] == 1
    assert list(m["next_hop"])[0][0] == "/api/accounts"


def test_drop_logs_and_ca_requests():
    d = audit.parse_drops([
        "zt-drop-forward: IN=wg0 OUT=dmz0 SRC=10.10.0.200 DST=10.20.0.10 LEN=60 PROTO=TCP SPT=40000 DPT=22 SYN",
        "zt-drop-forward: IN=wg0 OUT=dmz0 SRC=10.10.0.200 DST=10.20.0.10 LEN=60 PROTO=TCP SPT=40001 DPT=22 SYN",
        "zt-drop-input: IN=wan0 SRC=192.168.122.1 DST=192.168.122.10 LEN=84 PROTO=ICMP TYPE=8",
        "unrelated kernel line"])
    assert d[("forward", "10.10.0.200", "10.20.0.10:22", "TCP")] == 2
    assert d[("input", "192.168.122.1", "192.168.122.10", "ICMP")] == 1
    c = audit.parse_ca(['time="x" level=info method=POST path=/1.0/sign status=201',
                        'time="x" level=info method=POST path=/1.0/revoke status=200',
                        'time="x" level=info method=POST path=/1.0/renew status=401'])
    assert c == Counter({("/1.0/sign", "201"): 1, ("/1.0/revoke", "200"): 1, ("/1.0/renew", "401"): 1})


def test_interval_and_db_parsing():
    assert audit.interval("2 hours ago") == "2 hours" and audit.interval("30 min ago") == "30 minutes"
    assert audit.interval("yesterday; DROP TABLE x") == "24 hours"     # never pasted into SQL as is
    db = audit.parse_db("A|spiffe://x|transfer|3\nL|2026-11-20 10:00:00|spiffe://x|transfer|{\"a\": 1}\n"
                        "B|0|12\nT|6|2\n")
    assert db["by_actor"] == [("spiffe://x", "transfer", 3)] and db["ledger_sum"] == 0 and db["transfers"] == 6


def data(**over):
    now = time.time()
    d = {"since": "24 hours ago", "unreachable": [],
         "nodes": {"frontend": {"mtls": audit.parse_mtls(MTLS), "drops": Counter(),
                                "crl": {"crl_number": 3, "revoked": ["62C2BB79B0AB"], "next_update": now + 3600,
                                        "fetched_at": now - 30},
                                "cert": {"serial": "AB", "notAfter": "Nov 21 10:00:00 2026 GMT"}},
                   "service-a": {"mtls": audit.parse_mtls([]), "drops": Counter(),
                                 "crl": {"crl_number": 3, "revoked": ["62C2BB79B0AB"], "next_update": now + 3600,
                                         "fetched_at": now - 20}, "cert": {}}},
         "db": audit.parse_db("B|0|4\nT|2|0\n"), "clients": [],
         "attacks.json": None, "remote-client-report.json": None}
    d.update(over)
    return d


def test_clean_report_has_no_finding():
    md, findings = audit.render(data())
    assert findings == [] and "none: every check above is as expected" in md
    assert "62C2BB79B0AB" in md and A in md and "balanced" in md


def test_findings():
    d = data()
    d["nodes"]["service-a"]["crl"]["next_update"] = time.time() - 1
    d["nodes"]["service-a"]["crl"]["crl_number"] = 2
    d["db"]["ledger_sum"] = 5
    d["remote-client-report.json"] = {"when": "now", "machine": "rc", "results": [
        {"id": "B3", "title": "x", "verdict": "BREACH"}]}
    _, f = audit.render(d)
    assert any("STALE" in x or "past its next update" in x for x in f)
    assert any("different CRLs" in x for x in f)
    assert "the ledger is not balanced" in f and "remote attack B3: BREACH" in f


def test_only_services_that_enforce_revocation_are_checked_for_a_list(build, monkeypatch):
    """gateway, database and the CA have no HTTPS mTLS service: no CRL expected there."""
    monkeypatch.setattr(audit, "BUILD", build)
    assert audit.crl_nodes() == ["frontend", "service-a", "service-b"]
    d = data()
    d["nodes"]["gateway"] = {"drops": Counter(), "cert": {}}      # no "crl" key: not checked
    _, findings = audit.render(d)
    assert findings == []
