"""Stage 7 — the services, end to end. Run with `make test-7` (on the i5, asks for sudo once).

The client is the WireGuard test peer (netns zt-peer on the i5) with its own certificate
(spiffe://cloud.local/client/test-peer), exactly like the i7 would be.
"""
import re
import time

import pytest
import yaml

from ztlib import BUILD
from ztlive import (PKI, ROOT_CA, VMs, ca_issued_cert, ensure_peer, expired_cert, frontend_url,
                    mtls, other_ca_cert, probe_tunnel, push, run_script, peer_creds)

pytestmark = pytest.mark.services

INV = yaml.safe_load((BUILD / "inventory.yml").read_text()) if (BUILD / "inventory.yml").exists() else {}
GROUPS = INV.get("all", {}).get("children", {})
APP = list(GROUPS.get("app", {}).get("hosts", {}))
DB = list(GROUPS.get("postgres", {}).get("hosts", {}))
TP_URI = PKI.get("identities", {}).get("client-test-peer", {}).get("uri", "")


@pytest.fixture(scope="module")
def vm():
    return VMs()


@pytest.fixture(scope="module")
def peer():
    return ensure_peer()


@pytest.fixture(scope="module")
def tp():
    return peer_creds()


@pytest.fixture(scope="module")
def chain(peer, tp):
    r = probe_tunnel(frontend_url("/chain?marker=stage7-check"), *tp)
    assert r["ok"], r
    return r["body"]


# ------------------------------------------------------------ processes --
@pytest.mark.parametrize("node", APP)
def test_service_running_unprivileged_on_policy_address(vm, node):
    h = vm(node)
    svc = h.service("zt-mtls")
    assert svc.is_running and svc.is_enabled
    users = h.check_output("ps -eo user=,args= | grep '[z]t-mtls /etc' | awk '{print $1}'").split()
    assert users and set(users) == {"zt-app"}, users
    want = sorted(s["listen"] for s in mtls(node)["serves"].values())
    got = sorted(l.split()[3] for l in h.check_output("ss -Hltn").splitlines()
                 if l.split() and any(l.split()[3].endswith(f":{s['port']}") for s in mtls(node)["serves"].values()))
    assert got == want, "bound to the policy address only, never 0.0.0.0"


@pytest.mark.parametrize("node", DB)
def test_postgres_on_data_plane_only(vm, node):
    h = vm(node)
    pg = next(iter(mtls(node)["serves"].values()))
    got = sorted(l.split()[3] for l in h.check_output("ss -Hltn").splitlines() if l.split()[3].endswith(f":{pg['port']}"))
    assert got == [pg["listen"]]
    hba = h.check_output("cat $(ls -d /etc/postgresql/*/main | tail -1)/pg_hba.conf")
    assert hba == (BUILD / "nodes" / node / "pg_hba.conf").read_text()


# ----------------------------------------------------------- end to end --
def test_chain_end_to_end(chain):
    """client -> frontend -> service-a -> service-b -> database, every hop mTLS 1.3, and each
    hop saw the caller the policy declares."""
    hops = []
    h = chain
    while h:
        hops.append(h)
        h = h.get("next")
    assert [x["node"] for x in hops] == ["frontend", "service-a", "service-b", "database"]
    assert hops[0]["peer"] == TP_URI
    assert hops[1]["peer"] == "spiffe://cloud.local/frontend"
    assert hops[2]["peer"] == "spiffe://cloud.local/service-a"
    db = hops[3]
    assert db["db_user"] == "service_b" and db["items"] == 3 and db["marker"] == "stage7-check"
    assert re.search(r"CN\s*=\s*service-b", db["client_dn"]), db["client_dn"]
    for x in hops:
        assert x["tls"] == "TLSv1.3", x


def test_server_identity_is_pinned(peer, tp):
    r = probe_tunnel(frontend_url("/health"), *tp)
    assert r["ok"] and r["server_ids"] == ["spiffe://cloud.local/frontend"] and r["tls"] == "TLSv1.3"


# ------------------------------------------------------- mTLS refusals --
@pytest.fixture(scope="module")
def bad(tmp_path_factory, vm):
    tmp = tmp_path_factory.mktemp("bad-creds")
    ca = vm(PKI["ca"]["node"])
    return {
        "no client certificate": (None, None),
        "certificate from another CA": other_ca_cert(tmp, TP_URI),
        "identity not in the allowlist": ca_issued_cert(ca, tmp, "service-a"),
        "expired certificate": expired_cert(ca, tmp, TP_URI, "client-test-peer"),
    }


@pytest.mark.parametrize("case,expect", [
    ("no client certificate", r"CERTIFICATE_REQUIRED|certificate required"),
    ("certificate from another CA", r"UNKNOWN_CA|unknown ca"),
    ("identity not in the allowlist", r"403"),
    ("expired certificate", r"CERTIFICATE_EXPIRED|certificate expired"),
])
def test_frontend_refuses(peer, vm, bad, case, expect):
    fe = vm(next(n for n in APP if "client" in str(mtls(n)["serves"])))
    since = fe.check_output("date '+%Y-%m-%d %H:%M:%S'").strip()
    time.sleep(1)
    r = probe_tunnel(frontend_url("/health"), *bad[case])
    assert not r["ok"], f"{case}: the frontend accepted it: {r}"
    verdict = f"{r['status']} {r['error']}"
    assert re.search(expect, verdict, re.I), verdict
    time.sleep(1)
    log = fe.check_output(f"journalctl -u zt-mtls --since '{since}' --no-pager")
    assert "refused 10.10.0.200" in log, f"refusal not logged: {log[-1500:]}"


def test_tls12_refused(peer, tp):
    r = probe_tunnel(frontend_url("/health"), *tp, extra=["--tls12"])
    assert not r["ok"] and r["stage"] == "handshake" and "PROTOCOL_VERSION" in (r["error"] or "").upper()


@pytest.mark.parametrize("caller,callee", [("frontend", "service-a"), ("service-a", "service-b")])
def test_inner_services_refuse_a_valid_but_unlisted_identity(vm, tp, caller, callee):
    """Even from the right VM (the firewall lets it through), a valid certificate of another
    identity (the tunnel client's) gets a 403: identity, not network position, is what counts."""
    h = vm(caller)
    f = push(h, {"c.crt": tp[0], "c.key": tp[1], "root.crt": ROOT_CA})
    try:
        listen = next(iter(mtls(callee)["serves"].values()))["listen"]
        r = run_script(h, "tls_probe.py", ["--url", f"https://{listen}/health", "--ca", f["root.crt"],
                                           "--cert", f["c.crt"], "--key", f["c.key"]])
    finally:
        h.run(f"rm -rf {f['_dir']}")
    assert r["status"] == 403 and r["tls"] == "TLSv1.3", r


# ----------------------------------------------------- database refusals --
@pytest.fixture(scope="module")
def pg_client(vm):
    """The VM allowed to reach the database (service-b), with its real files."""
    node = next(n for n in APP if any(c.get("protocol") == "postgres" for c in mtls(n)["calls"].values()))
    call = next(c for c in mtls(node)["calls"].values() if c.get("protocol") == "postgres")
    return vm(node), call


def _pg(h, call, **kw):
    host, port = call["address"].rsplit(":", 1)
    args = ["--host", host, "--port", port, "--db", call["db_name"],
            "--user", kw.pop("user", call["db_user"]), "--ca", "/etc/zt/pki/root_ca.crt"]
    for k, v in kw.items():
        args += [f"--{k}", v]
    return run_script(h, "pg_probe.py", args)


def test_db_accepts_service_b_certificate(pg_client):
    h, call = pg_client
    r = _pg(h, call, cert="/etc/zt/pki/cert.crt", key="/etc/zt/pki/cert.key")
    assert r["ok"] and r["user"] == call["db_user"] and r["tls"] == "TLSv1.3", r


def test_db_refuses_without_client_certificate(pg_client):
    h, call = pg_client
    r = _pg(h, call)
    assert not r["ok"] and re.search(r"certificate|pg_hba", r["error"], re.I), r


def test_db_refuses_plaintext(pg_client):
    h, call = pg_client
    r = _pg(h, call, sslmode="disable")
    assert not r["ok"] and re.search(r"no encryption|pg_hba", r["error"], re.I), r


def test_db_refuses_other_identity(pg_client, tp):
    """A valid certificate from our CA, but its CN is not mapped to the role (pg_ident)."""
    h, call = pg_client
    f = push(h, {"c.crt": tp[0], "c.key": tp[1]})
    try:
        r = _pg(h, call, cert=f["c.crt"], key=f["c.key"])
    finally:
        h.run(f"rm -rf {f['_dir']}")
    assert not r["ok"] and re.search(r"certificate authentication failed|pg_hba|map", r["error"], re.I), r


def test_db_refuses_other_role_with_valid_cert(pg_client):
    h, call = pg_client
    r = _pg(h, call, user="postgres", cert="/etc/zt/pki/cert.crt", key="/etc/zt/pki/cert.key")
    assert not r["ok"], "service-b's certificate must not open the superuser role"


# ---------------------------------------------- renewal reaches the service --
def test_renewed_certificate_is_served(vm, peer, tp):
    fe_name = next(n for n in APP if "client" in str(mtls(n)["serves"]))
    fe = vm(fe_name)
    serial = lambda r: int(r["server_serial"], 16)  # noqa: E731
    before = serial(probe_tunnel(frontend_url("/health"), *tp))
    fe.check_output("/usr/local/sbin/zt-cert-renew --force")
    on_disk = int(fe.check_output("openssl x509 -in /etc/zt/pki/cert.crt -noout -serial").split("=")[1], 16)
    now = None
    for _ in range(20):
        time.sleep(1)
        r = probe_tunnel(frontend_url("/health"), *tp)
        if r["ok"]:
            now = serial(r)
            if now == on_disk:
                break
    assert now == on_disk != before, "the service still serves the old certificate"
