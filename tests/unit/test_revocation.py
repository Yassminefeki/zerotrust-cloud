"""Stage 13 offline: certificate revocation, end to end.

* zt-crl, the real program: fetches a CRL (signed with openssl by the test PKI's intermediate)
  over HTTPS, checks its signature, its issuer, its number (no rollback), publishes the serials;
* zt-mtls, the real services of test_bank_app.py, read that list:
  - a revoked certificate gets 403 "revoked" at once, while another certificate of the SAME
    identity still works (revocation is per certificate: the thief's copy, not Alice);
  - no list or an expired list: everybody is refused (fail-closed, 503);
  - a revoked SERVICE certificate is refused by the service that calls it (a compromised VM).
"""
import http.server
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time

import pytest

from test_bank_app import bank, call, write_revoked  # noqa: F401  (bank is a fixture)
from unit_helpers import ROOT

ZT_CRL = ROOT / "ansible/roles/app/files/zt-crl"


def serial(crt):
    return subprocess.run(["openssl", "x509", "-in", str(crt), "-noout", "-serial"],
                          capture_output=True, text=True, check=True).stdout.strip().split("=")[1]


def log(bank, node):
    return (bank["dir"] / f"{node}.log").read_text()


# ------------------------------------------------------------- zt-mtls reads the list --
@pytest.fixture
def revoked(bank):
    """Set the revocation list for one test, restore an empty fresh one afterwards."""
    path = bank["dir"] / "revoked.json"
    yield lambda *a, **k: write_revoked(path, *a, **k)
    write_revoked(path, [])


def test_stolen_copy_refused_owner_still_in(bank, revoked):
    d = bank["dir"]
    assert call(bank, "alice-stolen", "GET", "/api/me")[0] == 200, "before: the copy works like Alice"
    revoked([serial(d / "alice-stolen.crt")])
    s, out, _ = call(bank, "alice-stolen", "GET", "/api/accounts")
    assert s == 403 and "is revoked" in out["reason"], out
    assert call(bank, "alice", "GET", "/api/me")[0] == 200, "the same identity with another certificate"
    assert re.search(rf"certificate {serial(d / 'alice-stolen.crt')} of \['spiffe://cloud.local/customer/alice'\] "
                     r"is revoked", log(bank, "frontend"))


def test_revocation_takes_effect_without_restart(bank, revoked):
    pid_before = (bank["dir"] / "frontend.pid").read_text() if (bank["dir"] / "frontend.pid").exists() else None
    revoked([serial(bank["dir"] / "bob.crt")])
    assert call(bank, "bob", "GET", "/api/me")[0] == 403
    revoked([])
    assert call(bank, "bob", "GET", "/api/me")[0] == 200
    if pid_before:
        assert (bank["dir"] / "frontend.pid").read_text() == pid_before


@pytest.mark.parametrize("state", ["expired", "missing", "garbage"])
def test_fail_closed_without_a_fresh_list(bank, revoked, state):
    path = bank["dir"] / "revoked.json"
    if state == "expired":
        revoked([], next_update_in=-10)
    elif state == "missing":
        path.unlink()
    else:
        path.write_text("{not json")
        os.utime(path, None)
    s, out, _ = call(bank, "alice", "GET", "/api/me")
    assert s == 503 and "revocation status unknown" in out["reason"], out


def test_revoked_service_certificate_refused_by_its_caller(bank, revoked):
    """service-a's certificate revoked (a compromised VM): the frontend will not talk to it."""
    revoked([serial(bank["dir"] / "service-a.crt")])
    s, out, _ = call(bank, "alice", "GET", "/api/accounts")
    assert s == 502, out
    assert "certificate" in json.dumps(out) and "revoked" in json.dumps(out)
    assert call(bank, "dev", "GET", "/api/me")[0] == 200, "what does not need service-a still works"


# ----------------------------------------------------------- zt-crl builds the list --
CA_CNF = """[ca]
default_ca = zt
[zt]
database = {d}/index.txt
crlnumber = {d}/crlnumber
default_md = sha256
default_crl_days = 1
"""


def make_crl(d, revoked_crts, number, key="int.key", cert="int.crt"):
    """A real CRL, signed by the test intermediate (or another CA), DER, with a given number."""
    crl = d / "crl"
    crl.mkdir(exist_ok=True)
    (crl / "ca.cnf").write_text(CA_CNF.format(d=crl))
    lines = []
    for c in revoked_crts:
        lines.append(f"R\t300101000000Z\t{time.strftime('%y%m%d%H%M%SZ', time.gmtime())}\t{serial(c)}\tunknown\t/CN=x")
    (crl / "index.txt").write_text("".join(l + "\n" for l in lines))
    (crl / "crlnumber").write_text(f"{number:02X}\n")
    subprocess.run(["openssl", "ca", "-gencrl", "-config", str(crl / "ca.cnf"), "-keyfile", str(d / key),
                    "-cert", str(d / cert), "-out", str(crl / "crl.pem")], check=True, capture_output=True)
    subprocess.run(["openssl", "crl", "-in", str(crl / "crl.pem"), "-outform", "DER", "-out", str(crl / "crl.der")],
                   check=True, capture_output=True)
    return (crl / "crl.der").read_bytes()


@pytest.fixture
def crl_server(bank):
    """A stand-in for step-ca's /1.0/crl, over TLS with a certificate of our PKI."""
    d = bank["dir"]
    state = {"der": b""}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/pkix-crl")
            self.send_header("Content-Length", str(len(state["der"])))
            self.end_headers()
            self.wfile.write(state["der"])

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.10", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "frontend.crt", d / "frontend.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    pki = d / "zt-crl"
    pki.mkdir(exist_ok=True)
    (pki / "root_ca.crt").write_text((d / "root.crt").read_text())
    (pki / "cert.crt").write_text((d / "service-a.crt").read_text())          # leaf + intermediate
    out = pki / "revoked.json"
    conf = pki / "mtls.json"
    conf.write_text(json.dumps({"revocation": {"crl_url": f"https://127.0.0.10:{srv.server_port}/1.0/crl",
                                               "file": str(out)}}))

    def run():
        return subprocess.run([sys.executable, str(ZT_CRL), str(conf)], capture_output=True, text=True,
                              env=dict(os.environ, ZT_PKI=str(pki)))
    yield state, run, out
    srv.shutdown()


def test_zt_crl_publishes_the_revoked_serials(bank, crl_server):
    state, run, out = crl_server
    d = bank["dir"]
    state["der"] = make_crl(d, [d / "alice-stolen.crt", d / "bob.crt"], number=5)
    r = run()
    assert r.returncode == 0, r.stderr
    got = json.loads(out.read_text())
    assert set(got["revoked"]) == {serial(d / "alice-stolen.crt").lstrip("0"), serial(d / "bob.crt").lstrip("0")}
    assert got["crl_number"] == 5 and got["next_update"] > time.time() + 3600
    assert oct(out.stat().st_mode & 0o777) == "0o644"


def test_zt_crl_refuses_an_older_list(bank, crl_server):
    """An attacker replaying yesterday's CRL (before the revocation) must not un-revoke anything."""
    state, run, out = crl_server
    d = bank["dir"]
    state["der"] = make_crl(d, [d / "alice-stolen.crt"], number=7)
    assert run().returncode == 0
    state["der"] = make_crl(d, [], number=3)
    r = run()
    assert r.returncode == 1 and "went backwards" in r.stderr
    assert json.loads(out.read_text())["crl_number"] == 7, "the newer list is kept"


def test_zt_crl_refuses_a_list_signed_by_someone_else(bank, crl_server):
    state, run, out = crl_server
    d = bank["dir"]
    subprocess.run(["bash", "-c", "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out evil.key 2>/dev/null"
                    " && openssl req -x509 -new -key evil.key -subj /CN=int -days 1 -out evil.crt"
                    " -addext keyUsage=critical,keyCertSign,cRLSign"], cwd=d, check=True, capture_output=True)
    state["der"] = make_crl(d, [], number=99, key="evil.key", cert="evil.crt")    # same name, other key
    if out.exists():
        out.unlink()
    r = run()
    assert r.returncode == 1 and "does not verify" in r.stderr
    assert not out.exists()


def test_end_to_end_crl_to_refusal(bank, crl_server):
    """The list zt-crl builds from a real CRL is the list the services enforce."""
    state, run, out = crl_server
    d = bank["dir"]
    state["der"] = make_crl(d, [d / "alice-stolen.crt"], number=11)
    assert run().returncode == 0
    target = d / "revoked.json"
    target.write_text(out.read_text())
    os.utime(target, None)
    try:
        assert call(bank, "alice-stolen", "GET", "/api/me")[0] == 403
        assert call(bank, "alice", "GET", "/api/me")[0] == 200
    finally:
        write_revoked(target, [])
