"""Stage 0 — the mTLS service (ansible/roles/app/files/zt-mtls), offline.

A throwaway PKI (openssl) and three instances (frontend -> service-a -> service-b) on 127.0.0.x,
configured exactly like the generated mtls.json. Checks the chain and the four refusals the
requirements ask for, plus TLS 1.2, source addresses and server identity pinning.
"""
import json
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "ansible/roles/app/files/zt-mtls"
PROBE = ROOT / "tests/tls_probe.py"
TD = "spiffe://cloud.local"

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")

SH = r"""
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
k evil.key; openssl req -x509 -new -key evil.key -subj /CN=evil -days 2 -out evil.crt \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
leaf(){ k "$1.key"; openssl req -new -key "$1.key" -subj "/CN=$1" -out "$1.csr"
  SAN="$2" openssl x509 -req -in "$1.csr" -CA "$3.crt" -CAkey "$3.key" -days 1 -extfile ext.cnf -extensions leaf -out "$1.leaf" 2>/dev/null
  cat "$1.leaf" "$3.crt" > "$1.crt"; }
leaf frontend  "URI:$TD/frontend,IP:127.0.0.10"  int
leaf service-a "URI:$TD/service-a,IP:127.0.0.11" int
leaf service-b "URI:$TD/service-b,IP:127.0.0.12" int
leaf peer      "URI:$TD/client/test-peer,DNS:client-test-peer" int
leaf other-id  "URI:$TD/service-a,DNS:service-a" int
leaf foreign   "URI:$TD/client/test-peer" evil
# expired: signed by the real intermediate, validity entirely in the past (openssl ca)
mkdir -p db && : > db/index.txt && echo 01 > db/serial
cat > ca.cnf <<EOF
[ca]
default_ca=d
[d]
database=db/index.txt
serial=db/serial
new_certs_dir=db
default_md=sha256
policy=p
unique_subject=no
[p]
commonName=supplied
[x]
basicConstraints=CA:FALSE
extendedKeyUsage=clientAuth
subjectAltName=URI:$TD/client/test-peer
EOF
k expired.key; openssl req -new -key expired.key -subj /CN=client-test-peer -out expired.csr
openssl ca -batch -config ca.cnf -cert int.crt -keyfile int.key -in expired.csr -out expired.leaf \
  -startdate 20200101000000Z -enddate 20200102000000Z -extensions x -notext 2>/dev/null
cat expired.leaf int.crt > expired.crt
"""


def free_port(ip):
    s = socket.socket()
    s.bind((ip, 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def net(tmp_path_factory):
    d = tmp_path_factory.mktemp("mtls")
    subprocess.run(["bash", "-c", SH], cwd=d, check=True, env={"TD": TD, "PATH": "/usr/bin:/bin"},
                   capture_output=True)
    ips = {"frontend": "127.0.0.10", "service-a": "127.0.0.11", "service-b": "127.0.0.12"}
    ports = {n: free_port(ip) for n, ip in ips.items()}
    addr = {n: f"{ips[n]}:{ports[n]}" for n in ips}
    confs = {
        "frontend": {"serves": {"https": {"allowed_ids": [f"{TD}/client/i7", f"{TD}/client/test-peer"],
                                          "allowed_sources": ["127.0.0.0/8"]}},
                     "calls": {"api-a": {"address": addr["service-a"], "expected_id": f"{TD}/service-a"}}},
        "service-a": {"serves": {"api-a": {"allowed_ids": [f"{TD}/frontend"], "allowed_sources": ["127.0.0.1"]}},
                      "calls": {"api-b": {"address": addr["service-b"], "expected_id": f"{TD}/service-b"}}},
        "service-b": {"serves": {"api-b": {"allowed_ids": [f"{TD}/service-a"], "allowed_sources": ["127.0.0.1"]}},
                      "calls": {}},
    }
    procs = []
    for n, c in confs.items():
        (d / n).mkdir()
        for src, dst in (("crt", "cert.crt"), ("key", "cert.key")):
            shutil.copy(d / f"{n}.{src}", d / n / dst)
        shutil.copy(d / "root.crt", d / n / "root_ca.crt")
        for s in c["serves"].values():
            s.update(listen=addr[n], port=ports[n], protocol="https")
        for s in c["calls"].values():
            s["protocol"] = "https"
        (d / n / "mtls.json").write_text(json.dumps(dict(c, node=n, identity=f"{TD}/{n}", min_tls="1.3")))
        procs.append(subprocess.Popen([sys.executable, str(SERVICE), str(d / n / "mtls.json"), str(d / n)],
                                      stdout=open(d / f"{n}.log", "w"), stderr=subprocess.STDOUT))
    for n in ips:
        for _ in range(50):
            try:
                socket.create_connection((ips[n], ports[n]), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
    yield {"dir": d, "addr": addr}
    for p in procs:
        p.terminate()
        p.wait(5)


def probe(net, name, path="/health", creds=None, extra=()):
    d = net["dir"]
    cmd = [sys.executable, str(PROBE), "--url", f"https://{net['addr'][name]}{path}", "--ca", str(d / "root.crt")]
    if creds:
        cmd += ["--cert", str(d / f"{creds}.crt"), "--key", str(d / f"{creds}.key")]
    return json.loads(subprocess.run(cmd + list(extra), capture_output=True, text=True, check=True).stdout)


def test_chain(net):
    r = probe(net, "frontend", "/chain?marker=m1", "peer")
    assert r["ok"], r
    b = r["body"]
    assert (b["peer"], b["next"]["peer"], b["next"]["next"]["peer"]) == (
        f"{TD}/client/test-peer", f"{TD}/frontend", f"{TD}/service-a")
    assert {b["tls"], b["next"]["tls"], b["next"]["next"]["tls"]} == {"TLSv1.3"}
    assert b["next"]["next"]["marker"] == "m1"


@pytest.mark.parametrize("creds,expect", [
    (None, "CERTIFICATE_REQUIRED"),          # no client certificate
    ("foreign", "UNKNOWN_CA"),               # signed by another CA
    ("expired", "CERTIFICATE_EXPIRED"),      # right CA, right ID, past validity
])
def test_handshake_refusals(net, creds, expect):
    r = probe(net, "frontend", creds=creds)
    assert not r["ok"] and r["status"] is None and expect in (r["error"] or ""), r


def test_identity_not_in_allowlist_is_403(net):
    r = probe(net, "frontend", creds="other-id")
    assert r["status"] == 403 and "not allowed" in r["body"]["reason"]


def test_inner_service_refuses_the_client_identity(net):
    assert probe(net, "service-a", creds="peer")["status"] == 403


def test_tls12_refused(net):
    r = probe(net, "frontend", creds="peer", extra=["--tls12"])
    assert not r["ok"] and r["stage"] == "handshake"


def test_source_address_enforced(net):
    d = net["dir"]
    ip, port = net["addr"]["service-a"].rsplit(":", 1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(d / "root.crt")
    ctx.load_cert_chain(d / "frontend.crt", d / "frontend.key")   # right identity, wrong address
    s = socket.create_connection((ip, int(port)), source_address=("127.0.0.99", 0), timeout=5)
    with ctx.wrap_socket(s, server_hostname=ip) as t:
        t.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b" 403 " in t.recv(200)


def test_next_hop_identity_is_pinned(net, tmp_path):
    """frontend configured to call service-a, but service-b answers at that address -> 502."""
    d = net["dir"]
    conf = json.loads((d / "frontend/mtls.json").read_text())
    conf["calls"]["api-a"]["address"] = net["addr"]["service-b"]
    port = free_port("127.0.0.10")
    conf["serves"]["https"].update(listen=f"127.0.0.10:{port}", port=port)
    (tmp_path / "mtls.json").write_text(json.dumps(conf))
    p = subprocess.Popen([sys.executable, str(SERVICE), str(tmp_path / "mtls.json"), str(d / "frontend")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.10", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        r = probe(dict(net, addr={"x": f"127.0.0.10:{port}"}), "x", "/chain?marker=z", "peer")
    finally:
        p.terminate()
        p.wait(5)
    assert r["status"] == 502 and "expected spiffe://cloud.local/service-a" in r["body"]["error"]


def test_refusals_are_logged(net):
    test_handshake_refusals(net, None, "CERTIFICATE_REQUIRED")
    time.sleep(0.3)
    assert "refused 127.0.0.1: tls handshake" in (net["dir"] / "frontend.log").read_text()
