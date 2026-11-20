"""Stage 11 — the ZT Bank website, live. Run with `make test-11` (on the cloud host).

* the site is served by the real frontend, through the WireGuard tunnel, to every actor, with
  the strict Content-Security-Policy, exactly the files of the repository, read-only on the VM;
* cross-site request forgery is refused on the real chain (and logged with the real actor);
* the Firefox bundle of each exported actor (build/export/<peer>/<actor>/) is complete, private,
  AES-256 encrypted, opens with its password only and holds the right identity.
The browser itself is tested offline with a real Chrome (tests/unit/test_web_ui.py); the remote client
imports the bundle by hand (FIREFOX.txt).
"""
import hashlib
import json
import re
import subprocess
import time
import uuid

import pytest

from ztlib import BUILD, ROOT
from ztlive import PKI, VMs, actor_creds, actor_identity, ensure_peer, frontend_node, frontend_url, probe_tunnel

pytestmark = pytest.mark.web

WWW = ROOT / "ansible/roles/app/files/www"
SITE = sorted(p.name for p in WWW.iterdir())
# the actors who use the website (through the tunnel): every client identity with a web_url
ACTORS = sorted(i["actor"] for i in PKI.get("identities", {}).values() if i.get("web_url"))
EXPORTED = sorted((i["export_to"], i["actor"], cn) for cn, i in PKI.get("identities", {}).items() if i.get("export_to"))
SECRETS = ROOT / "ansible/.secrets/pki"


@pytest.fixture(scope="module")
def peer():
    return ensure_peer()


@pytest.fixture(scope="module")
def vm():
    return VMs()


def get(actor, path, **kw):
    return probe_tunnel(frontend_url(path), *actor_creds(actor), **kw)


# ------------------------------------------------------------------------------ the site --
@pytest.mark.parametrize("actor", ACTORS)
def test_every_actor_gets_the_site(peer, actor):
    r = get(actor, "/")
    assert r["status"] == 200, r
    assert r["headers"]["Content-Type"].startswith("text/html")
    assert r["body"] == (WWW / "index.html").read_text()
    csp = r["headers"]["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe" not in csp


def test_site_files_are_the_repository_ones(peer):
    for name in SITE:
        if name == "index.html":
            continue
        r = get("alice", f"/static/{name}")
        assert r["status"] == 200, (name, r)
        assert r["body"] == (WWW / name).read_text(), name


def test_no_certificate_no_site(peer):
    r = probe_tunnel(frontend_url("/"))
    assert r["status"] is None and r["error"], "the handshake itself is refused"


def test_site_is_read_only_on_the_frontend_and_only_there(vm):
    fe = vm(frontend_node())
    for name in SITE:
        f = fe.file(f"/usr/local/share/zt-bank/www/{name}")
        assert f.user == "root" and f.group == "root" and f.mode == 0o644, name
        assert f.sha256sum == hashlib.sha256((WWW / name).read_bytes()).hexdigest(), name
    assert fe.run("sudo -u zt-app test -w /usr/local/share/zt-bank/www/index.html").rc != 0
    for node in ("service-a", "service-b"):
        assert not vm(node).file("/usr/local/share/zt-bank/www").exists, f"no website on {node}"


# --------------------------------------------------------------- cross-site request forgery --
def balance():
    r = get("alice", "/api/accounts")
    assert r["status"] == 200, r
    return {a["id"]: a["balance"] for a in r["body"]["accounts"]}


@pytest.mark.parametrize("headers,status", [
    (["Content-Type: text/plain"], 415),
    (["Origin: https://evil.example"], 403),
    (["Sec-Fetch-Site: cross-site"], 403),
])
def test_cross_site_transfer_refused(peer, headers, status):
    before = balance()
    body = {"from": "ZTB-ALICE-01", "to": "ZTB-BOB-01", "amount": "0.01", "description": "csrf",
            "idempotency_key": uuid.uuid4().hex}
    extra = []
    for h in headers:
        extra += ["--header", h]
    r = get("alice", "/api/transfers", method="POST", data=json.dumps(body), extra=extra)
    assert r["status"] == status, r
    assert balance() == before, "nothing was paid"


def test_cross_site_refusal_logged_with_the_actor_and_never_forwarded(peer, vm):
    fe, core = vm(frontend_node()), vm("service-a")
    since = fe.check_output("date '+%Y-%m-%d %H:%M:%S'").strip()
    time.sleep(1)
    key = f"csrf-{uuid.uuid4().hex[:12]}"
    body = {"from": "ZTB-ALICE-01", "to": "ZTB-BOB-01", "amount": "0.01", "idempotency_key": key}
    r = get("alice", "/api/transfers", method="POST", data=json.dumps(body),
            extra=["--header", "Sec-Fetch-Site: cross-site"])
    assert r["status"] == 403
    time.sleep(1)
    alice = actor_identity("alice")["uri"]
    log = fe.check_output(f"journalctl -u zt-mtls --since '{since}' --no-pager")
    assert f"denied {alice} POST /api/transfers: 403 cross-site request refused" in log
    assert "POST /transfers" not in core.check_output(f"journalctl -u zt-mtls --since '{since}' --no-pager"), \
        "refused at the frontend: core banking never saw it"


# ------------------------------------------------------------------- the Firefox bundles --
def openssl(*args, inp=None):
    return subprocess.run(["openssl", *map(str, args)], input=inp, capture_output=True, text=True)


@pytest.mark.parametrize("peer_name,actor,cn", EXPORTED, ids=[f"{p}/{a}" for p, a, _ in EXPORTED])
def test_firefox_bundle_exported(peer_name, actor, cn):
    d = BUILD / "export" / peer_name / actor
    files = {"client.crt", "client.key", "root_ca.crt", f"{actor}.p12", "p12-password.txt", "FIREFOX.txt"}
    assert files <= {p.name for p in d.iterdir()}, sorted(p.name for p in d.iterdir())
    for f in files:
        assert oct((d / f).stat().st_mode & 0o777) == "0o600", f
    p12, pw = d / f"{actor}.p12", d / "p12-password.txt"
    assert (p12.read_bytes() == (SECRETS / cn / "client.p12").read_bytes())
    info = openssl("pkcs12", "-info", "-noout", "-in", p12, "-passin", f"file:{pw}")
    assert info.returncode == 0 and "AES-256-CBC" in info.stderr, info.stderr
    assert openssl("pkcs12", "-in", p12, "-passin", "pass:guess", "-nodes").returncode != 0, "wrong password opens nothing"

    out = openssl("pkcs12", "-in", p12, "-passin", f"file:{pw}", "-nodes").stdout
    leaf = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S).group(0)
    assert leaf.strip() in (d / "client.crt").read_text(), "the same certificate as client.crt (current one)"
    assert f"URI:{PKI['identities'][cn]['uri']}" in openssl("x509", "-noout", "-ext", "subjectAltName", inp=leaf).stdout
    pub = lambda *a, inp=None: openssl("pkey", "-pubout", *a, inp=inp).stdout  # noqa: E731
    assert pub(inp=out) == pub("-in", d / "client.key")
    v = openssl("verify", "-purpose", "sslclient", "-CAfile", BUILD / "pki/root_ca.crt",
                "-untrusted", d / "client.crt", d / "client.crt")
    assert v.returncode == 0, v.stdout + v.stderr

    guide = (d / "FIREFOX.txt").read_text()
    fp = openssl("x509", "-in", BUILD / "pki/root_ca.crt", "-noout", "-fingerprint", "-sha256").stdout.strip().split("=", 1)[1]
    assert PKI["identities"][cn]["web_url"] in guide and fp in guide and f"{actor}.p12" in guide


def test_web_url_of_the_guide_is_the_live_site(peer):
    url = PKI["identities"]["customer-alice"]["web_url"]
    r = probe_tunnel(url, *actor_creds("alice"))
    assert r["status"] == 200 and "ZT Bank" in r["body"]


def test_bundles_and_passwords_never_tracked():
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    assert not re.search(r"\.p12$|p12\.pass|p12-password", tracked, re.M)
