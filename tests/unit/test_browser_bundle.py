"""Stage 11 offline: the Firefox bundle built by ansible/certs.yml, run exactly as written there.

The shell of the task is taken from the playbook and run on a throw-away PKI shaped like the
real one (root -> intermediate -> actor). Then:
* the bundle is AES-256 encrypted, opens with its password only, holds the actor's key + chain;
* with NSS tools (libnss3-tools, the crypto library of Firefox): Firefox's own importer accepts
  it, and NSS validates the certificate as an SSL *client* certificate under the bank's root;
* rebuilt only when the certificate changes; the import guide names the right URL and root.
"""
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from unit_helpers import PKI_SH, TD
from unit_helpers import ROOT  # noqa: E402

jinja2 = pytest.importorskip("jinja2")

ALICE = {"key": "customer-alice", "value": {"actor": "alice", "name": "Alice Martin", "role": "customer",
                                             "uri": f"{TD}/customer/alice", "lifetime": "24h", "export_to": "remote-client",
                                             "web_url": "https://10.20.0.10:8443/"}}
NICK = "ZT Bank - Alice Martin (customer)"


def task(name):
    plays = yaml.safe_load((ROOT / "ansible/certs.yml").read_text())
    for play in plays:
        for t in play.get("tasks", []):
            if t["name"].startswith(name):
                return t
    raise KeyError(name)


def render(text, **v):
    env = jinja2.Environment(keep_trailing_newline=True)
    env.filters["quote"] = lambda s: shlex.quote(str(s))
    return env.from_string(text).render(**v)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("bundle")
    subprocess.run(["bash", "-c", PKI_SH], cwd=d, check=True, capture_output=True, env={"TD": TD, "PATH": os.environ["PATH"]})
    sec = d / "secrets"
    (sec / "customer-alice").mkdir(parents=True)
    shutil.copy(d / "alice.crt", sec / "customer-alice/client.crt")    # leaf + intermediate, like step ca sign
    shutil.copy(d / "alice.key", sec / "customer-alice/client.key")
    return d, sec / "customer-alice"


def run_task(name, sec_dir):
    t = task(name)
    cmd = t["ansible.builtin.shell"]
    script = render(cmd if isinstance(cmd, str) else cmd["cmd"], pki_secrets=str(sec_dir.parent), item=ALICE)
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@pytest.fixture(scope="module")
def bundle(pki):
    d, a = pki
    run_task("Browser bundle password", a)
    assert run_task("Browser bundle (PKCS#12", a) == "built"
    return d, a


def test_password_random_private_and_kept(bundle):
    _, a = bundle
    pw = (a / "p12.pass").read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{24}", pw)
    assert oct((a / "p12.pass").stat().st_mode & 0o777) == "0o600"
    run_task("Browser bundle password", a)        # generated once: never replaced (the bundle would not open)
    assert (a / "p12.pass").read_text().strip() == pw


def test_bundle_is_private_and_aes256(bundle):
    _, a = bundle
    p12 = a / "client.p12"
    assert oct(p12.stat().st_mode & 0o777) == "0o600"
    info = subprocess.run(["openssl", "pkcs12", "-info", "-in", p12, "-noout", "-passin", f"file:{a}/p12.pass"],
                          capture_output=True, text=True)
    assert info.returncode == 0, info.stderr
    assert "AES-256-CBC" in info.stderr and "RC2" not in info.stderr and "3DES" not in info.stderr, info.stderr


def test_bundle_holds_the_actor_key_and_chain(bundle):
    _, a = bundle
    out = subprocess.run(["openssl", "pkcs12", "-in", a / "client.p12", "-passin", f"file:{a}/p12.pass", "-nodes"],
                         capture_output=True, text=True, check=True).stdout
    certs = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    assert len(certs) == 2, "leaf + intermediate (the root is imported separately, as an authority)"
    assert f"friendlyName: {NICK}" in out
    leaf = subprocess.run(["openssl", "x509", "-noout", "-ext", "subjectAltName"], input=certs[0],
                          capture_output=True, text=True).stdout
    assert f"URI:{TD}/customer/alice" in leaf
    pub = lambda args, inp=None: subprocess.run(args, input=inp, capture_output=True, text=True, check=True).stdout  # noqa: E731
    assert pub(["openssl", "pkey", "-pubout"], out) == pub(["openssl", "pkey", "-pubout", "-in", a / "client.key"])


def test_wrong_password_opens_nothing(bundle):
    _, a = bundle
    r = subprocess.run(["openssl", "pkcs12", "-in", a / "client.p12", "-passin", "pass:guess", "-nodes"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "PRIVATE KEY" not in r.stdout


def test_rebuilt_only_when_the_certificate_changes(bundle):
    _, a = bundle
    assert run_task("Browser bundle (PKCS#12", a) == "ok"
    t = (a / "client.crt").stat().st_mtime
    os.utime(a / "client.p12", (t - 60, t - 60))        # = a certificate renewed after the bundle was made
    assert run_task("Browser bundle (PKCS#12", a) == "built"
    assert run_task("Browser bundle (PKCS#12", a) == "ok"


nss = pytest.mark.skipif(not shutil.which("pk12util"), reason="needs libnss3-tools (Firefox's crypto library)")


@nss
def test_firefox_crypto_imports_it_and_trusts_it_for_client_auth(bundle, tmp_path):
    d, a = bundle
    db = f"sql:{tmp_path}"
    subprocess.run(["certutil", "-N", "-d", db, "--empty-password"], check=True, capture_output=True)
    # step 2 of the guide: the root, trusted to identify websites ("C" = trusted CA for SSL)
    subprocess.run(["certutil", "-A", "-d", db, "-n", "ZT root", "-t", "C,,", "-i", d / "root.crt"],
                   check=True, capture_output=True)
    # step 3: the bundle, with its password — what Firefox's "Import..." button does
    r = subprocess.run(["pk12util", "-i", a / "client.p12", "-d", db, "-w", a / "p12.pass"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    listed = subprocess.run(["certutil", "-L", "-d", db], capture_output=True, text=True, check=True).stdout
    assert NICK in listed
    keys = subprocess.run(["certutil", "-K", "-d", db], capture_output=True, text=True, check=True).stdout
    assert NICK in keys, "the private key came with it"
    # with that root, Firefox trusts the bank's server certificate (SSL server usage)
    subprocess.run(["certutil", "-A", "-d", db, "-n", "bank", "-t", ",,", "-i", d / "frontend.leaf"],
                   check=True, capture_output=True)
    v = subprocess.run(["certutil", "-V", "-d", db, "-n", "bank", "-u", "V"], capture_output=True, text=True)
    assert "certificate is valid" in v.stdout, v.stdout + v.stderr
    # and what the bank checks on its side: the client certificate chains to the root for client auth
    v = subprocess.run(["openssl", "verify", "-purpose", "sslclient", "-CAfile", d / "root.crt",
                        "-untrusted", a / "client.crt", a / "client.crt"], capture_output=True, text=True)
    assert v.returncode == 0, v.stdout + v.stderr


@nss
def test_firefox_crypto_refuses_a_wrong_password(bundle, tmp_path):
    _, a = bundle
    db = f"sql:{tmp_path}"
    subprocess.run(["certutil", "-N", "-d", db, "--empty-password"], check=True, capture_output=True)
    bad = tmp_path / "bad.pass"
    bad.write_text("guess\n")
    r = subprocess.run(["pk12util", "-i", a / "client.p12", "-d", db, "-w", bad], capture_output=True, text=True)
    assert r.returncode != 0


def test_import_guide(bundle):
    d, _ = bundle
    fp = subprocess.run(["openssl", "x509", "-in", d / "root.crt", "-noout", "-fingerprint", "-sha256"],
                        capture_output=True, text=True, check=True).stdout.strip().split("=", 1)[1]
    text = render((ROOT / "ansible/templates/firefox-import.txt.j2").read_text(), item=ALICE, fingerprint=fp)
    assert "https://10.20.0.10:8443/" in text and fp in text and "alice.p12" in text and NICK in text
    assert "24h" in text and "your accounts" in text
    assert "{{" not in text and "{%" not in text


def test_bundle_and_password_are_exported_never_committed():
    certs = (ROOT / "ansible/certs.yml").read_text()
    assert "i.actor ~ '.p12'" in certs and "'p12-password.txt'" in certs
    ignored = (ROOT / ".gitignore").read_text()
    assert "build/" in ignored and ("ansible/.secrets" in ignored or ".secrets" in ignored)


def test_web_url_is_the_frontend_from_the_policy(build):
    import json
    pki_json = json.loads((Path(build) / "pki/pki.json").read_text())
    alice = pki_json["identities"]["customer-alice"]
    assert alice["web_url"] == "https://10.20.0.10:8443/" and alice["name"] == "Alice Martin"
    assert pki_json["identities"]["staff-dev"]["name"] == "dev"
