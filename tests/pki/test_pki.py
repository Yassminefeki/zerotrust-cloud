"""Stage 6 — workload and client certificates. Run with `make test-6` (on the cloud host).

Expected identities come from build/pki/pki.json (generated from policy.yaml)."""
import json
import subprocess
import time
from datetime import datetime, timezone

import pytest
import testinfra
import yaml

from ztlib import BUILD, ROOT, run

pytestmark = pytest.mark.pki

PKI = json.loads((BUILD / "pki/pki.json").read_text()) if (BUILD / "pki/pki.json").exists() else {}
INV = yaml.safe_load((BUILD / "inventory.yml").read_text()) if (BUILD / "inventory.yml").exists() else {}
NODES = list(INV.get("all", {}).get("children", {}).get("pki", {}).get("hosts", {}))
CLIENTS = [k for k, v in PKI.get("identities", {}).items() if v["kind"] == "client"]
STEP = "$(command -v step || command -v step-cli)"
SECRETS = ROOT / "ansible/.secrets/pki"
ROOT_CA = BUILD / "pki/root_ca.crt"


@pytest.fixture(scope="module")
def vm():
    cache = {}

    def get(name):
        if name not in cache:
            cache[name] = testinfra.get_host(f"ssh://{name}", ssh_config=str(BUILD / "ssh_config"), sudo=True)
        return cache[name]
    return get


def inspect(h, path="/etc/zt/pki/cert.crt"):
    return json.loads(h.check_output(f"{STEP} certificate inspect --format json {path}"))


def hours(cert):
    nb = datetime.fromisoformat(cert["validity"]["start"].replace("Z", "+00:00"))
    na = datetime.fromisoformat(cert["validity"]["end"].replace("Z", "+00:00"))
    return (na - nb).total_seconds() / 3600, na


# ---------------------------------------------------------- workloads --
@pytest.mark.parametrize("node", NODES)
def test_workload_identity(vm, node):
    h, ident = vm(node), PKI["identities"][node]
    cert = inspect(h)
    sans = cert["extensions"]["subject_alt_name"]
    assert cert["subject"]["common_name"] == [ident["cn"]]
    assert sans.get("uniform_resource_identifiers") == [ident["uri"]], "exactly one SPIFFE ID"
    assert set(sans.get("dns_names", [])) == set(ident["dns"])
    assert set(sans.get("ip_addresses", [])) == set(ident["ips"]), "data-plane IPs only, never mgmt"
    life, end = hours(cert)
    assert 23.9 <= life <= 24.1, f"lifetime {life}h"
    assert end > datetime.now(timezone.utc)
    assert h.run(f"{STEP} certificate verify /etc/zt/pki/cert.crt --roots /etc/zt/pki/root_ca.crt").rc == 0


@pytest.mark.parametrize("node", NODES)
def test_files_and_permissions(vm, node):
    h = vm(node)
    key, crt, root = (h.file(f"/etc/zt/pki/{f}") for f in ("cert.key", "cert.crt", "root_ca.crt"))
    assert key.user == "root" and key.group == "zt-tls" and key.mode == 0o640
    assert crt.mode == 0o644 and root.mode == 0o644
    assert h.file("/etc/zt/pki").mode == 0o750
    assert root.content_string.strip() == ROOT_CA.read_text().strip(), "pinned root = the CA's root"


@pytest.mark.parametrize("node", NODES)
def test_renewal_timer(vm, node):
    h = vm(node)
    t = h.service("zt-cert-renew.timer")
    assert t.is_enabled and t.is_running
    env = h.file("/etc/zt/pki/renew.env").content_string
    assert f"EXPIRES_IN={PKI['renew_before']}" in env and f"CA_URL={PKI['ca']['url']}" in env


def test_timer_run_is_a_noop_while_fresh(vm):
    h = vm(NODES[0])
    before = inspect(h)["serial_number"]
    h.check_output("/usr/local/sbin/zt-cert-renew")
    assert inspect(h)["serial_number"] == before, "a fresh certificate must not be renewed"


def test_forced_renewal(vm):
    """Renewal over mTLS with the current certificate: new serial, same identity, same key,
    a full 24h again, and the service hook ran."""
    node = NODES[1] if len(NODES) > 1 else NODES[0]
    h = vm(node)
    old = inspect(h)
    pub_before = h.check_output("openssl pkey -in /etc/zt/pki/cert.key -pubout")
    since = h.check_output("date '+%Y-%m-%d %H:%M:%S'").strip()
    time.sleep(1)
    h.check_output("/usr/local/sbin/zt-cert-renew --force")
    new = inspect(h)
    assert new["serial_number"] != old["serial_number"]
    assert new["extensions"]["subject_alt_name"] == old["extensions"]["subject_alt_name"]
    assert 23.9 <= hours(new)[0] <= 24.1
    assert h.check_output("openssl pkey -in /etc/zt/pki/cert.key -pubout") == pub_before
    assert h.file("/etc/zt/pki/cert.crt").mode == 0o644
    log = h.check_output(f"journalctl -t zt-cert-renew --since '{since}' --no-pager")
    assert "renewed /etc/zt/pki/cert.crt" in log


def test_enrolment_token_is_single_use(vm):
    """A stolen enrolment token is worth one certificate at most: the CA refuses a replay."""
    ca = vm(PKI["ca"]["node"])
    ident = PKI["identities"][NODES[0]]
    sans = " ".join(f"--san {s}" for s in [ident["uri"], *ident["dns"], *ident["ips"]])
    tok = ca.check_output(
        f"sudo -u step env STEPPATH=/etc/step-ca {STEP} ca token {ident['cn']} {sans} "
        f"--provisioner {PKI['ca']['provisioner']} --provisioner-password-file "
        f"/etc/step-ca/secrets/provisioner-password --ca-url {PKI['ca']['url']} "
        f"--root /etc/step-ca/certs/root_ca.crt --not-after 5m").strip()
    d = "/tmp/zt-replay"
    cmd = (f"{STEP} ca certificate {ident['cn']} {d}/c.crt {d}/c.key --token '{tok}' "
           f"--ca-url {PKI['ca']['url']} --root /etc/step-ca/certs/root_ca.crt --force")
    ca.check_output(f"rm -rf {d} && mkdir -p {d}")
    since = ca.check_output("date '+%Y-%m-%d %H:%M:%S'").strip()
    first = ca.run(cmd)
    second = ca.run(cmd)
    ca.run(f"rm -rf {d}")
    assert first.rc == 0, first.stderr
    assert second.rc != 0, "the CA accepted a replayed token"
    # the client only gets a generic 401; the reason is in the CA's log
    log = ca.check_output(f"journalctl -u step-ca --since '{since}' --no-pager")
    assert "token already used" in log.lower(), log[-2000:]


# ------------------------------------------------------------ clients --
def _openssl_json(path):
    text = subprocess.run(["openssl", "x509", "-in", str(path), "-noout", "-text"],
                          capture_output=True, text=True, check=True).stdout
    end = subprocess.run(["openssl", "x509", "-in", str(path), "-noout", "-enddate"],
                         capture_output=True, text=True, check=True).stdout
    start = subprocess.run(["openssl", "x509", "-in", str(path), "-noout", "-startdate"],
                           capture_output=True, text=True, check=True).stdout
    fmt = "%b %d %H:%M:%S %Y %Z"
    nb = datetime.strptime(start.split("=", 1)[1].strip(), fmt)
    na = datetime.strptime(end.split("=", 1)[1].strip(), fmt)
    return text, (na - nb).total_seconds() / 3600


@pytest.mark.parametrize("client", CLIENTS)
def test_client_certificates(client):
    ident = PKI["identities"][client]
    d = SECRETS / client
    for f in ("client.key", "client.crt"):
        assert oct((d / f).stat().st_mode & 0o777) == "0o600", f
    text, life = _openssl_json(d / "client.crt")
    assert f"URI:{ident['uri']}" in text
    want = int(ident["lifetime"][:-1]) / (1 if ident["lifetime"].endswith("h") else 60)
    assert abs(life - want) <= 0.1, f"{client}: {life}h instead of {ident['lifetime']}"
    v = run(["openssl", "verify", "-CAfile", str(ROOT_CA), "-untrusted", str(d / "client.crt"),
             str(d / "client.crt")])
    assert v.returncode == 0, v.stderr
    key_pub = run(["openssl", "pkey", "-in", str(d / "client.key"), "-pubout"], check=True).stdout
    crt_pub = run(["openssl", "x509", "-in", str(d / "client.crt"), "-noout", "-pubkey"], check=True).stdout
    assert key_pub == crt_pub, "the certificate is for the key generated on the cloud host"


def test_client_secrets_never_tracked():
    assert run(["git", "-C", str(ROOT), "ls-files", "ansible/.secrets"]).stdout.strip() == ""
    for client in CLIENTS:
        key = (SECRETS / client / "client.key").read_text()
        body = "".join(l for l in key.splitlines() if "-----" not in l)
        assert run(["git", "-C", str(ROOT), "grep", "-qF", body[:40]]).returncode == 1


def test_actor_identities_exported_to_their_machine():
    """build/export/<peer>/<actor>/: only the actors whose `export_to` names that machine."""
    exported = {(i["export_to"], i["actor"]): cn for cn, i in PKI["identities"].items() if i.get("export_to")}
    assert exported, "at least one actor is exported (alice and dev to the remote client)"
    for (peer, actor), cn in exported.items():
        d = BUILD / "export" / peer / actor
        for f in ("client.crt", "client.key", "root_ca.crt"):
            assert oct((d / f).stat().st_mode & 0o777) == "0o600", f"{peer}/{actor}/{f}"
        assert (d / "client.crt").read_text() == (SECRETS / cn / "client.crt").read_text()
    for peer_dir in (BUILD / "export").iterdir():
        for sub in peer_dir.iterdir():
            if sub.is_dir():
                assert (peer_dir.name, sub.name) in exported, f"{sub} is not declared in the policy"
    assert not (BUILD / "export/remote-client/client.key").exists(), "old single-identity export removed"
