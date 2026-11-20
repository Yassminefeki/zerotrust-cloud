"""Stage 3 — internal CA (step-ca on VM6). Run with `make test-3` (on the cloud host).

Expected values come from build/pki/pki.json (generated from policy.yaml)."""
import hashlib
import json
import subprocess
from datetime import datetime

import pytest
import testinfra

from ztlib import BUILD, ROOT, run

pytestmark = pytest.mark.ca

PKI = json.loads((BUILD / "pki" / "pki.json").read_text()) if (BUILD / "pki" / "pki.json").exists() else None
STEP = "$(command -v step || command -v step-cli)"


@pytest.fixture(scope="module")
def pki():
    if PKI is None:
        pytest.exit("run `make gen` first", returncode=2)
    return PKI


@pytest.fixture(scope="module")
def ca(pki):
    return testinfra.get_host(f"ssh://{pki['ca']['node']}", ssh_config=str(BUILD / "ssh_config"), sudo=True)


def step_as_ca(ca, args):
    """Run the step CLI on the CA VM as the step user (secrets are readable only by it)."""
    return ca.run(f"sudo -u step env STEPPATH=/etc/step-ca {STEP} {args}")


def token(ca, pki, cn, sans):
    """One-time JWK token minted on the CA (the provisioner password never leaves the CA)."""
    c = pki["ca"]
    san_args = " ".join(f"--san {s}" for s in sans)
    return step_as_ca(ca, f"ca token {cn} {san_args} --provisioner {c['provisioner']} "
                          f"--provisioner-password-file /etc/step-ca/secrets/provisioner-password "
                          f"--ca-url {c['url']} --root /etc/step-ca/certs/root_ca.crt")


def issue(ca, pki, cn, sans, cert_flags=""):
    """Request a certificate with a fresh token. `cert_flags` go to `step ca certificate`
    (e.g. --not-after 48h is the CERTIFICATE lifetime; on `step ca token` it would be the token's)."""
    tok = token(ca, pki, cn, sans)
    assert tok.rc == 0, f"token minting must work, the CA is what must refuse: {tok.stderr}"
    d = f"/tmp/zt-probe-{cn}"
    return ca.run(f"rm -rf {d} && mkdir -p {d} && {STEP} ca certificate {cn} {d}/c.crt {d}/c.key "
                  f"--token '{tok.stdout.strip()}' --ca-url {pki['ca']['url']} "
                  f"--root /etc/step-ca/certs/root_ca.crt {cert_flags} --force "
                  f"&& {STEP} certificate inspect --format json {d}/c.crt")


# -------------------------------------------------------------- service --
def test_step_ca_running_as_unprivileged_user(ca):
    svc = ca.service("step-ca")
    assert svc.is_running and svc.is_enabled
    user = ca.check_output("ps -o user= -C step-ca").split()
    assert user and set(user) == {"step"}, user


def test_listens_on_mgmt_only(ca, pki):
    listeners = ca.check_output("ss -Hltn").split("\n")
    ports = [l.split()[3] for l in listeners if l.split() and l.split()[3].endswith(f":{pki['ca']['port']}")]
    assert ports == [f"{pki['ca']['ip']}:{pki['ca']['port']}"], ports


def test_secrets_are_private(ca):
    for f in ("secrets/password", "secrets/provisioner-password", "secrets/root_ca_key",
              "secrets/intermediate_ca_key"):
        st = ca.file(f"/etc/step-ca/{f}")
        assert st.exists and st.user == "step" and st.mode & 0o077 == 0, f"{f}: {oct(st.mode)} {st.user}"


def test_config_from_policy(ca, pki):
    cfg = json.loads(ca.check_output("cat /etc/step-ca/config/ca.json"))
    claims = cfg["authority"]["claims"]
    assert claims["defaultTLSCertDuration"] == pki["lifetime"] == claims["maxTLSCertDuration"]
    assert claims["allowRenewalAfterExpiry"] is False
    assert cfg["authority"]["policy"]["x509"] == pki["x509_policy"]
    assert cfg["tls"]["minVersion"] == 1.3


# ------------------------------------------------------------ from the cloud host --
def test_root_exported_and_fingerprint_matches(ca):
    root = BUILD / "pki" / "root_ca.crt"
    fp_file = BUILD / "pki" / "root_ca.fingerprint"
    assert root.exists() and fp_file.exists()
    der = subprocess.run(["openssl", "x509", "-in", str(root), "-outform", "DER"],
                         capture_output=True, check=True).stdout
    assert hashlib.sha256(der).hexdigest() == fp_file.read_text().strip()
    on_ca = ca.check_output(f"{STEP} certificate fingerprint /etc/step-ca/certs/root_ca.crt").strip()
    assert on_ca == fp_file.read_text().strip()


def test_health_over_tls13_with_pinned_root(ca, pki):
    """Run on the CA VM: after stage 4 the cloud host may only SSH to the VMs (policy: admin-ssh),
    so it cannot reach :9000 itself. The root used here is the one pinned on the cloud host."""
    url = f"{pki['ca']['url']}/health"
    r = ca.run(f"curl -s --tlsv1.3 --tls-max 1.3 --cacert /etc/step-ca/certs/root_ca.crt {url}")
    assert r.rc == 0 and json.loads(r.stdout) == {"status": "ok"}, r.stderr


def test_tls12_refused(ca, pki):
    r = ca.run(f"openssl s_client -connect {pki['ca']['ip']}:{pki['ca']['port']} -tls1_2 </dev/null")
    assert r.rc != 0 or "Cipher is (NONE)" in r.stdout


def test_secrets_never_tracked_by_git():
    tracked = run(["git", "-C", str(ROOT), "ls-files", "ansible/.secrets", "build"]).stdout.strip()
    assert tracked == ""
    for p in ("ansible/.secrets/ca_key_password", "build/pki/root_ca.crt"):
        assert run(["git", "-C", str(ROOT), "check-ignore", "-q", p]).returncode == 0, p
    assert oct((ROOT / "ansible/.secrets/ca_key_password").stat().st_mode & 0o777) == "0o600"


# --------------------------------------------------------------- issuance --
def test_issue_24h_spiffe_cert(ca, pki):
    ident = pki["identities"]["frontend"]
    r = issue(ca, pki, ident["cn"], [ident["uri"], *ident["dns"], *ident["ips"]])
    assert r.rc == 0, r.stderr
    cert = json.loads(r.stdout)
    sans = cert["extensions"]["subject_alt_name"]
    assert sans.get("uniform_resource_identifiers") == [ident["uri"]]
    assert set(sans.get("ip_addresses", [])) == set(ident["ips"])
    assert cert["subject"]["common_name"] == [ident["cn"]]
    nb = datetime.fromisoformat(cert["validity"]["start"].replace("Z", "+00:00"))
    na = datetime.fromisoformat(cert["validity"]["end"].replace("Z", "+00:00"))
    hours = (na - nb).total_seconds() / 3600
    assert 23.9 <= hours <= 24.1, f"lifetime {hours}h"
    chain = ca.run(f"{STEP} certificate verify /tmp/zt-probe-frontend/c.crt --roots /etc/step-ca/certs/root_ca.crt")
    assert chain.rc == 0, chain.stderr


@pytest.mark.parametrize("case,cn,sans,cert_flags,reason", [
    ("foreign trust domain", "frontend", ["spiffe://evil.example/frontend"], "",
     'uri name "spiffe://evil.example/frontend" not allowed'),
    ("name not in policy", "intruder", ["spiffe://cloud.local/intruder", "intruder"], "",
     'dns name "intruder" not allowed'),
    ("mgmt address in a cert", "frontend", ["spiffe://cloud.local/frontend", "frontend", "10.50.0.20"], "",
     'ip name "10.50.0.20" not allowed'),
    ("lifetime above 24h", "frontend", ["spiffe://cloud.local/frontend", "frontend"], "--not-after 48h",
     "more than the authorized maximum certificate duration"),
])
def test_ca_refuses(ca, pki, case, cn, sans, cert_flags, reason):
    """Each refusal must come from the CA itself, for the expected reason (not from a TLS or
    token error, which would make the test pass for the wrong reason)."""
    r = issue(ca, pki, cn, sans, cert_flags)
    assert r.rc != 0, f"CA should refuse: {case}"
    out = r.stdout + r.stderr
    assert "forbidden by the certificate authority" in out and reason in out, out


def test_renewal_with_current_cert(ca, pki):
    """24h certs are renewed over mTLS with the current cert (no provisioner secret needed)."""
    ident = pki["identities"]["service-a"]
    assert issue(ca, pki, ident["cn"], [ident["uri"], *ident["dns"], *ident["ips"]]).rc == 0
    d = "/tmp/zt-probe-service-a"
    before = ca.check_output(f"{STEP} certificate inspect --format json {d}/c.crt")
    r = ca.run(f"{STEP} ca renew {d}/c.crt {d}/c.key --ca-url {pki['ca']['url']} "
               f"--root /etc/step-ca/certs/root_ca.crt --force")
    assert r.rc == 0, r.stderr
    after = ca.check_output(f"{STEP} certificate inspect --format json {d}/c.crt")
    assert json.loads(before)["serial_number"] != json.loads(after)["serial_number"]
