"""Helpers shared by the stage 7-8 tests: VMs, the tunnel test peer, credentials, probes."""
import base64
import json
import shlex
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import testinfra

from ztlib import BUILD, ROOT, run

PKI = json.loads((BUILD / "pki/pki.json").read_text()) if (BUILD / "pki/pki.json").exists() else {}
WG = json.loads((BUILD / "wireguard/wireguard.json").read_text()) if (BUILD / "wireguard/wireguard.json").exists() else {}
ROOT_CA = BUILD / "pki/root_ca.crt"
TESTS = ROOT / "tests"
NS = "zt-peer"
STEP = "$(command -v step || command -v step-cli)"


def mtls(node):
    return json.loads((BUILD / "nodes" / node / "mtls.json").read_text())


def frontend_node():
    """The node that serves the actors (the one whose mtls.json has an actor directory)."""
    for node in PKI.get("identities", {}):
        p = BUILD / "nodes" / node / "mtls.json"
        if p.exists() and json.loads(p.read_text()).get("actors"):
            return node
    raise LookupError("no service reachable by the actors in the policy")


def frontend_url(path):
    """The one service the tunnel may reach, from the policy (10.20.0.10:8443)."""
    serves = mtls(frontend_node())["serves"].values()
    s = next((v for v in serves if v.get("app") == "web"), None) or next(iter(serves))
    return f"https://{s['listen']}{path}"


def actor_identity(actor):
    return next(i for i in PKI["identities"].values() if i.get("actor") == actor)


def actor_creds(actor):
    """(cert, key) of an actor; every client key is generated on the cloud host (ansible/.secrets/pki)."""
    d = ROOT / "ansible/.secrets/pki" / actor_identity(actor)["cn"]
    return d / "client.crt", d / "client.key"


def peer_creds():
    """The test client's default identity: Dev (staff), who may use the diagnostic routes."""
    return actor_creds("dev")


class VMs:
    def __init__(self):
        self.cache = {}

    def __call__(self, name):
        if name not in self.cache:
            self.cache[name] = testinfra.get_host(f"ssh://{name}", ssh_config=str(BUILD / "ssh_config"), sudo=True)
        return self.cache[name]


def ensure_peer():
    if NS not in run(["ip", "netns", "list"]).stdout.split():
        conf = BUILD / "export" / next(p for p in WG["peers"] if p["test"])["name"] / "wg0.conf"
        run([str(ROOT / "tools/zt-test-peer"), "up", str(conf)], sudo=True, check=True)
    return NS


def netns_of(cert):
    """The namespace a client certificate is used from: its actor's device if it is bound to one
    (the statements bot: zt-bot), else the test peer."""
    if cert:
        return PKI.get("identities", {}).get(Path(cert).parent.name, {}).get("netns") or NS
    return NS


def ensure_ns(ns):
    """Bring up a peer's namespace (zt-peer, or a device such as zt-bot) if it is not there."""
    if ns == NS:
        return ensure_peer()
    if ns not in run(["ip", "netns", "list"]).stdout.split():
        peer = next(p for p in WG["peers"] if p.get("netns") == ns)
        conf = BUILD / "export" / peer["name"] / "wg0.conf"
        run([str(ROOT / "tools/zt-test-peer"), "up", str(conf), ns], sudo=True, check=True)
    return ns


def probe_tunnel(url, cert=None, key=None, extra=(), method="GET", data=None, ns=None):
    """tls_probe.py from inside a peer's netns (= a client coming through WireGuard): the test peer,
    or the device the certificate is bound to (`ns` overrides, e.g. a stolen bot certificate)."""
    ns = ensure_ns(ns or netns_of(cert))
    cmd = ["sudo", "-n", "ip", "netns", "exec", ns, "python3", str(TESTS / "tls_probe.py"),
           "--url", url, "--ca", str(ROOT_CA)]
    if cert:
        cmd += ["--cert", str(cert), "--key", str(key)]
    cmd += ["--method", method] + (["--data", data] if data is not None else [])
    r = subprocess.run(cmd + list(extra), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def push(h, files):
    """Copy local files to a fresh private dir on a VM; returns {name: remote path}."""
    d = f"/tmp/zt-test-{uuid.uuid4().hex[:8]}"
    h.check_output(f"install -d -m 700 {d}")
    out = {}
    for name, data in files.items():
        if isinstance(data, Path):
            data = data.read_bytes()
        if isinstance(data, str):
            data = data.encode()
        b64 = base64.b64encode(data).decode()
        h.check_output(f"printf %s {b64} | base64 -d > {d}/{name} && chmod 600 {d}/{name}")
        out[name] = f"{d}/{name}"
    out["_dir"] = d
    return out


def run_script(h, script, args):
    """Run one of tests/*.py on a VM (python3 -c), return its JSON output."""
    code = (TESTS / script).read_text()
    r = h.run(f"python3 -c {shlex.quote(code)} " + " ".join(shlex.quote(str(a)) for a in args))
    assert r.rc == 0, r.stderr
    return json.loads(r.stdout)


# ------------------------------------------------------------ bad credentials --
def other_ca_cert(tmp, uri):
    """A certificate with a perfectly valid-looking SPIFFE ID, signed by a throwaway CA."""
    sh = f"""
set -e; cd {shlex.quote(str(tmp))}
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out evil-root.key
openssl req -x509 -new -key evil-root.key -subj /CN=evil-root -days 2 -out evil-root.crt \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out other.key
openssl req -new -key other.key -subj /CN=client-test-peer -out other.csr
printf 'basicConstraints=CA:FALSE\\nextendedKeyUsage=clientAuth\\nsubjectAltName=URI:{uri}\\n' > ext
openssl x509 -req -in other.csr -CA evil-root.crt -CAkey evil-root.key -days 1 -extfile ext -out other.crt
"""
    run(["bash", "-c", sh], check=True)
    return Path(tmp) / "other.crt", Path(tmp) / "other.key"


def _on_ca(ca, cmd):
    return ca.check_output(f"sudo -u step env STEPPATH=/etc/step-ca {cmd}")


def expired_cert(ca, tmp, uri, cn):
    """Signed OFFLINE with the real intermediate (the CA's API refuses past validity), valid
    from -48h to -24h: everything is right except the dates."""
    d = f"/tmp/zt-exp-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    nb = (now - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")
    na = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ca.check_output(f"install -d -m 700 -o step {d}")
    try:
        _on_ca(ca, f"{STEP} certificate create {cn} {d}/c.crt {d}/c.key --profile leaf "
                   f"--ca /etc/step-ca/certs/intermediate_ca.crt "
                   f"--ca-key /etc/step-ca/secrets/intermediate_ca_key "
                   f"--ca-password-file /etc/step-ca/secrets/password "
                   f"--not-before {nb} --not-after {na} --san {uri} "
                   f"--no-password --insecure --bundle --kty EC --curve P-256")
        crt, key = ca.check_output(f"cat {d}/c.crt"), ca.check_output(f"cat {d}/c.key")
    finally:
        ca.run(f"rm -rf {d}")
    (Path(tmp) / "expired.crt").write_text(crt + "\n")
    (Path(tmp) / "expired.key").write_text(key + "\n")
    (Path(tmp) / "expired.key").chmod(0o600)
    return Path(tmp) / "expired.crt", Path(tmp) / "expired.key"


def ca_issued_cert(ca, tmp, ident_name):
    """A genuine, valid certificate from our CA for ANOTHER identity of the policy."""
    ident = PKI["identities"][ident_name]
    c = PKI["ca"]
    sans = " ".join(f"--san {s}" for s in [ident["uri"], *ident["dns"]])
    d = f"/tmp/zt-iss-{uuid.uuid4().hex[:6]}"
    tok = _on_ca(ca, f"{STEP} ca token {ident['cn']} {sans} --provisioner {c['provisioner']} "
                     f"--provisioner-password-file /etc/step-ca/secrets/provisioner-password "
                     f"--ca-url {c['url']} --root /etc/step-ca/certs/root_ca.crt --not-after 5m").strip()
    try:
        ca.check_output(f"install -d -m 700 {d} && {STEP} ca certificate {ident['cn']} {d}/c.crt {d}/c.key "
                        f"--token {shlex.quote(tok)} --ca-url {c['url']} "
                        f"--root /etc/step-ca/certs/root_ca.crt --force")
        crt, key = ca.check_output(f"cat {d}/c.crt"), ca.check_output(f"cat {d}/c.key")
    finally:
        ca.run(f"rm -rf {d}")
    (Path(tmp) / f"{ident_name}.crt").write_text(crt + "\n")
    (Path(tmp) / f"{ident_name}.key").write_text(key + "\n")
    (Path(tmp) / f"{ident_name}.key").chmod(0o600)
    return Path(tmp) / f"{ident_name}.crt", Path(tmp) / f"{ident_name}.key"
