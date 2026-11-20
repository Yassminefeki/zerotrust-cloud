"""Stage 13 — attacks that no earlier stage plays, live. Run with `make test-13` (on the cloud host).

A1  stolen laptop: a copy of Alice's certificate works until it is revoked; then it is refused
    everywhere within a minute (the CRL timer), while Alice's own certificate keeps working; the CA
    refuses to renew it; no list (or a stale one) = nobody gets in (fail-closed).
A2  compromised frontend (root on the VM): it reaches only its declared flows, holds no one else's
    key, and the inner services keep enforcing their own routes.
A5  reconnaissance: a full TCP scan from inside the tunnel and from outside finds exactly what the
    policy publishes, nothing else.

The other attacks of the catalogue (tests/attacks/catalogue.yaml) are proven by the tests of earlier
stages; `make attacks` runs them all and writes build/reports/attacks.md.
"""
import ipaddress
import json
import re
import shlex
import subprocess
import time

import pytest
import yaml

from probe import is_reachable, probe_from
from ztlib import BUILD, ROOT
from ztlive import (PKI, STEP, VMs, _on_ca, actor_creds, actor_identity, ca_issued_cert, ensure_peer,
                    frontend_node, frontend_url, probe_tunnel, push)

pytestmark = pytest.mark.attacks

POLICY = yaml.safe_load((ROOT / "policy.yaml").read_text())
HOST = json.loads((BUILD / "host/host.json").read_text())
TESTS = ROOT / "tests"
ALICE = next(k for k, v in PKI["identities"].items() if v.get("actor") == "alice")
REVOCATION_DEADLINE_S = 90          # timer every 60 s + fetch; the policy promises "within a minute"
APP_NODES = sorted(p.parent.name for p in (BUILD / "nodes").glob("*/mtls.json")
                   if "revocation" in json.loads(p.read_text()))


@pytest.fixture(scope="module")
def vm():
    return VMs()


@pytest.fixture(scope="module")
def peer():
    return ensure_peer()


def serial_of(crt):
    out = subprocess.run(["openssl", "x509", "-in", str(crt), "-noout", "-serial"],
                         capture_output=True, text=True, check=True).stdout
    return out.strip().split("=", 1)[1]


def revoked_serials(h):
    d = json.loads(h.file("/etc/zt/pki/revoked.json").content_string)
    return {int(x, 16) for x in d["revoked"]}


def revoke_on_ca(ca, serial_hex, reason="stage 13 attack test"):
    """Exactly what `make revoke` does: one-time revocation token minted on the CA, then revoke."""
    c, dec = PKI["ca"], int(serial_hex, 16)
    root = "/etc/step-ca/certs/root_ca.crt"
    tok = _on_ca(ca, f"{STEP} ca token --revoke --provisioner {c['provisioner']} "
                     f"--provisioner-password-file /etc/step-ca/secrets/provisioner-password "
                     f"--ca-url {c['url']} --root {root} {dec}").strip()
    r = ca.run(f"{STEP} ca revoke --token {shlex.quote(tok)} --reasonCode 1 --reason {shlex.quote(reason)} "
               f"--ca-url {c['url']} --root {root} {dec}")
    assert r.rc == 0, "revocation refused by the CA (output withheld: it may echo the token)"


def me(cert, key):
    return probe_tunnel(frontend_url("/api/me"), cert, key)


# ===================================================================== A1 ====
@pytest.fixture(scope="module")
def stolen(vm, tmp_path_factory, peer):
    """A second, perfectly valid certificate for Alice (her laptop copied by a thief), then revoked
    with the timer only: no manual refresh, so the test measures the real delay."""
    tmp = tmp_path_factory.mktemp("stolen")
    crt, key = ca_issued_cert(vm(PKI["ca"]["node"]), tmp, ALICE)
    before = me(crt, key)
    serial = serial_of(crt)
    t0 = time.time()
    revoke_on_ca(vm(PKI["ca"]["node"]), serial)
    seen = None
    while time.time() - t0 < REVOCATION_DEADLINE_S:
        r = me(crt, key)
        if r["status"] != 200:
            seen = r
            break
        time.sleep(3)
    return {"crt": crt, "key": key, "serial": serial, "before": before, "after": seen,
            "seconds": round(time.time() - t0, 1), "t0": t0}


def test_a1_stolen_copy_worked_before_revocation(stolen):
    assert stolen["before"]["status"] == 200, stolen["before"]
    assert stolen["before"]["body"]["identity"] == actor_identity("alice")["uri"]


def test_a1_revoked_within_a_minute_without_any_restart(stolen):
    r = stolen["after"]
    assert r is not None, f"still accepted {REVOCATION_DEADLINE_S}s after the revocation"
    assert r["status"] == 403 and "revoked" in r["body"]["reason"], r
    print(f"A1: refused {stolen['seconds']}s after the revocation")


def test_a1_every_service_has_the_serial(vm, stolen):
    """Each service's own timer picks the CRL up independently: every one of them within the
    deadline (counted from the revocation), not only the one that was asked first."""
    missing = set(APP_NODES)
    while missing and time.time() - stolen["t0"] < REVOCATION_DEADLINE_S:
        missing = {n for n in missing if int(stolen["serial"], 16) not in revoked_serials(vm(n))}
        if missing:
            time.sleep(3)
    assert not missing, f"still not revoked {REVOCATION_DEADLINE_S}s after the revocation on: {sorted(missing)}"


def test_a1_alice_own_certificate_still_works(stolen):
    r = me(*actor_creds("alice"))
    assert r["status"] == 200 and r["body"]["identity"] == actor_identity("alice")["uri"], r


def test_a1_ca_refuses_to_renew_the_revoked_certificate(vm, stolen):
    ca = vm(PKI["ca"]["node"])
    f = push(ca, {"c.crt": stolen["crt"], "c.key": stolen["key"]})
    try:
        r = ca.run(f"{STEP} ca renew --force {f['c.crt']} {f['c.key']} "
                   f"--ca-url {PKI['ca']['url']} --root /etc/step-ca/certs/root_ca.crt")
    finally:
        ca.run(f"rm -rf {f['_dir']}")
    assert r.rc != 0


def test_a1_refusal_logged_with_the_serial(vm, stolen):
    log = vm(frontend_node()).check_output("journalctl -u zt-mtls --since '-10min' --no-pager -o cat")
    logged = {int(x, 16) for x in re.findall(r"certificate ([0-9A-Fa-f]+) of \S+ is revoked", log)}
    assert int(stolen["serial"], 16) in logged


def test_a1_fail_closed_without_a_fresh_list(vm, peer):
    """The attacker blocks the CA (or deletes the list) hoping revocations stop: nobody gets in."""
    fe = vm(frontend_node())
    fe.check_output("systemctl stop zt-crl.timer && mv /etc/zt/pki/revoked.json /etc/zt/pki/revoked.json.aside")
    try:
        r = me(*actor_creds("alice"))
        assert r["status"] == 503 and "revocation status unknown" in r["body"]["reason"], r
    finally:
        fe.run("mv -f /etc/zt/pki/revoked.json.aside /etc/zt/pki/revoked.json; "
               "systemctl start zt-crl.service; systemctl start zt-crl.timer")
    assert me(*actor_creds("alice"))["status"] == 200


def test_a1_crl_fetcher_is_timed_and_least_privileged(vm):
    for node in APP_NODES:
        h = vm(node)
        assert h.service("zt-crl.timer").is_enabled and h.service("zt-crl.timer").is_running, node
        unit = h.check_output("systemctl cat zt-crl.service")
        assert "ReadWritePaths=/etc/zt/pki" in unit and "ProtectSystem=strict" in unit, node
        d = json.loads(h.file("/etc/zt/pki/revoked.json").content_string)
        assert d["next_update"] > time.time() and time.time() - d["fetched_at"] < 180, node


# ===================================================================== A2 ====
def _addr(node, net):
    if node == "host":
        return POLICY["networks"][net]["host_ip"]
    return POLICY["nodes"][node]["interfaces"].get(net)


def _targets_and_allowed(src):
    """Every TCP service of the policy on another machine -> may `src` reach it per the policy?"""
    rules = POLICY["flows"] + POLICY["infra"]
    out = {}
    for name, s in POLICY["services"].items():
        if s.get("proto", "tcp") != "tcp":
            continue
        nodes = [n for n in POLICY["nodes"] if n != src] if s["node"] == "*" else [s["node"]]
        for n in nodes:
            ip = _addr(n, s["network"])
            if not ip or n == src:
                continue
            ok = any(r["to"] == name and r["from"] in (src, "*") for r in rules)
            out[(ip, s["port"])] = ok
    return out


def test_a2_compromised_frontend_reaches_only_its_flows(vm):
    fe = vm(frontend_node())
    expect = _targets_and_allowed(frontend_node())
    internet = str(ipaddress.IPv4Address(0x01010101))      # a public resolver: no way out to the internet
    expect[(internet, 443)] = False
    expect[(POLICY["networks"]["wan"]["host_ip"], 22)] = False   # nor to the cloud host's SSH on the NAT side
    keys = list(expect)
    got = dict(zip(keys, probe_from(fe, [list(k) for k in keys])))
    wrong = {f"{ip}:{p}": got[(ip, p)] for (ip, p), ok in expect.items() if is_reachable(got[(ip, p)]) != ok}
    assert not wrong, wrong
    assert any(expect.values()), "the frontend's own flows were not probed"


# The VM's own keys: its workload identity, its SSH host keys, and keys the Ubuntu image generates
# for itself on first boot (snakeoil TLS, fwupd's local signing key). None identifies anyone in the bank.
PRIVATE_OK = ("/etc/zt/pki/cert.key", "/etc/ssh/ssh_host_", "/etc/ssl/private/ssl-cert-snakeoil.key",
              "/var/lib/fwupd/pki/secret.key")


def test_a2_compromised_frontend_holds_no_one_elses_key(vm):
    """Root on the frontend finds its own key and the partner secret it must check, nothing else:
    no CA material, no provisioner password, no other workload's or actor's key, no DB credential."""
    fe = vm(frontend_node())
    found = fe.run("grep -rlI --exclude-dir=proc 'PRIVATE KEY' /etc /root /home /opt /srv /var/lib /tmp "
                   "2>/dev/null").stdout.split()
    extra = [p for p in found if not p.startswith(PRIVATE_OK)]
    assert not extra, f"private keys on the frontend besides its own: {extra}"
    assert not fe.file("/etc/step-ca").exists
    names = fe.run("find /etc /root /home /opt /srv /var/lib -xdev \\( -iname '*provisioner*' "
                   "-o -iname '*.p12' -o -iname '.pgpass' -o -name 'pg_service.conf' \\) 2>/dev/null").stdout.split()
    assert not names, names
    sans = fe.check_output("openssl x509 -in /etc/zt/pki/cert.crt -noout -ext subjectAltName")
    assert "URI:" + PKI["identities"][frontend_node()]["uri"] in sans.replace(" ", "")
    assert sans.count("URI:") == 1, "the frontend's certificate must carry one identity only"


def test_a2_inner_services_do_not_accept_the_frontend_beyond_its_flow():
    """Even if the network let it through, the mTLS layer alone refuses the frontend's (valid)
    certificate everywhere but service-a: the ledger only accepts service-a."""
    fe = PKI["identities"][frontend_node()]["uri"]
    for node in APP_NODES:
        for name, s in json.loads((BUILD / "nodes" / node / "mtls.json").read_text())["serves"].items():
            accepts = fe in s.get("allowed_ids", [])
            assert accepts == (name == "api-a"), f"{node}/{name}: accepts the frontend = {accepts}"


# ===================================================================== A5 ====
def scan(where, host, ports="1-65535"):
    cmd = ["python3", str(TESTS / "port_scan.py"), host, "--ports", ports]
    if where != "outside":
        cmd = ["sudo", "-n", "ip", "netns", "exec", where] + cmd
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _policy_ports():
    return sorted({s["port"] for s in POLICY["services"].values()} | {22, 80, 443, 8080})


def test_a5_scan_from_the_tunnel_finds_only_the_website(peer):
    """The hostile test peer routes EVERY policy network into the tunnel and scans: full range on
    the addresses it can route to first-hand (frontend, gateway), policy ports + 1-1024 elsewhere."""
    web = frontend_url("/").split("//")[1].rstrip("/")
    web_ip, web_port = web.rsplit(":", 1)
    gw_tun = str(ipaddress.ip_interface(json.loads((BUILD / "wireguard/wireguard.json").read_text())["address"]).ip)
    found = {}
    for ip in (web_ip, gw_tun):
        found[ip] = scan(peer, ip)["open"]
    others = {a for n in POLICY["nodes"].values() for net, a in n["interfaces"].items() if net != "wan"}
    others |= {POLICY["networks"]["mgmt"]["host_ip"]}
    ports = "1-1024," + ",".join(map(str, _policy_ports()))
    for ip in sorted(others - {web_ip, gw_tun}):
        found[ip] = scan(peer, ip, ports)["open"]
    reachable = {f"{ip}:{p}" for ip, ps in found.items() for p in ps}
    assert reachable == {f"{web_ip}:{web_port}"}, reachable


def test_a5_scan_from_outside_finds_only_the_published_ports():
    """From the cloud host's own namespace (outside, like the Wi-Fi after the port forwarding),
    every TCP port of the gateway's WAN address: only the partner API answers. WireGuard (UDP) never
    answers a scan without the right key (A6)."""
    gw = json.loads((BUILD / "wireguard/wireguard.json").read_text())["endpoint_ip"]
    published = {int(d["to"].rsplit(":", 1)[1]) for d in HOST["dnat"] if d["proto"] == "tcp"}
    r = scan("outside", gw)
    assert set(r["open"]) == published, r
    assert r["refused"] == 0, "a refusal (RST) reveals the address: denies must be silent"


def test_a5_scans_are_visible_in_the_drop_logs(vm):
    log = vm("gateway").check_output("journalctl -k --since '-15min' --no-pager -o cat | grep -c zt-drop- || true")
    assert int(log.strip() or 0) > 0
