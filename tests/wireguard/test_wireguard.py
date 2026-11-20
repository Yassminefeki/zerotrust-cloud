"""Stage 5 — WireGuard on the gateway. Run with `make test-5` (on the i5, asks for sudo once).

The tunnel client is a network namespace on the i5 ("zt-peer", see tools/zt-test-peer) whose
ONLY interface is the tunnel, and which routes EVERY policy network into it. So each deny below
is enforced by the gateway (cryptokey routing + nftables), never by the client's own routes.

What the i5 cannot test: the DNAT on the Wi-Fi interface (a host never receives its own packets
"from outside"). The DNAT rules are checked in stage 2; the real path is checked from the i7
(README, "Check from the i7").
"""
import json
import re
import subprocess
import time

import pytest
import testinfra

from probe import is_reachable, probe_netns
from ztlib import BUILD, ROOT, run

pytestmark = pytest.mark.wireguard

NS, DEV = "zt-peer", "wg-zt-peer"
SECRETS = ROOT / "ansible" / ".secrets" / "wireguard"
EXPORT = BUILD / "export"
WG = json.loads((BUILD / "wireguard/wireguard.json").read_text()) if (BUILD / "wireguard/wireguard.json").exists() else {}
MATRIX = json.loads((BUILD / "matrix.json").read_text()) if (BUILD / "matrix.json").exists() else []
TUNNEL = [e for e in MATRIX if e["src"] == "tunnel" and e["proto"] == "tcp"]
PEERS = {p["name"]: p for p in WG.get("peers", [])}
TEST_PEER = next((p for p in WG.get("peers", []) if p["test"]), None)
FRONTEND = WG.get("reachable", ["/"])[0].split("/")[0]          # 10.20.0.10, from the policy
FRONTEND_PORT = next((e["port"] for e in TUNNEL if e["expected"] == "allow"), None)


def key(name, ext):
    return (SECRETS / f"{name}.{ext}").read_text().strip()


@pytest.fixture(scope="module")
def gw():
    return testinfra.get_host(f"ssh://{WG['server']}", ssh_config=str(BUILD / "ssh_config"), sudo=True)


@pytest.fixture(scope="module")
def peer():
    """(Re)create the test peer namespace from the exported config; left up for later stages."""
    conf = EXPORT / TEST_PEER["name"] / "wg0.conf"
    if not conf.exists():
        pytest.fail(f"{conf} missing: run `make wireguard`")
    run([str(ROOT / "tools/zt-test-peer"), "up", str(conf)], sudo=True, check=True)
    # first packet triggers the handshake; give it a moment
    probe_netns(NS, [[FRONTEND, FRONTEND_PORT]])
    return NS


def ns_wg(ns, dev, what):
    return run(["ip", "netns", "exec", ns, "wg", "show", dev, what], sudo=True, check=True).stdout


# ------------------------------------------------------------------ keys --
def test_keys_private_and_never_tracked():
    assert oct(SECRETS.stat().st_mode & 0o777) == "0o700"
    files = sorted(SECRETS.iterdir())
    assert files, "no keys: run `make wireguard`"
    for f in files:
        assert oct(f.stat().st_mode & 0o777) == "0o600", f
    tracked = run(["git", "-C", str(ROOT), "ls-files"], check=True).stdout
    assert ".secrets" not in tracked
    for f in files:
        if f.suffix in (".key", ".psk"):
            r = run(["git", "-C", str(ROOT), "grep", "-qF", f.read_text().strip()])
            assert r.returncode == 1, f"secret {f.name} appears in a tracked file"


def test_templates_carry_no_key():
    for t in (BUILD / "wireguard").glob("*.j2"):
        has_key = bool(re.search(r"(PrivateKey|PresharedKey) = [A-Za-z0-9+/]{43}=", t.read_text()))
        assert not has_key, f"{t} contains a key"   # boolean: never print the file


def test_i7_export(env):
    """What is produced for each real peer: its wg0.conf, private, least privilege. The i7 dials
    the i5's mDNS name; a peer living ON the i5 (netns, the stage 12 bot) dials the gateway directly.
    Checks are booleans: a failure must never print the file, it holds the peer's keys."""
    real = [p for p in WG["peers"] if not p["test"]]
    for p in real:
        conf = EXPORT / p["name"] / "wg0.conf"
        text = conf.read_text()
        endpoint = (f"{WG['endpoint_ip']}:{WG['port']}" if p.get("netns")
                    else f"{env['entry_point']}:{env['wan_port']}")
        checks = {
            "private file (0600)": oct(conf.stat().st_mode & 0o777) == "0o600",
            f"Endpoint = {endpoint}": f"Endpoint = {endpoint}" in text,
            "AllowedIPs = what the tunnel may reach": (re.search(r"^AllowedIPs = (.*)$", text, re.M) or [None, ""])[1]
                                                     .split(", ") == WG["reachable"],
            f"Address = {p['ip']}/32": f"Address = {p['ip']}/32" in text,
            "its own private key": f"PrivateKey = {key(p['name'], 'key')}" in text,
            "the gateway's public key": f"PublicKey = {key(WG['server'], 'pub')}" in text,
            "its own pre-shared key": f"PresharedKey = {key(p['name'], 'psk')}" in text,
        }
        failed = [k for k, ok in checks.items() if not ok]
        assert not failed, f"{conf}: {failed}"


# --------------------------------------------------------------- gateway --
def test_gateway_wg0_up_and_enabled(gw):
    svc = gw.service(f"wg-quick@{WG['iface']}")
    assert svc.is_running and svc.is_enabled
    conf = gw.file(f"/etc/wireguard/{WG['iface']}.conf")
    assert conf.user == "root" and conf.mode == 0o600
    assert gw.file("/etc/wireguard").mode == 0o700
    addrs = gw.check_output(f"ip -4 -br addr show {WG['iface']}")
    assert WG["address"] in addrs


def test_gateway_peers_are_exactly_the_policy(gw):
    i = WG["iface"]
    assert int(gw.check_output(f"wg show {i} listen-port")) == WG["port"]
    assert gw.check_output(f"wg show {i} public-key").strip() == key(WG["server"], "pub")
    allowed = dict(l.split("\t") for l in gw.check_output(f"wg show {i} allowed-ips").splitlines())
    assert allowed == {key(p["name"], "pub"): f"{p['ip']}/32" for p in WG["peers"]}, \
        "each peer may only use its own /32 (cryptokey routing)"
    psks = dict(l.split("\t") for l in gw.check_output(f"wg show {i} preshared-keys").splitlines())
    assert all(v != "(none)" for v in psks.values()), "every peer has a pre-shared key"


def test_gateway_forwards_but_does_not_nat(gw):
    assert gw.sysctl("net.ipv4.ip_forward") == 1
    assert gw.check_output("nft list tables").split("\n") == ["table inet zt"], \
        "no nat table: the frontend sees the real tunnel address (10.10.0.x)"


# ----------------------------------------------------------- handshake --
def test_handshake_both_sides(peer, gw):
    now = time.time()
    hs = int(ns_wg(peer, DEV, "latest-handshakes").split()[1])
    assert now - hs < 180, "test peer never completed a handshake with the gateway"
    gw_hs = dict(l.split("\t") for l in gw.check_output(f"wg show {WG['iface']} latest-handshakes").splitlines())
    assert now - int(gw_hs[key(TEST_PEER["name"], "pub")]) < 180


def test_ciphertext_leaves_from_host_namespace(peer):
    """Inside zt-peer there is nothing but lo and the tunnel."""
    out = run(["ip", "-n", peer, "-br", "link"], sudo=True, check=True).stdout
    names = {l.split()[0].split("@")[0] for l in out.splitlines() if l.strip()}
    assert names == {"lo", DEV}


# --------------------------------------------------------------- matrix --
@pytest.fixture(scope="module")
def results(peer):
    got = probe_netns(peer, [[e["dst_ip"], e["port"]] for e in TUNNEL])
    return {(e["dst_ip"], e["port"]): v for e, v in zip(TUNNEL, got)}


def _ids(e):
    return f"tunnel->{e['dst']}({e['dst_ip']}):{e['port']}-{e['expected']}"


@pytest.mark.parametrize("entry", TUNNEL, ids=_ids)
def test_tunnel_matrix(results, entry):
    v = results[(entry["dst_ip"], entry["port"])]
    if entry["expected"] == "allow":
        assert is_reachable(v), f"declared flow {entry['flow']} is blocked ({v})"
    else:
        assert not is_reachable(v), f"undeclared flow from the tunnel is reachable ({v})"


def test_only_frontend_from_tunnel(results):
    allowed = sorted(k for k, v in results.items() if is_reachable(v))
    assert allowed == [(FRONTEND, FRONTEND_PORT)]


@pytest.mark.parametrize("dst,port", [
    ("10.30.0.11", 9443),   # service-a
    ("10.40.0.10", 5432),   # database
    ("10.50.0.10", 9000),   # CA
    ("10.10.0.1", 22),      # the gateway itself, over the tunnel
    ("10.50.0.1", 3142),    # the i5's apt cache
    ("10.20.0.10", 22),     # frontend, other port
])
def test_tunnel_required_denies(peer, dst, port):
    assert probe_netns(peer, [[dst, port]]) == ["timeout"], "a deny must be a silent drop"


def test_tunnel_drop_logged_on_gateway(peer, gw):
    time.sleep(3)   # let the log rate limit refill
    probe_netns(peer, [["10.30.0.11", 9443]])
    time.sleep(1)
    log = gw.check_output("journalctl -k --since -30s --no-pager")
    assert re.search(r"zt-drop-forward: IN=wg0 .*SRC=10\.10\.0\.200 DST=10\.30\.0\.11 .*DPT=9443", log), \
        "the gateway must log what it drops from the tunnel"


# ----------------------------------------------- impersonation attempts --
def test_spoofed_tunnel_address_dropped(peer):
    """The test peer uses the i7's tunnel address: the gateway drops it (that /32 belongs to the
    i7's key only), even toward the one allowed destination."""
    i7 = next(p for p in WG["peers"] if not p["test"])
    run(["ip", "-n", peer, "addr", "add", f"{i7['ip']}/32", "dev", DEV], sudo=True, check=True)
    try:
        assert probe_netns(peer, [[FRONTEND, FRONTEND_PORT]], bind=i7["ip"]) == ["timeout"]
    finally:
        run(["ip", "-n", peer, "addr", "del", f"{i7['ip']}/32", "dev", DEV], sudo=True)


ROGUE = r'''
set -euo pipefail
ip netns del zt-rogue 2>/dev/null || true; ip link del wg-zt-rogue 2>/dev/null || true
ip netns add zt-rogue
ip link add wg-zt-rogue type wireguard
wg set wg-zt-rogue private-key "$1" peer "$2" endpoint "$3" allowed-ips "$4/32" persistent-keepalive 1 $5
ip link set wg-zt-rogue netns zt-rogue
ip -n zt-rogue link set lo up
ip -n zt-rogue addr add "$6/32" dev wg-zt-rogue
ip -n zt-rogue link set wg-zt-rogue up
ip -n zt-rogue route add "$4/32" dev wg-zt-rogue
'''


def _rogue(tmp_path, private_key, psk):
    kf = tmp_path / "k"
    kf.write_text(private_key + "\n")
    kf.chmod(0o600)
    extra = ""
    if psk:
        pf = tmp_path / "p"
        pf.write_text(psk + "\n")
        pf.chmod(0o600)
        extra = f"preshared-key {pf}"
    args = [str(kf), key(WG["server"], "pub"), f"{WG['endpoint_ip']}:{WG['port']}",
            FRONTEND, extra, TEST_PEER["ip"]]
    run(["bash", "-c", ROGUE, "rogue"] + args, sudo=True, check=True)
    try:
        verdict = probe_netns("zt-rogue", [[FRONTEND, FRONTEND_PORT]], timeout=4)
        hs = run(["ip", "netns", "exec", "zt-rogue", "wg", "show", "wg-zt-rogue", "latest-handshakes"],
                 sudo=True, check=True).stdout.split()
        return verdict, int(hs[1]) if len(hs) > 1 else 0
    finally:
        run(["ip", "netns", "del", "zt-rogue"], sudo=True)


def test_unknown_key_gets_nothing(tmp_path):
    """A client with a key the gateway does not know: no handshake, no answer at all."""
    fresh = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
    verdict, hs = _rogue(tmp_path, fresh, psk=None)
    assert verdict == ["timeout"] and hs == 0


def test_stolen_private_key_without_psk_gets_nothing(tmp_path):
    """A copied private key alone is not enough: without the peer's pre-shared key the
    handshake never completes (each peer's PSK is a second, independent secret)."""
    verdict, hs = _rogue(tmp_path, key(TEST_PEER["name"], "key"), psk=None)
    assert verdict == ["timeout"] and hs == 0


def test_dnat_target_is_the_wireguard_endpoint(zt_host):
    """The i5's WAN DNAT (stage 1/2) points at the address and port the gateway listens on."""
    assert {"proto": "udp", "to": f"{WG['endpoint_ip']}:{WG['port']}"} in [
        {"proto": d["proto"], "to": d["to"]} for d in zt_host["dnat"]]
    live = run(["nft", "list", "table", "inet", "zt_host"], sudo=True, check=True).stdout
    assert f"dnat ip to {WG['endpoint_ip']}:{WG['port']}" in live
