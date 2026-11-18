"""Stage 0 — what gen_rules.py produces enforces exactly the policy, nothing more."""
import json
import re
import shutil
import subprocess

import pytest

from conftest import gen_rules, mtls, nft

NODES = ["gateway", "frontend", "service-a", "service-b", "database", "ca"]


# ---------------------------------------------------------------- nftables --
def _nft_check(path):
    if not shutil.which("nft"):
        pytest.skip("nft not installed")
    # unprivileged parse check inside a throwaway user+net namespace
    cmd = ["nft", "-c", "-f", str(path)]
    if shutil.which("unshare"):
        cmd = ["unshare", "-rn"] + cmd
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 and "Operation not permitted" in r.stderr:
        pytest.skip("cannot create a network namespace here")
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("node", NODES)
def test_node_ruleset_parses(build, node):
    _nft_check(build / "nodes" / node / "nftables.conf")


def test_host_ruleset_parses(build):
    _nft_check(build / "host" / "nftables-zt.conf")


@pytest.mark.parametrize("node", NODES)
def test_default_drop_and_log_on_every_chain(build, node):
    text = nft(build, node)
    for chain in ("input", "forward", "output"):
        body = re.search(rf"chain {chain} \{{(.*?)\n  \}}", text, re.S).group(1)
        assert "policy drop;" in body, f"{node}/{chain} must default-drop"
        assert f'log prefix "zt-drop-{chain}: "' in body, f"{node}/{chain} must log drops"
        assert body.strip().splitlines()[-1].strip().startswith("limit rate"), "log must be last"


@pytest.mark.parametrize("node", NODES)
def test_ssh_only_from_host_on_mgmt(build, node):
    """Lock-out guard: SSH from the i5 over mgmt is always allowed, and only that."""
    text = nft(build, node)
    ssh = [l for l in text.splitlines() if "dport 22 " in l]
    assert len(ssh) == 1
    assert 'iifname "mgmt0" ip saddr 10.50.0.1/32' in ssh[0]


def test_only_the_gateway_forwards_and_only_tunnel_to_frontend_8443(build):
    for node in NODES:
        fwd = re.search(r"chain forward \{(.*?)\n  \}", nft(build, node), re.S).group(1)
        accepts = [l.strip() for l in fwd.splitlines() if l.strip().endswith('"flows:client-frontend"')]
        if node == "gateway":
            assert accepts == ['iifname "wg0" oifname "dmz0" ip saddr 10.10.0.0/24 ip daddr 10.20.0.10 '
                               'tcp dport 8443 ct state new accept comment "flows:client-frontend"']
        else:
            assert accepts == [] and " accept comment" not in fwd


def test_frontend_accepts_8443_only_from_tunnel(build):
    lines = [l for l in nft(build, "frontend").splitlines() if "dport 8443" in l]
    assert len(lines) == 1 and "ip saddr 10.10.0.0/24" in lines[0] and 'iifname "dmz0"' in lines[0]


def test_declared_denies_have_no_rule(build):
    # service-A -> database, frontend -> service-B: neither side may have a rule.
    assert "10.40.0.10" not in nft(build, "service-a")
    assert "10.30.0.12" not in nft(build, "frontend")
    db = nft(build, "database")
    assert "10.30.0.11" not in db and "5432" in db
    pg = [l for l in db.splitlines() if "dport 5432" in l]
    assert len(pg) == 1 and "ip saddr 10.40.0.11 " in pg[0]


def test_mgmt_never_reaches_business_ports(build):
    for node in NODES:
        for l in nft(build, node).splitlines():
            if '"mgmt0"' in l:
                assert re.search(r"dport (22|9000|3142) ", l), f"{node}: mgmt rule on business port: {l}"


def test_only_wireguard_is_open_to_anything(build):
    for node in NODES:
        for l in nft(build, node).splitlines():
            if " accept" in l and "dport" in l and "saddr" not in l:
                assert node == "gateway" and "udp dport 51820" in l


# ------------------------------------------------------------------- host --
def test_host_dnat_by_interface_name(build, env):
    host = (build / "host" / "nftables-zt.conf").read_text()
    assert (f'iifname "{env["wan_interface"]}" udp dport {env["wan_port"]} '
            f'dnat ip to 192.168.122.10:51820') in host
    assert "policy drop" not in host, "never default-drop the user's laptop"


def test_env_change_only_touches_host_and_client_side(policy, env, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    gen_rules.generate(policy, env, a)
    gen_rules.generate(policy, dict(env, wan_interface="enp3s0", wan_port=443,
                                    entry_point="other-host.local"), b)
    for node in NODES:
        assert (a / f"nodes/{node}/nftables.conf").read_text() == \
               (b / f"nodes/{node}/nftables.conf").read_text()
    hb = (b / "host/nftables-zt.conf").read_text()
    assert 'iifname "enp3s0" udp dport 443 dnat ip to 192.168.122.10:51820' in hb
    assert "Endpoint = other-host.local:443" in (b / "wireguard/client-i7.conf.j2").read_text()


# ------------------------------------------------------------------- mTLS --
def test_mtls_allowlists(build):
    assert mtls(build, "frontend")["serves"]["https"]["allowed_ids"] == [
        "spiffe://cloud.local/client/i7", "spiffe://cloud.local/client/test-peer"]
    assert mtls(build, "service-a")["serves"]["api-a"]["allowed_ids"] == ["spiffe://cloud.local/frontend"]
    assert mtls(build, "service-b")["serves"]["api-b"]["allowed_ids"] == ["spiffe://cloud.local/service-a"]
    assert mtls(build, "frontend")["calls"] == {
        "api-a": {"address": "10.30.0.11:9443", "expected_id": "spiffe://cloud.local/service-a"}}
    assert mtls(build, "service-b")["calls"]["postgres"]["expected_id"] == "spiffe://cloud.local/database"
    for n in NODES:
        m = mtls(build, n)
        assert m["identity"] == f"spiffe://cloud.local/{n}" and m["min_tls"] == "1.3"


def test_pg_hba_only_service_b(build):
    hba = (build / "nodes/database/pg_hba.conf").read_text()
    rules = [l for l in hba.splitlines() if l.startswith("host")]
    assert rules == ["hostssl  appdb  service_b  10.40.0.11/32  cert  clientcert=verify-full map=zt"
                     "   # flows:service-b-database"]
    assert not re.search(r"^host\s", hba, re.M), "no plain-text host lines"
    assert "zt  service-b  service_b" in (build / "nodes/database/pg_ident.conf").read_text()


# -------------------------------------------------------------- WireGuard --
def test_wireguard_configs(build, env):
    srv = (build / "wireguard/gateway-wg0.conf.j2").read_text()
    assert "ListenPort = 51820" in srv and "Address = 10.10.0.1/24" in srv
    assert "AllowedIPs = 10.10.0.2/32" in srv and "AllowedIPs = 10.10.0.200/32" in srv
    cli = (build / "wireguard/client-i7.conf.j2").read_text()
    assert f"Endpoint = {env['entry_point']}:{env['wan_port']}" in cli
    assert "AllowedIPs = 10.20.0.10/32" in cli, "client routes only what policy lets it reach"
    for text in (srv, cli):
        assert not re.search(r"PrivateKey = [A-Za-z0-9+/]{43}=", text), "no real key in templates"


# ------------------------------------------------------------- terraform --
def test_tfvars(build):
    tf = json.loads((build / "terraform.tfvars.json").read_text())
    assert set(tf["networks"]) == {"wan", "dmz", "app", "data", "mgmt"}
    assert tf["networks"]["dmz"]["host_ip"] is None and tf["networks"]["mgmt"]["host_ip"] == "10.50.0.1"
    macs = [i["mac"] for n in tf["nodes"].values() for i in n["interfaces"]]
    assert len(macs) == len(set(macs))
    assert all(any(i["network"] == "mgmt" for i in n["interfaces"]) for n in tf["nodes"].values())


# --------------------------------------------------------------- matrix --
def test_matrix_allows_exactly_the_declared_flows(policy, matrix):
    allowed = {(m["src"], m["dst"], m["dst_ip"], m["port"]) for m in matrix if m["expected"] == "allow"}
    business = {
        ("tunnel", "frontend", "10.20.0.10", 8443),
        ("frontend", "service-a", "10.30.0.11", 9443),
        ("service-a", "service-b", "10.30.0.12", 9443),
        ("service-b", "database", "10.40.0.10", 5432),
    }
    infra = ({("host", n, policy["nodes"][n]["interfaces"]["mgmt"], 22) for n in NODES}
             | {(n, "ca", "10.50.0.10", 9000) for n in NODES if n != "ca"}
             | {(n, "host", "10.50.0.1", 3142) for n in NODES})
    assert allowed == business | infra


@pytest.mark.parametrize("src,dst_ip,port", [
    ("service-a", "10.40.0.10", 5432),   # service-A -> database
    ("frontend", "10.30.0.12", 9443),    # frontend -> service-B
    ("tunnel", "10.30.0.11", 9443),
    ("tunnel", "10.20.0.1", 22),
    ("tunnel", "10.50.0.10", 9000),
    ("frontend", "10.50.0.30", 9443),    # business port via mgmt address
])
def test_matrix_required_denies(matrix, src, dst_ip, port):
    hits = [m for m in matrix if m["src"] == src and m["dst_ip"] == dst_ip and m["port"] == port]
    assert hits and all(m["expected"] == "deny" for m in hits)


def test_tunnel_reaches_only_frontend_8443(matrix):
    ok = [(m["dst_ip"], m["port"]) for m in matrix if m["src"] == "tunnel" and m["expected"] == "allow"]
    assert ok == [("10.20.0.10", 8443)]
