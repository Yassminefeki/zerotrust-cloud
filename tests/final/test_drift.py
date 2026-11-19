"""Stage 8b — drift: what runs is exactly what policy.yaml generates. Run with `make test-8`.

1. build/ is up to date with policy.yaml + env.yaml (regenerated in memory and compared);
2. every live config generated from the policy is byte-identical on its machine
   (nftables on every VM and the i5, mtls.json, pg_hba/pg_ident, WireGuard peers, CA policy);
3. the full N x N matrix — every source (6 VMs, the i5, a tunnel client) x every address of
   every VM x every policy port — is probed for real, and the set of reachable pairs must be
   EXACTLY the set of declared flows. A report is written to build/drift-report.json.
"""
import json
import re
from collections import Counter
from pathlib import Path

import pytest
import yaml

import gen_rules
from probe import is_reachable, probe_from, probe_local, probe_netns
from ztlib import BUILD, run
from ztlive import NS, VMs, WG, ensure_peer

pytestmark = pytest.mark.final

MATRIX = json.loads((BUILD / "matrix.json").read_text()) if (BUILD / "matrix.json").exists() else []
INV = yaml.safe_load((BUILD / "inventory.yml").read_text()) if (BUILD / "inventory.yml").exists() else {}
NODES = list(INV.get("all", {}).get("hosts", {}))
GROUPS = INV.get("all", {}).get("children", {})


@pytest.fixture(scope="module")
def vm():
    return VMs()


def accepts(text):
    out, chain = Counter(), None
    for line in text.splitlines():
        m = re.match(r"\s*chain (\w+) \{", line)
        if m:
            chain = m.group(1)
        m = re.search(r'accept comment "([^"]+)"', line)
        if m:
            out[(chain, m.group(1))] += 1
    return out


# --------------------------------------------------------------- build/ --
def test_build_is_up_to_date(policy, env, tmp_path):
    files = gen_rules.generate(policy, env, tmp_path)
    stale = [f for f, text in files.items() if (BUILD / f).read_text() != text]
    assert stale == [], f"build/ is stale, run `make gen`: {stale}"


# ---------------------------------------------------------- live configs --
@pytest.mark.parametrize("node", NODES)
def test_vm_firewall_is_the_policy(vm, node):
    h = vm(node)
    gen = (BUILD / "nodes" / node / "nftables.conf").read_text()
    assert h.file("/etc/nftables.conf").content_string == gen
    assert accepts(h.check_output("nft list ruleset")) == accepts(gen)
    assert h.check_output("nft list tables").split("\n") == ["table inet zt"]


def test_host_firewall_is_the_policy():
    gen = (BUILD / "host/nftables-zt.conf").read_text()
    live = run(["nft", "list", "table", "inet", "zt_host"], sudo=True, check=True).stdout
    assert accepts(live) == accepts(gen)
    assert set(re.findall(r'dnat ip to (\S+)', live)) == set(re.findall(r'dnat ip to (\S+)', gen))


@pytest.mark.parametrize("node", list(GROUPS.get("app", {}).get("hosts", {})))
def test_mtls_allowlists_are_the_policy(vm, node):
    assert vm(node).file("/etc/zt/mtls.json").content_string == (BUILD / "nodes" / node / "mtls.json").read_text()


@pytest.mark.parametrize("node", list(GROUPS.get("postgres", {}).get("hosts", {})))
@pytest.mark.parametrize("f", ["pg_hba.conf", "pg_ident.conf"])
def test_database_access_is_the_policy(vm, node, f):
    live = vm(node).check_output(f"cat $(ls -d /etc/postgresql/*/main | tail -1)/{f}")
    assert live + "\n" == (BUILD / "nodes" / node / f).read_text() or live == (BUILD / "nodes" / node / f).read_text()


def test_wireguard_peers_are_the_policy(vm):
    h = vm(WG["server"])
    secrets = Path(BUILD).parent / "ansible/.secrets/wireguard"
    allowed = dict(l.split("\t") for l in h.check_output(f"wg show {WG['iface']} allowed-ips").splitlines())
    assert allowed == {(secrets / f"{p['name']}.pub").read_text().strip(): f"{p['ip']}/32" for p in WG["peers"]}


def test_ca_issuance_policy_is_the_policy(vm):
    pki = json.loads((BUILD / "pki/pki.json").read_text())
    cfg = json.loads(vm(pki["ca"]["node"]).check_output("cat /etc/step-ca/config/ca.json"))
    assert cfg["authority"]["policy"]["x509"] == pki["x509_policy"]


# ----------------------------------------------------------- N x N matrix --
def _host_attached(policy):
    """Networks where the i5 itself has an address. Other destinations would leave through its
    default route (Wi-Fi) and probe someone else's network instead of ours."""
    import ipaddress
    return [ipaddress.ip_network(s["cidr"]) for s in policy["networks"].values() if s.get("host_ip")]


@pytest.fixture(scope="module")
def full_matrix(vm, policy):
    import ipaddress
    ensure_peer()
    attached = _host_attached(policy)
    tcp = [e for e in MATRIX if e["proto"] == "tcp" and
           (e["src"] != "host" or any(ipaddress.ip_address(e["dst_ip"]) in n for n in attached))]
    by_src = {}
    for e in tcp:
        by_src.setdefault(e["src"], []).append(e)
    verdicts = {}
    for src, entries in by_src.items():
        targets = [[e["dst_ip"], e["port"]] for e in entries]
        if src == "host":
            got = probe_local([tuple(t) for t in targets])
        elif src == "tunnel":
            got = probe_netns(NS, targets)
        else:
            got = probe_from(vm(src), targets)
        for e, v in zip(entries, got):
            verdicts[(e["src"], e["dst_ip"], e["port"])] = v
    report = [dict(e, verdict=verdicts[(e["src"], e["dst_ip"], e["port"])]) for e in tcp]
    (BUILD / "drift-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def test_every_source_was_probed(full_matrix):
    assert {e["src"] for e in full_matrix} == set(NODES) | {"host", "tunnel"}


def test_reachable_set_is_exactly_the_declared_flows(full_matrix):
    reachable = {(e["src"], e["dst_ip"], e["port"]) for e in full_matrix if is_reachable(e["verdict"])}
    declared = {(e["src"], e["dst_ip"], e["port"]) for e in full_matrix if e["expected"] == "allow"}
    extra, missing = sorted(reachable - declared), sorted(declared - reachable)
    assert not extra and not missing, f"undeclared but reachable: {extra}\ndeclared but blocked: {missing}"


def test_declared_flows_reach_a_live_service(full_matrix):
    """With every service up, an allowed probe must find a listener (open), not just a path."""
    not_open = [(e["src"], e["dst_ip"], e["port"], e["verdict"]) for e in full_matrix
                if e["expected"] == "allow" and e["verdict"] != "open"]
    assert not_open == []


def test_denies_are_silent(full_matrix):
    """No deny ever answers (a RST/ICMP would reveal that something is there)."""
    loud = [(e["src"], e["dst_ip"], e["port"], e["verdict"]) for e in full_matrix
            if e["expected"] == "deny" and e["verdict"] == "refused"]
    assert loud == []
