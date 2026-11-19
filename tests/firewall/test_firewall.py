"""Stage 4 — default-drop nftables on every VM. Run with `make test-4` (on the i5).

Two kinds of checks:
  * the live ruleset on each VM is exactly the generated one (policies, accepts, logging)
  * real TCP probes for every (source, destination, port) of build/matrix.json that is
    testable now: VMs and the i5 as sources (the tunnel arrives in stage 5).
"""
import ipaddress
import json
import re
import time
from collections import Counter

import pytest
import testinfra

from probe import TIMEOUT, is_reachable, probe_from, probe_local
from ztlib import BUILD

pytestmark = pytest.mark.firewall

MATRIX = json.loads((BUILD / "matrix.json").read_text()) if (BUILD / "matrix.json").exists() else []
TF = json.loads((BUILD / "terraform.tfvars.json").read_text()) if (BUILD / "terraform.tfvars.json").exists() else {}
NODES = sorted(TF.get("nodes", {}))
MGMT = TF.get("networks", {}).get("mgmt", {}).get("cidr", "")


@pytest.fixture(scope="module")
def vm():
    cache = {}

    def get(name):
        if name not in cache:
            cache[name] = testinfra.get_host(f"ssh://{name}", ssh_config=str(BUILD / "ssh_config"), sudo=True)
        return cache[name]
    return get


def generated(node):
    return (BUILD / "nodes" / node / "nftables.conf").read_text()


def accepts_by_chain(text):
    """Counter of (chain, comment) for every accept rule that carries a policy comment."""
    out, chain = Counter(), None
    for line in text.splitlines():
        m = re.match(r"\s*chain (\w+) \{", line)
        if m:
            chain = m.group(1)
        m = re.search(r'accept comment "([^"]+)"', line)
        if m:
            out[(chain, m.group(1))] += 1
    return out


# ------------------------------------------------------------ live ruleset --
@pytest.mark.parametrize("name", NODES)
def test_live_ruleset_is_the_generated_one(vm, name):
    live = vm(name).check_output("nft list ruleset")
    assert vm(name).check_output("nft list tables").split("\n") == ["table inet zt"], \
        "no other table (ufw, iptables-nft leftovers) may exist"
    for chain in ("input", "forward", "output"):
        body = re.search(rf"chain {chain} \{{(.*?)\n\t\}}", live, re.S).group(1)
        assert "policy drop;" in body, f"{name}/{chain} is not default-drop"
        assert f'log prefix "zt-drop-{chain}: "' in body, f"{name}/{chain} does not log drops"
    assert accepts_by_chain(live) == accepts_by_chain(generated(name)), \
        "live accept rules differ from policy.yaml (drift)"


@pytest.mark.parametrize("name", NODES)
def test_persistent_and_no_pending_rollback(vm, name):
    h = vm(name)
    assert h.service("nftables").is_enabled
    assert h.file("/etc/nftables.conf").content_string == generated(name)
    assert not h.service("ufw").is_running
    assert h.run("systemctl is-active zt-nft-rollback.timer").stdout.strip() != "active", \
        "a rollback is still armed: the last apply was never confirmed"


# ---------------------------------------------------------------- probes --
def _testable(entry):
    """TCP probes we can run now: from VMs, and from the i5 towards mgmt addresses only
    (the i5 has no address on dmz/app/data; probing them would just leak SYNs to the LAN)."""
    if entry["proto"] != "tcp":
        return False
    if entry["src_kind"] == "node":
        return True
    if entry["src"] == "host":
        return ipaddress.ip_address(entry["dst_ip"]) in ipaddress.ip_network(MGMT)
    return False   # tunnel: stage 5


@pytest.fixture(scope="module")
def results(vm):
    """Run every testable probe once, grouped by source (parallel inside each source)."""
    todo = [e for e in MATRIX if _testable(e)]
    by_src = {}
    for e in todo:
        by_src.setdefault(e["src"], []).append(e)
    verdicts = {}
    for src, entries in by_src.items():
        targets = [[e["dst_ip"], e["port"]] for e in entries]
        got = probe_local([tuple(t) for t in targets]) if src == "host" else probe_from(vm(src), targets)
        for e, v in zip(entries, got):
            verdicts[(e["src"], e["dst_ip"], e["port"])] = v
    return verdicts


def _ids(e):
    return f"{e['src']}->{e['dst']}({e['dst_ip']}):{e['port']}-{e['expected']}"


@pytest.mark.parametrize("entry", [e for e in MATRIX if _testable(e)], ids=_ids)
def test_matrix(results, entry):
    v = results[(entry["src"], entry["dst_ip"], entry["port"])]
    if entry["expected"] == "allow":
        assert is_reachable(v), f"declared flow {entry['flow']} is blocked ({v})"
    else:
        assert not is_reachable(v), f"undeclared flow is reachable ({v})"


# The cases called out in the requirements, asserted by name so they cannot silently vanish
# from the matrix.
@pytest.mark.parametrize("src,dst_ip,port", [
    ("service-a", "10.40.0.10", 5432),   # service-A -> database
    ("frontend", "10.30.0.12", 9443),    # frontend -> service-B
    ("frontend", "10.50.0.30", 22),      # VM -> VM over mgmt
    ("host", "10.50.0.10", 9000),        # the i5 has SSH only, not the CA
])
def test_required_denies(results, src, dst_ip, port):
    assert not is_reachable(results[(src, dst_ip, port)])


def test_denied_is_a_silent_drop(results):
    """A deny is a DROP, never a reject: the i5 -> CA:9000 SYN is dropped by the CA's input
    chain, so the i5 sees a timeout (a reject would answer and leak that something is there).
    For VM sources the drop usually happens earlier, on their own output chain."""
    assert results[("host", "10.50.0.10", 9000)] == "timeout"
    assert results[("frontend", "10.30.0.12", 9443)] != "refused"


def _fresh_probe_then_log(vm, src, dst_ip, port, logger_vm, prefix):
    """Drop logging is rate limited (10/s, burst 20): let the bucket refill, send ONE probe,
    then read the log of the VM that drops it."""
    time.sleep(3)
    if src == "host":
        probe_local([(dst_ip, port)], timeout=1.5)
    else:
        probe_from(vm(src), [[dst_ip, port]], timeout=1.5)
    time.sleep(1)
    return vm(logger_vm).check_output(
        f"journalctl -k --since -2min --no-pager | grep '{prefix}' || true")


def test_drop_logged_on_destination_input(vm):
    log = _fresh_probe_then_log(vm, "host", "10.50.0.10", 9000, "ca", "zt-drop-input")
    assert "SRC=10.50.0.1 " in log and "DPT=9000" in log, log[-2000:]


def test_drop_logged_on_source_output(vm):
    log = _fresh_probe_then_log(vm, "frontend", "10.30.0.12", 9443, "frontend", "zt-drop-output")
    assert "DST=10.30.0.12 " in log and "DPT=9443" in log, log[-2000:]
