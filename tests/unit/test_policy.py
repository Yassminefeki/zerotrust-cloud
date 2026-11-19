"""Stage 0 — the policy is valid and the generator rejects anything unsafe."""
import copy
import ipaddress
import re
import subprocess

import pytest

import gen_rules
from unit_helpers import ROOT


def test_policy_and_example_env_are_valid(policy, env):
    assert gen_rules.validate_policy(policy) == []
    assert gen_rules.validate_env(env) == []
    gen_rules.resolve(policy)


def test_topology_ips_are_the_fixed_ones(policy):
    n = policy["nodes"]
    assert n["gateway"]["interfaces"] == {"wan": "192.168.122.10", "tunnel": "10.10.0.1",
                                          "dmz": "10.20.0.1", "mgmt": "10.50.0.2"}
    assert n["frontend"]["interfaces"]["dmz"] == "10.20.0.10"
    assert n["frontend"]["interfaces"]["app"] == "10.30.0.10"
    assert n["service-a"]["interfaces"]["app"] == "10.30.0.11"
    assert n["service-b"]["interfaces"]["app"] == "10.30.0.12"
    assert n["service-b"]["interfaces"]["data"] == "10.40.0.11"
    assert n["database"]["interfaces"]["data"] == "10.40.0.10"
    assert n["ca"]["interfaces"]["mgmt"] == "10.50.0.10"
    assert n["database"]["memory_mb"] == 2048
    assert all(s["memory_mb"] == 1024 for k, s in n.items() if k != "database")
    for name in ("dmz", "app", "data", "mgmt"):
        assert policy["networks"][name]["mode"] == "isolated"
    assert policy["networks"]["wan"]["mode"] == "nat"
    # only the gateway touches the WAN
    assert [k for k, s in n.items() if "wan" in s["interfaces"]] == ["gateway"]


@pytest.mark.parametrize("bad", ["192.0.2.42", "198.51.100.5", "2001:db8::1"])
def test_entry_point_must_be_a_name_not_an_ip(env, bad):
    e = dict(env, entry_point=bad)
    assert any("not an IP" in x for x in gen_rules.validate_env(e))


def test_bad_interface_name_rejected(env):
    assert gen_rules.validate_env(dict(env, wan_interface="wlp2s0; rm -rf /"))


def test_infra_flow_outside_mgmt_rejected(mutable_policy):
    mutable_policy["infra"].append({"name": "sneaky", "from": "host", "to": "postgres"})
    assert any("mgmt" in e for e in gen_rules.validate_policy(mutable_policy))


def test_business_flow_on_mgmt_rejected(mutable_policy):
    mutable_policy["flows"].append({"name": "sneaky", "from": "frontend", "to": "step-ca"})
    assert any("mgmt" in e for e in gen_rules.validate_policy(mutable_policy))


def test_ip_outside_cidr_rejected(mutable_policy):
    mutable_policy["nodes"]["service-a"]["interfaces"]["app"] = "10.40.0.99"
    assert gen_rules.validate_policy(mutable_policy)


def test_duplicate_ip_rejected(mutable_policy):
    mutable_policy["nodes"]["service-a"]["interfaces"]["app"] = "10.30.0.10"
    assert any("already used" in e for e in gen_rules.validate_policy(mutable_policy))


def test_nodes_are_never_routed(mutable_policy):
    # frontend shares no network with the database: declaring it must fail, not silently route.
    mutable_policy["flows"].append({"name": "shortcut", "from": "frontend", "to": "postgres"})
    assert gen_rules.validate_policy(mutable_policy) == []
    with pytest.raises(gen_rules.PolicyError, match="never routed"):
        gen_rules.resolve(mutable_policy)


def test_identity_outside_trust_domain_rejected(mutable_policy):
    mutable_policy["principals"]["tunnel"]["identities"] = ["spiffe://evil.example/x"]
    assert gen_rules.validate_policy(mutable_policy)


def test_actor_identities_are_derived_inside_the_trust_domain(policy):
    for a in policy["actors"]:
        assert gen_rules.actor_uri(policy, a).startswith("spiffe://cloud.local/")


def test_secrets_and_env_are_gitignored():
    gi = (ROOT / ".gitignore").read_text().split()
    for must in ("env.yaml", "build/", "ansible/.secrets/", "*.tfstate", "*.tfstate.*", ".terraform/"):
        assert must in gi, f".gitignore must contain {must}"


# RFC 5737 documentation ranges are allowed (used in examples/tests only).
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def test_no_hardcoded_ip_outside_declared_networks(policy):
    """No Wi-Fi/LAN address anywhere in the repo: every IPv4 literal must belong to a
    network declared in policy.yaml (or be 0.0.0.0/127.x/RFC 5737 documentation)."""
    nets = [ipaddress.ip_network(s["cidr"]) for s in policy["networks"].values()] + DOC_NETS
    tracked = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                             cwd=ROOT, capture_output=True, text=True)
    files = (tracked.stdout.split() if tracked.returncode == 0
             else [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file()])
    offenders = []
    for rel in files:
        p = ROOT / rel
        if any(part in (".git", "build", ".venv", ".terraform", "__pycache__") for part in p.parts):
            continue
        if p.suffix in (".png", ".img", ".qcow2", ".pyc"):
            continue
        try:
            text = p.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for m in IPV4.finditer(text):
            try:
                ip = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue  # not an address (e.g. a version string)
            if ip.is_loopback or ip.is_unspecified or any(ip in n for n in nets):
                continue
            offenders.append(f"{rel}: {ip}")
    assert not offenders, "hard-coded IPs outside policy networks:\n" + "\n".join(offenders)
