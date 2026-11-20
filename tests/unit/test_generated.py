"""Stage 0 — what gen_rules.py produces enforces exactly the policy, nothing more."""
import json
import re
import shutil
import subprocess

import pytest
import yaml

import gen_rules
from unit_helpers import mtls, nft

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
    """Lock-out guard: SSH from the cloud host over mgmt is always allowed, and only that."""
    text = nft(build, node)
    ssh = [l for l in text.splitlines() if "dport 22 " in l]
    assert len(ssh) == 1
    assert 'iifname "mgmt0" ip saddr 10.50.0.1/32' in ssh[0]
    # replies to the cloud host survive a first ruleset load over an already-open (untracked) session
    replies = [l.strip() for l in text.splitlines() if "sport 22 " in l]
    ip = next(l for l in text.splitlines() if "dport 22 " in l).split("ip daddr ")[1].split()[0]
    assert replies == [f'oifname "mgmt0" ip saddr {ip} ip daddr 10.50.0.1 tcp sport 22 accept '
                       f'comment "infra:admin-ssh:replies"']


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
                assert re.search(r"dport (22|9000|3142) |sport 22 accept", l), \
                    f"{node}: mgmt rule on business port: {l}"


def test_only_wireguard_and_the_published_partner_port_are_open_to_anything(build):
    for node in NODES:
        for l in nft(build, node).splitlines():
            if " accept" in l and "dport" in l and "saddr" not in l:
                assert node == "gateway" and ("udp dport 51820" in l or
                                              ("tcp dport 8444 ct status dnat" in l and '"wan0" oifname "dmz0"' in l)), l


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
    assert "Endpoint = other-host.local:443" in (b / "wireguard/client-remote-client.conf.j2").read_text()


# ------------------------------------------------------------------- mTLS --
def test_mtls_allowlists(build):
    assert mtls(build, "frontend")["serves"]["https"]["allowed_ids"] == [
        "spiffe://cloud.local/customer/alice", "spiffe://cloud.local/customer/bob",
        "spiffe://cloud.local/staff/dev", "spiffe://cloud.local/bot/statements"]
    assert mtls(build, "service-a")["serves"]["api-a"]["allowed_ids"] == ["spiffe://cloud.local/frontend"]
    assert mtls(build, "service-b")["serves"]["api-b"]["allowed_ids"] == ["spiffe://cloud.local/service-a"]
    assert mtls(build, "frontend")["calls"] == {
        "api-a": {"address": "10.30.0.11:9443", "expected_id": "spiffe://cloud.local/service-a",
                  "protocol": "https"}}
    pg_call = mtls(build, "service-b")["calls"]["postgres"]
    assert (pg_call["protocol"], pg_call["db_name"], pg_call["db_user"]) == ("postgres", "appdb", "service_b")
    assert mtls(build, "database")["serves"]["postgres"]["allowed_sources"] == ["10.40.0.11"]
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
    cli = (build / "wireguard/client-remote-client.conf.j2").read_text()
    assert f"Endpoint = {env['entry_point']}:{env['wan_port']}" in cli
    assert "AllowedIPs = 10.20.0.10/32" in cli, "client routes only what policy lets it reach"
    for text in (srv, cli):
        assert not re.search(r"PrivateKey = [A-Za-z0-9+/]{43}=", text), "no real key in templates"


def test_test_peer_is_hostile_and_direct(build, env):
    """The test peer routes every policy network into the tunnel (the gateway must refuse what
    it may not reach) and talks to the gateway on the NAT network: nothing Wi-Fi related."""
    cli = (build / "wireguard/client-test-peer.conf.j2").read_text()
    assert "Endpoint = 192.168.122.10:51820" in cli
    allowed = re.search(r"^AllowedIPs = (.*)$", cli, re.M).group(1).split(", ")
    assert set(allowed) == {"10.10.0.0/24", "10.20.0.0/24", "10.30.0.0/24", "10.40.0.0/24",
                            "10.50.0.0/24", "192.168.122.0/24"}
    assert env["entry_point"] not in cli


def test_inventory_role_groups(build):
    ch = yaml.safe_load((build / "inventory.yml").read_text())["all"]["children"]
    assert list(ch["wireguard"]["hosts"]) == ["gateway"]
    assert list(ch["pki"]["hosts"]) == ["frontend", "service-a", "service-b", "database"]
    assert list(ch["app"]["hosts"]) == ["frontend", "service-a", "service-b"]
    assert list(ch["postgres"]["hosts"]) == ["database"]


def test_wireguard_json(build):
    wg = json.loads((build / "wireguard/wireguard.json").read_text())
    assert wg["server"] == "gateway" and wg["iface"] == "wg0" and wg["port"] == 51820
    assert wg["address"] == "10.10.0.1/24" and wg["endpoint_ip"] == "192.168.122.10"
    assert [(p["name"], p["test"]) for p in wg["peers"]] == [("remote-client", False), ("bot", False), ("test-peer", True)]
    assert wg["peers"][1]["netns"] == "zt-bot" and wg["peers"][1]["conn_limit"] == "5/second"
    assert wg["reachable"] == ["10.20.0.10/32"]


def test_test_peer_template_independent_of_env(policy, env, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    gen_rules.generate(policy, env, a)
    gen_rules.generate(policy, dict(env, wan_interface="enp3s0", wan_port=443,
                                    entry_point="other-host.local"), b)
    for f in ("client-test-peer.conf.j2", "gateway-wg0.conf.j2"):
        assert (a / "wireguard" / f).read_text() == (b / "wireguard" / f).read_text()


@pytest.mark.parametrize("peers,msg", [
    ([{"name": "only-test", "ip": "10.10.0.9", "test": True}], "at least one real"),
    ([{"name": "remote-client", "ip": "10.10.0.2", "test": "yes"}], "test must be true/false"),
    ([{"name": "Bad_Name", "ip": "10.10.0.2"}], "lowercase DNS label"),
])
def test_bad_wireguard_peers_rejected(policy, peers, msg):
    p = json.loads(json.dumps(policy))
    p["wireguard"]["peers"] = peers
    assert any(msg in e for e in gen_rules.validate_policy(p))


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


# ------------------------------------------------------- stage 1: host --
def test_host_apt_cache_guard(build):
    host = (build / "host" / "nftables-zt.conf").read_text()
    accepts = [l for l in host.splitlines() if "dport 3142 accept" in l]
    assert accepts and all('iifname "virbr-zt-mgmt"' in l for l in accepts)
    lines = [l.strip() for l in host.splitlines()]
    drop = lines.index('iifname != "lo" tcp dport 3142 drop comment "zt: host service for mgmt only"')
    assert all(lines.index(a.strip()) < drop for a in accepts), "accepts must come before the drop"


def test_libvirt_hook(build, env):
    hook = build / "host" / "libvirt-hook-network"
    text = hook.read_text()
    assert text.startswith("#!/bin/bash\n")
    r = subprocess.run(["bash", "-n", str(hook)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    rule = (f'-i {env["wan_interface"]} -o virbr-zt-wan -d 192.168.122.10/32 -p udp --dport 51820 '
            f'-m conntrack --ctstate DNAT')
    assert f"iptables -w -I FORWARD 1 {rule}" in text, "must sit in FORWARD, before the jump to LIBVIRT_FWI"
    assert f"iptables -w -D FORWARD {rule}" in text, "must be idempotent"
    assert f"iptables -w -I LIBVIRT_FWI" not in text, "libvirt rebuilds its own chain: never rely on it"
    assert "nft insert rule ip libvirt_network guest_input" in text
    assert "export PATH=/usr/sbin:" in text, "libvirt runs hooks with a minimal PATH"


def test_libvirt_hook_ignores_other_operations(build, tmp_path):
    """On 'stopped' etc. the hook must exit 0 without touching anything."""
    fake = tmp_path / "bin"
    fake.mkdir()
    for b in ("iptables", "nft"):
        (fake / b).write_text(f"#!/bin/sh\necho CALLED >> {tmp_path}/calls\nexit 1\n")
        (fake / b).chmod(0o755)
    hook = (build / "host/libvirt-hook-network").read_text().replace(
        "export PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"export PATH={fake}:/usr/bin:/bin")
    (tmp_path / "hook").write_text(hook)
    r = subprocess.run(["bash", str(tmp_path / "hook"), "zt-wan", "stopped", "end"],
                       env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True)
    assert r.returncode == 0 and not (tmp_path / "calls").exists()


def test_libvirt_hook_runs_with_empty_path(build, tmp_path):
    """Simulate libvirt: no PATH at all. The hook must still find iptables (via its own PATH)."""
    fake = tmp_path / "sbin"
    fake.mkdir()
    # like the real iptables: -D fails once the rule is gone, -L/-I succeed
    (fake / "iptables").write_text(
        f"#!/bin/sh\necho \"$@\" >> {tmp_path}/calls\n"
        "for a in \"$@\"; do [ \"$a\" = -D ] && exit 1; done\nexit 0\n")
    (fake / "iptables").chmod(0o755)
    hook = (build / "host/libvirt-hook-network").read_text().replace(
        "export PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"export PATH={fake}:/usr/bin:/bin")
    (tmp_path / "hook").write_text(hook)
    r = subprocess.run(["/bin/bash", str(tmp_path / "hook"), "zt-dmz", "started", "begin"],
                       env={}, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    calls = (tmp_path / "calls").read_text()
    assert "-I FORWARD 1" in calls, calls


def test_host_json(build):
    h = json.loads((build / "host/host.json").read_text())
    assert h["wan_bridge"] == "virbr-zt-wan"
    assert h["host_services"] == ["tcp/3142"]
    assert h["dnat"] == [{"proto": "udp", "port": 51820, "to": "192.168.122.10:51820", "flow": "wg-ingress"},
                         {"proto": "tcp", "port": 8444, "to": "192.168.122.10:8444", "flow": "partner-webhook"}]


# ---------------------------------------------------- stage 2: terraform --
def test_tfvars_routes_on_the_right_interface(build):
    tf = json.loads((build / "terraform.tfvars.json").read_text())
    by = {n: {i["iface"]: i for i in v["interfaces"]} for n, v in tf["nodes"].items()}
    assert by["gateway"]["wan0"]["routes"] == [{"to": "default", "via": "192.168.122.1"}]
    assert by["frontend"]["dmz0"]["routes"] == [{"to": "10.10.0.0/24", "via": "10.20.0.1"}]
    for n, ifs in by.items():
        for name, i in ifs.items():
            if (n, name) not in {("gateway", "wan0"), ("frontend", "dmz0")}:
                assert i["routes"] == [], f"{n}/{name} must have no route (VMs are never routed)"
    assert [n for n, v in tf["nodes"].items() if v["ip_forward"]] == ["gateway"]
    assert "wan" not in {i["network"] for n, v in tf["nodes"].items() if n != "gateway" for i in v["interfaces"]}


def test_ssh_config_and_inventory(build, env):
    cfg = (build / "ssh_config").read_text()
    assert "Host frontend\n  HostName 10.50.0.20\n" in cfg
    assert f"IdentityFile {env['ssh_public_key_file'][:-4]}\n" in cfg
    inv = yaml.safe_load((build / "inventory.yml").read_text())
    assert inv["all"]["hosts"]["ca"]["ansible_host"] == "10.50.0.10"
    assert inv["all"]["vars"]["ansible_ssh_private_key_file"] == env["ssh_public_key_file"][:-4]


def test_public_key_required(env):
    assert gen_rules.validate_env(dict(env, ssh_public_key_file="~/.ssh/id_ed25519"))


# ------------------------------------------------------------- stage 3: PKI --
def test_pki_identities_and_ca_policy(build):
    pki = json.loads((build / "pki/pki.json").read_text())
    assert pki["ca"]["url"] == "https://10.50.0.10:9000" and pki["lifetime"] == "24h"
    ids = pki["identities"]
    # only nodes that take part in mTLS get a cert; never the gateway or the CA itself
    assert set(ids) == {"frontend", "service-a", "service-b", "database",
                        "customer-alice", "customer-bob", "staff-dev", "bot-statements", "partner-payflow"}
    assert ids["service-b"]["uri"] == "spiffe://cloud.local/service-b"
    assert ids["service-b"]["ips"] == ["10.30.0.12", "10.40.0.11"], "data-plane IPs only, no mgmt"
    a = ids["customer-alice"]
    assert (a["uri"], a["ips"], a["role"], a["actor"], a["export_to"], a["lifetime"]) == (
        "spiffe://cloud.local/customer/alice", [], "customer", "alice", "remote-client", "24h")
    assert ids["bot-statements"]["lifetime"] == "1h", "the bot gets a short-lived certificate"
    assert "export_to" not in ids["customer-bob"], "test actors are never exported"
    allow = pki["x509_policy"]["allow"]
    assert allow["uri"] == ["cloud.local"]
    assert "10.50.0.20" not in allow["ip"], "no mgmt address may ever be certified"
    assert sorted(allow["dns"]) == sorted(i["cn"] for i in ids.values())
    assert pki["x509_policy"]["allowWildcardNames"] is False


# ----------------------------------------------------------- actors / routes --
def routes_of(build, node, svc):
    """{(method, path): ["customer/alice", "frontend", ...]} without the spiffe://cloud.local/ prefix"""
    return {(r["method"], r["path"]): sorted(i.split("cloud.local/", 1)[1] for i in r["allow_ids"])
            for r in mtls(build, node)["serves"][svc]["routes"]}


def test_frontend_routes_per_role(build):
    r = routes_of(build, "frontend", "https")
    customers = ["customer/alice", "customer/bob"]
    assert r[("GET", "/api/accounts")] == customers
    assert r[("POST", "/api/transfers")] == customers
    assert r[("GET", "/api/statements")] == ["bot/statements"]
    assert r[("GET", "/api/status")] == ["staff/dev"]
    assert r[("GET", "/chain")] == ["staff/dev"]
    assert "staff/dev" not in r[("GET", "/api/accounts")], "support staff never sees balances"
    assert "bot/statements" not in r[("POST", "/api/transfers")], "the bot never moves money"


def test_inner_routes_only_for_the_upstream_node(build):
    for node, svc, caller in (("service-a", "api-a", "frontend"), ("service-b", "api-b", "service-a")):
        for (m, p), who in routes_of(build, node, svc).items():
            assert who == [caller], (node, m, p, who)


def test_actor_directory_on_the_frontend(build):
    actors = mtls(build, "frontend")["actors"]
    assert actors["spiffe://cloud.local/customer/alice"] == {"actor": "alice", "role": "customer", "customer": "alice",
                                                             "name": "Alice Martin", "rate_per_min": 240}
    assert actors["spiffe://cloud.local/staff/dev"] == {"actor": "dev", "role": "staff", "name": "dev",
                                                         "rate_per_min": 240}
    assert mtls(build, "service-a")["actors"] == {}, "inner services only know nodes"


def test_every_route_id_is_allowed_by_the_service(build):
    for node in ("frontend", "service-a", "service-b"):
        for svc, s in mtls(build, node)["serves"].items():
            for r in s.get("routes", []):
                assert set(r["allow_ids"]) <= set(s["allowed_ids"]), (node, r)


@pytest.mark.parametrize("mutate,msg", [
    (lambda p: p["actors"]["alice"].update(role="admin"), "unknown role"),
    (lambda p: p["actors"]["alice"].pop("customer"), "`customer` is required"),
    (lambda p: p["actors"]["dev"].update(customer="dev"), "`customer` is required"),
    (lambda p: p["actors"]["alice"].update(export_to="test-peer"), "real (non-test) WireGuard peer"),
    (lambda p: p["actors"]["statements"].update(cert_lifetime="48h"), "above the CA maximum"),
    (lambda p: p["actors"]["statements"].update(cert_lifetime="soon"), "look like 1h"),
    (lambda p: p["actors"]["alice"].update(entry="nowhere"), "entry must be a principal"),
    (lambda p: p["routes"]["https"].append({"name": "x", "method": "GET", "path": "/x", "allow": ["root"]}),
     "neither a role nor a node"),
    (lambda p: p["routes"]["https"].append({"name": "x", "method": "GET", "path": "/x", "allow": ["database"]}),
     "has no flow to https"),
    (lambda p: p["routes"]["api-a"].append({"name": "x", "method": "GET", "path": "/x", "allow": ["customer"]}),
     "no actor of role customer reaches api-a"),
    (lambda p: p["routes"]["https"].append({"name": "x", "method": "FETCH", "path": "/x", "allow": ["staff"]}),
     "method must be"),
    (lambda p: p["routes"]["https"].append(dict(p["routes"]["https"][0])), "duplicate"),
    (lambda p: p["routes"].pop("api-b"), "has no routes"),
    (lambda p: p["routes"].update(postgres=[]), "HTTPS mTLS services only"),
])
def test_bad_actors_and_routes_rejected(policy, mutate, msg):
    p = json.loads(json.dumps(policy))
    mutate(p)
    errs = gen_rules.validate_policy(p)
    assert any(msg in e for e in errs), errs


def test_stateless_replies_only_for_ssh(policy, build):
    """The conntrack-free reply exception is reserved to admin SSH, never to business flows."""
    assert [k for k, v in policy["services"].items() if v.get("stateless_replies")] == ["ssh"]
    for node in NODES:
        for l in nft(build, node).splitlines():
            if "sport" in l and "accept" in l:
                assert "sport 22 " in l or "udp sport 51820" in l, l
