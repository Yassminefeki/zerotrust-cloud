"""Stage 2 — libvirt networks and the 6 VMs match policy.yaml. Run with `make test-2` (on the i5).

Everything expected is read from build/terraform.tfvars.json (generated from policy.yaml):
no IP is written in this file."""
import json
import re

import pytest
import testinfra

from ztlib import BUILD, run

pytestmark = pytest.mark.infra

TF = json.loads((BUILD / "terraform.tfvars.json").read_text()) if (BUILD / "terraform.tfvars.json").exists() else None
NETS = sorted(TF["networks"]) if TF else []
NODES = sorted(TF["nodes"]) if TF else []


@pytest.fixture(scope="session")
def tf():
    if TF is None:
        pytest.exit("run `make gen` first", returncode=2)
    return TF


@pytest.fixture(scope="session")
def vm():
    cache = {}

    def get(name):
        if name not in cache:
            cache[name] = testinfra.get_host(f"ssh://{name}", ssh_config=str(BUILD / "ssh_config"))
        return cache[name]
    return get


def virsh(env, *args, check=True):
    return run(["virsh", "-c", env["libvirt_uri"], *args], check=check).stdout


# ---------------------------------------------------------------- networks --
@pytest.mark.parametrize("net", NETS)
def test_network_active_autostart_and_mode(env, tf, net):
    spec = tf["networks"][net]
    info = virsh(env, "net-info", spec["name"])
    assert re.search(r"Active:\s+yes", info) and re.search(r"Autostart:\s+yes", info)
    assert re.search(rf"Bridge:\s+{re.escape(spec['bridge'])}\b", info)
    xml = virsh(env, "net-dumpxml", spec["name"])
    if spec["mode"] == "nat":
        assert "<forward mode='nat'" in xml
    else:
        assert "<forward" not in xml, f"{net} must be isolated (no <forward>)"
    assert "<dhcp" not in xml and "<range" not in xml, "no DHCP: addresses are static"


@pytest.mark.parametrize("net", NETS)
def test_host_address_only_where_declared(tf, net):
    spec = tf["networks"][net]
    out = json.loads(run(["ip", "-j", "-4", "addr", "show", "dev", spec["bridge"]], check=True).stdout)
    addrs = [a["local"] for l in out for a in l.get("addr_info", [])]
    assert addrs == ([spec["host_ip"]] if spec["host_ip"] else []), \
        f"{spec['bridge']}: host must be pure L2 on isolated data-plane networks"


def test_host_has_no_route_into_data_planes(tf):
    routes = json.loads(run(["ip", "-j", "-4", "route"], check=True).stdout)
    l2_only = {s["bridge"] for s in tf["networks"].values() if not s["host_ip"]}
    assert not [r for r in routes if r.get("dev") in l2_only]


def test_libvirt_default_network_still_off(env):
    r = run(["virsh", "-c", env["libvirt_uri"], "net-info", "default"])
    assert r.returncode != 0 or re.search(r"Active:\s+no", r.stdout)


def test_wireguard_accept_precedes_libvirt_reject():
    """libvirt's LIBVIRT_FWI rejects new inbound traffic to zt-wan. Our accept must be in FORWARD
    BEFORE the jump to LIBVIRT_FWI (libvirt never reorders that jump, so it stays there)."""
    r = run(["iptables", "-w", "-S", "FORWARD"], sudo=True)
    if r.returncode != 0 or "LIBVIRT_FWI" not in r.stdout:   # nftables backend
        chain = run(["nft", "list", "chain", "ip", "libvirt_network", "guest_input"], sudo=True, check=True).stdout
        rules = [l.strip() for l in chain.splitlines() if "virbr-zt-wan" in l]
        assert rules and "zt:wg-ingress" in rules[0], "\n".join(rules)
        return
    rules = [l for l in r.stdout.splitlines() if l.startswith("-A FORWARD")]
    ours = [i for i, l in enumerate(rules) if "zt:wg-ingress" in l]
    jump = [i for i, l in enumerate(rules) if l.endswith("-j LIBVIRT_FWI")]
    assert len(ours) == 1, "exactly one copy of the WireGuard accept:\n" + "\n".join(rules)
    assert jump and ours[0] < jump[0], "accept must precede the jump to LIBVIRT_FWI:\n" + "\n".join(rules)


def test_libvirt_reject_still_guards_other_inbound():
    """We add ONE exception; libvirt's reject for anything else into zt-wan must still exist."""
    out = run(["iptables", "-w", "-S", "LIBVIRT_FWI"], sudo=True).stdout
    if out:
        assert re.search(r"-o virbr-zt-wan -j REJECT", out)


# --------------------------------------------------------------------- VMs --
@pytest.mark.parametrize("name", NODES)
def test_domain_running_with_declared_memory(env, tf, name):
    assert virsh(env, "domstate", f"zt-{name}").strip() == "running"
    info = virsh(env, "dominfo", f"zt-{name}")
    kib = int(re.search(r"Max memory:\s+(\d+) KiB", info).group(1))
    assert kib == tf["nodes"][name]["memory_mb"] * 1024
    assert re.search(r"Autostart:\s+enable", info)


@pytest.mark.parametrize("name", NODES)
def test_ssh_over_mgmt_and_cloud_init_done(vm, name):
    h = vm(name)
    assert h.run("hostname").stdout.strip() == name
    # first boot may still be finishing (runcmd applies the sysctls at the very end)
    status = h.run("timeout 600 cloud-init status --wait; cloud-init status").stdout
    assert "status: done" in status, status


@pytest.mark.parametrize("name", NODES)
def test_interfaces_names_and_ips_exact(vm, tf, policy, name):
    h = vm(name)
    got = {}
    for l in json.loads(h.check_output("ip -j -4 addr")):
        if l["ifname"] == "lo":
            continue
        got[l["ifname"]] = sorted(f'{a["local"]}/{a["prefixlen"]}' for a in l.get("addr_info", []))
    want = {i["iface"]: [f'{i["ip"]}/{i["prefix"]}'] for i in tf["nodes"][name]["interfaces"]}
    # The WireGuard interface is not a libvirt NIC: it appears in stage 5, on the policy's
    # tunnel node only, with the policy's tunnel address (checked here once it exists).
    tun = policy["networks"].get("tunnel", {})
    if "tunnel" in policy["nodes"][name]["interfaces"] and tun.get("iface") in got:
        prefix = tun["cidr"].split("/")[1]
        want[tun["iface"]] = [f'{policy["nodes"][name]["interfaces"]["tunnel"]}/{prefix}']
    assert got == want


@pytest.mark.parametrize("name", NODES)
def test_routes_exact(vm, tf, name):
    """Only connected routes, plus exactly the routes declared in policy.yaml."""
    h = vm(name)
    routes = json.loads(h.check_output("ip -j -4 route"))
    extra = sorted((r["dst"], r.get("gateway"), r["dev"]) for r in routes if r.get("protocol") != "kernel")
    want = sorted((("default" if x["to"] == "default" else x["to"]), x["via"], i["iface"])
                  for i in tf["nodes"][name]["interfaces"] for x in i["routes"])
    assert extra == want


@pytest.mark.parametrize("name", NODES)
def test_lean_apt_config(vm, name):
    conf = vm(name).file("/etc/apt/apt.conf.d/90zerotrust").content_string
    assert 'Pipeline-Depth "0"' in conf and 'Languages "none"' in conf


@pytest.mark.parametrize("name", NODES)
def test_sysctl_hardening(vm, tf, name):
    h = vm(name)
    assert h.sysctl("net.ipv4.ip_forward") == (1 if tf["nodes"][name]["ip_forward"] else 0)
    assert h.sysctl("net.ipv6.conf.all.disable_ipv6") == 1
    assert h.sysctl("net.ipv4.conf.all.rp_filter") == 1
    assert h.sysctl("net.ipv4.conf.all.accept_redirects") == 0


@pytest.mark.parametrize("name", [n for n in NODES if n != "gateway"])
def test_no_way_out_except_gateway(vm, name):
    # RFC 5737 address: anything not on a connected network is unreachable
    r = vm(name).run("ip route get 192.0.2.1")
    assert r.rc != 0, f"{name} has a route out: {r.stdout}"


@pytest.mark.parametrize("src,dst_net", [("service-a", "data"), ("frontend", "data"), ("database", "app"),
                                         ("ca", "app"), ("ca", "data"), ("ca", "dmz")])
def test_vms_are_not_routed_between_networks(vm, tf, src, dst_net):
    target = next(i["ip"] for n in tf["nodes"].values() for i in n["interfaces"] if i["network"] == dst_net)
    assert vm(src).run(f"ip route get {target}").rc != 0


@pytest.mark.parametrize("name", NODES)
def test_apt_cache_reachable_over_mgmt(vm, tf, name):
    mgmt_host = tf["networks"]["mgmt"]["host_ip"]
    code = vm(name).check_output(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 "
                                 f"http://{mgmt_host}:3142/acng-report.html")
    assert code == "200"


def test_apt_update_through_cache(vm):
    r = vm("ca").run("sudo apt-get update -q")
    assert r.rc == 0, r.stderr[-2000:]


@pytest.mark.parametrize("name", NODES)
def test_disk_is_file_backed_qcow2_and_confined(env, tf, name):
    """The XSLT in vms.tf must turn the pool volume into a file disk (so virt-aa-helper can
    confine it) while keeping the qcow2 driver (raw would let a guest forge a backing file)."""
    xml = virsh(env, "dumpxml", f"zt-{name}")
    disk = re.search(r"<disk type='(\w+)' device='disk'>(.*?)</disk>", xml, re.S)
    assert disk and disk.group(1) == "file", "system disk must be type='file'"
    assert "type='qcow2'" in disk.group(2)
    assert f"{tf['pool_path']}/zt-{name}.qcow2" in disk.group(2)
    assert re.search(r"<seclabel type='dynamic' model='apparmor'", xml), "AppArmor must confine the VM"
