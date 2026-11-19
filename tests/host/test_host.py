"""Stage 1 — the i5 is ready to host the cloud. Run with `make test-1` (on the i5)."""
import ipaddress
import json
import os
import re
import socket
from pathlib import Path

import pytest

from ztlib import ROOT, run, need

pytestmark = pytest.mark.host


# ------------------------------------------------------------- preflight --
def _wan_ipv4s(iface):
    out = run(["ip", "-j", "-4", "addr", "show", "dev", iface], check=True).stdout
    return {a["local"] for l in json.loads(out) for a in l.get("addr_info", [])}


def test_wan_interface_exists_and_has_an_address(env):
    assert _wan_ipv4s(env["wan_interface"]), f"{env['wan_interface']} has no IPv4 address"


def test_entry_point_resolves_to_this_host(env):
    """entry_point is a NAME (mDNS). It must resolve to whatever address wan_interface has
    right now — that's what makes the setup Wi-Fi independent."""
    need("avahi-resolve")
    r = run(["avahi-resolve", "-4", "-n", env["entry_point"]], timeout=10)
    assert r.returncode == 0 and r.stdout.strip(), f"{env['entry_point']} does not resolve: {r.stderr}"
    resolved = r.stdout.split()[-1]
    assert resolved in _wan_ipv4s(env["wan_interface"]), \
        f"{env['entry_point']} -> {resolved}, not an address of {env['wan_interface']}"


def test_entry_point_resolves_via_nss(env):
    """Same through the normal resolver (libnss-mdns), which is what wg-quick on a client uses."""
    infos = socket.getaddrinfo(env["entry_point"], None, socket.AF_INET)
    assert {i[4][0] for i in infos} & _wan_ipv4s(env["wan_interface"])


# ------------------------------------------------------------ virtualisation --
def test_kvm_usable_by_user():
    assert os.access("/dev/kvm", os.R_OK | os.W_OK), "add yourself to the kvm group and re-login"


def test_libvirtd_active_and_reachable(env):
    assert run(["systemctl", "is-active", "libvirtd"]).stdout.strip() == "active"
    r = run(["virsh", "-c", env["libvirt_uri"], "version"])
    assert r.returncode == 0, f"cannot talk to libvirt as user (libvirt group? re-login?): {r.stderr}"


def test_no_libvirt_network_overlaps_policy_except_ours(env, zt_host):
    cidrs = [ipaddress.ip_network(c) for c in zt_host["policy_cidrs"]]
    names = run(["virsh", "-c", env["libvirt_uri"], "net-list", "--name"], check=True).stdout.split()
    for n in names:
        if n.startswith("zt-"):
            continue
        xml = run(["virsh", "-c", env["libvirt_uri"], "net-dumpxml", n], check=True).stdout
        for m in re.finditer(r"<ip address='([\d.]+)'", xml):
            ip = ipaddress.ip_address(m.group(1))
            assert not any(ip in c for c in cidrs), f"active libvirt network '{n}' uses {ip}"


def test_tooling_versions():
    tf = run(["terraform", "version", "-json"], check=True).stdout
    major, minor = map(int, json.loads(tf)["terraform_version"].split(".")[:2])
    assert (major, minor) >= (1, 5)
    a = run(["ansible-playbook", "--version"], check=True).stdout
    core = re.search(r"core ([\d.]+)", a).group(1)
    assert tuple(map(int, core.split(".")[:2])) >= (2, 15), f"ansible-core {core} too old"
    cols = run(["ansible-galaxy", "collection", "list"], check=True).stdout
    for c in ("ansible.posix", "community.general"):
        assert c in cols, f"missing collection {c} (make host installs it)"
    for b in ("mkisofs", "xsltproc", "wg", "tcpdump", "nft", "openssl", "nc"):
        need(b)


def test_ssh_key_present(env):
    assert Path(os.path.expanduser(env["ssh_public_key_file"])).is_file()


# --------------------------------------------------------------- network --
def test_ip_forward_on_and_persistent():
    assert Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    assert "net.ipv4.ip_forward=1" in Path("/etc/sysctl.d/90-zerotrust.conf").read_text().replace(" ", "")


def test_host_rules_service_enabled_and_active():
    assert run(["systemctl", "is-enabled", "zerotrust-host"]).stdout.strip() == "enabled"
    assert run(["systemctl", "is-active", "zerotrust-host"]).stdout.strip() == "active"


def test_dnat_by_interface_name(env, zt_host):
    table = run(["nft", "list", "table", "inet", "zt_host"], sudo=True, check=True).stdout
    for d in zt_host["dnat"]:
        port = env["wan_port"] if d["proto"] == "udp" else d["port"]   # WireGuard: env; partner API: policy
        assert re.search(rf'iifname "{re.escape(env["wan_interface"])}" {d["proto"]} dport '
                         rf'{port} dnat ip to {re.escape(d["to"])}', table), table
    # by NAME only: no address of the WAN interface appears in the table
    for ip in _wan_ipv4s(env["wan_interface"]):
        assert ip not in table


def test_no_wifi_ip_in_installed_config(env):
    for f in ("/etc/zerotrust/nftables-zt.conf", "/etc/libvirt/hooks/network.d/zerotrust"):
        text = run(["cat", f], sudo=True, check=True).stdout
        for ip in _wan_ipv4s(env["wan_interface"]):
            assert ip not in text, f"{f} contains the Wi-Fi IP {ip}"


def test_host_never_default_drops():
    ruleset = run(["nft", "list", "table", "inet", "zt_host"], sudo=True, check=True).stdout
    assert "policy drop" not in ruleset


def test_libvirt_hook_installed():
    p = "/etc/libvirt/hooks/network.d/zerotrust"
    r = run(["test", "-x", p], sudo=True)
    assert r.returncode == 0, f"{p} missing or not executable"


def test_default_network_disabled(env):
    r = run(["virsh", "-c", env["libvirt_uri"], "net-info", "default"])
    if r.returncode == 0:  # defined: must be inactive and not autostarted
        assert re.search(r"Active:\s+no", r.stdout) and re.search(r"Autostart:\s+no", r.stdout)


# ------------------------------------------------------------- apt cache --
def test_apt_cacher_ng_up():
    assert run(["systemctl", "is-active", "apt-cacher-ng"]).stdout.strip() == "active"
    assert run(["bash", "-c", "ss -ltn '( sport = :3142 )' | grep -q 3142"]).returncode == 0


def test_apt_cache_not_exposed_to_wan(zt_host):
    table = run(["nft", "list", "table", "inet", "zt_host"], sudo=True, check=True).stdout
    for svc in zt_host["host_services"]:
        proto, port = svc.split("/")
        assert f'iifname != "lo" {proto} dport {port} drop' in table


def test_avahi_only_on_wan(env):
    assert run(["systemctl", "is-active", "avahi-daemon"]).stdout.strip() == "active"
    conf = Path("/etc/avahi/avahi-daemon.conf").read_text()
    assert re.search(rf"^allow-interfaces={re.escape(env['wan_interface'])}\s*$", conf, re.M)


def test_libvirtd_reruns_hook_on_start():
    """libvirtd is socket-activated: each start rebuilds LIBVIRT_FWI without calling hooks."""
    out = run(["systemctl", "show", "libvirtd", "-p", "ExecStartPost"]).stdout
    assert "/etc/libvirt/hooks/network.d/zerotrust" in out


def test_apt_cacher_ng_retries():
    conf = Path("/etc/apt-cacher-ng/acng.conf").read_text()
    assert re.search(r"^DlMaxRetries: *[1-9]", conf, re.M)
