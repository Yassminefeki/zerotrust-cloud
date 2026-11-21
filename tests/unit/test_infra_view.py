"""tools/infra-view.py: the live views, fed with canned outputs of virsh / ip / ssh (as on the cloud
host), render the right placement and flows and never show a Wi-Fi address, a MAC or a key."""
import importlib.util
import time

import pytest

from unit_helpers import ROOT

spec = importlib.util.spec_from_file_location("infra_view", ROOT / "tools/infra-view.py")
iv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iv)

WIFI = ".".join(["10", "25", "14", "145"])
MAC = ":".join(["52", "54", "00", "aa", "bb", "cc"])
NETS = {"zt-wan": "virbr-zt-wan", "zt-dmz": "virbr-zt-dmz", "zt-app": "virbr-zt-app", "zt-data": "virbr-zt-data",
        "zt-mgmt": "virbr-zt-mgmt"}


def fake_sh(cmd, timeout=15):
    if cmd[-3:] == ["net-list", "--all", "--name"]:
        return "\n".join(NETS) + "\n"
    if "net-info" in cmd:
        return f"Name: {cmd[-1]}\nBridge:         {NETS[cmd[-1]]}\n"
    if "domstate" in cmd:
        return "running\n"
    if "dominfo" in cmd:
        return "Max memory:     1048576 KiB\nCPU(s):         1\n"
    if "domiflist" in cmd:
        vm = cmd[-1]
        rows = "".join(f" vnet{i}  network  zt-{n}  virtio  {MAC}\n"
                       for i, n in enumerate(iv.POLICY["nodes"][vm]["interfaces"]))
        return " Interface  Type  Source  Model  MAC\n----\n" + rows
    if cmd[:2] == ["ip", "-br"]:
        return {"virbr-zt-mgmt": "virbr-zt-mgmt UP 10.50.0.1/24\n",
                "virbr-zt-wan": "virbr-zt-wan UP 192.168.122.1/24\n"}.get(cmd[-1], "")
    return ""


def fake_ssh(node, cmd):
    now = int(time.time())
    if cmd.startswith("sudo wg show"):
        return (f"privkey\tpubkey\t51820\toff\n"
                f"PUBREMOTE\t(none)\t{WIFI}:40000\t10.10.0.2/32\t{now - 12}\t1000\t2000\t0\n"
                f"PUBBOT\t(none)\t(none)\t10.10.0.3/32\t0\t0\t0\t0\n")
    if cmd.startswith("ss "):
        return {"frontend": "0 0 10.20.0.10:8443 10.10.0.2:51000\n0 0 10.30.0.10:41000 10.30.0.11:9443\n",
                "service-a": "0 0 10.30.0.11:9443 10.30.0.10:41000\n",
                "database": "0 0 10.40.0.10:5432 10.40.0.11:33000\n"}.get(node, "")
    if "zt-drop" in cmd and node == "gateway":
        return (f"2026-11-21T09:30:01+0100 gateway kernel: zt-drop-fwd: IN=wg0 OUT=app0 MAC={MAC} "
                f"SRC=10.10.0.200 DST=10.30.0.11 LEN=60 PROTO=TCP SPT=4000 DPT=9443\n"
                f"2026-11-21T09:30:02+0100 gateway kernel: zt-drop-in: IN=wan0 SRC={WIFI} DST=192.168.122.10 "
                f"LEN=60 PROTO=TCP SPT=4000 DPT=22\n")
    return ""


@pytest.fixture(autouse=True)
def canned(monkeypatch, tmp_path):
    monkeypatch.setattr(iv, "sh", fake_sh)
    monkeypatch.setattr(iv, "ssh", fake_ssh)
    wg = tmp_path / "ansible/.secrets/wireguard"
    wg.mkdir(parents=True)
    (wg / "remote-client.pub").write_text("PUBREMOTE\n")
    (wg / "bot.pub").write_text("PUBBOT\n")
    monkeypatch.setattr(iv, "REPO", tmp_path)


def run(view, capsys):
    iv.VIEWS[view]()
    return capsys.readouterr().out


def test_vms_sit_on_their_policy_networks(capsys):
    out = run("vms", capsys)
    assert "frontend" in out and "dmz:10.20.0.10" in out and "app:10.30.0.10" in out
    assert "database" in out and "data:10.40.0.10" in out and MAC not in out


def test_networks_and_where_the_host_has_an_address(capsys):
    out = run("nets", capsys)
    assert "10.50.0.1/24" in out and "virbr-zt-dmz" in out and "(aucune)" in out


def test_tunnel_shows_peer_names_never_keys_nor_wifi(capsys):
    out = run("wg", capsys)
    assert "remote-client" in out and "il y a 12 s" in out and "jamais" in out
    assert "PUBREMOTE" not in out and WIFI not in out


def test_live_connections_name_both_ends(capsys):
    out = run("conns", capsys)
    assert "remote-client(tunnel)" in out and "frontend(dmz)" in out
    assert "frontend(app)" in out and "service-a(app)" in out and "service-b(data)" in out


def test_drops_are_named_and_masked(capsys):
    out = run("drops", capsys)
    assert "test-peer(tunnel)" in out and "service-a(app):9443" in out
    assert WIFI not in out and MAC not in out and "<wifi-ip>" in out


def test_live_map(capsys):
    out = run("map", capsys)
    assert "handshake il y a 12 s" in out and "connexion(s) active(s)" in out
    assert "gateway" in out and "ca" in out and WIFI not in out


def test_graphical_live_map_serves_the_real_state(monkeypatch):
    """tools/infra-live.py: /state is the live data (same readers), the page draws it, only on localhost."""
    spec2 = importlib.util.spec_from_file_location("infra_live", ROOT / "tools/infra-live.py")
    live = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(live)
    monkeypatch.setattr(live, "iv", iv)
    st = live.state()
    assert set(st) == {"time", "vms", "peers", "conns", "drops"}
    assert st["vms"]["frontend"] == "running"
    assert {"src": "remote-client(tunnel)", "dst": "frontend(dmz)", "port": "8443", "service": "https"} in st["conns"]
    blob = str(st)
    assert WIFI not in blob and MAC not in blob and "PUBREMOTE" not in blob
    assert "<svg" in live.PAGE and "fetch(\"/state\")" in live.PAGE
    assert '("127.0.0.1", a.port)' in (ROOT / "tools/infra-live.py").read_text()
