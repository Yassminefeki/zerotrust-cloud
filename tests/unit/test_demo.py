"""The narrated demos (tools/demo.py, remote-client/demo.py): what they show and record is anonymised,
their scenes match the shared scenario (docs/24-scenario-demo.md), and captures render."""
import getpass
import importlib.util
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from unit_helpers import ROOT

sys.path.insert(0, str(ROOT / "tools"))
import demo_lib  # noqa: E402


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_sanitizer_hides_what_identifies_the_machines():
    clean = demo_lib.Sanitizer("cloud-host", extra=("secret-host.example",))
    host, user, home = socket.gethostname(), getpass.getuser(), str(Path.home())
    wifi = ".".join(["10", "25", "15", "12"])           # a home-LAN address (built, not written)
    mac = ":".join(["a4", "c3", "f0", "11", "22", "33"])
    text = (f"{user}@{host}:{home}/Documents/x  from {wifi} MAC={mac} to secret-host.example "
            f"via 10.20.0.10:8443 and 192.168.122.10 {ROOT}/tools")
    out = clean(text)
    for leak in (host, wifi, mac, "secret-host.example", str(ROOT)):
        assert leak not in out, leak
    if user != "root":
        assert user not in out
    if home != "/root":
        assert home not in out
    assert "10.20.0.10:8443" in out and "192.168.122.10" in out        # the policy's virtual networks stay
    assert "<wifi-ip>" in out and "<mac>" in out and "<hidden>" in out and "<repo>" in out


def test_commands_are_shown_run_and_recorded_sanitised(tmp_path, capsys):
    d = demo_lib.Demo("cloud-host", "cloud-host$", tmp_path, fast=True)
    d.scene("C9", "test", ["explain"])
    wifi = ".".join(["10", "25", "15", "12"])
    d.run([sys.executable, "-c", f"print('peer {wifi} HTTP 403 refused')"], shown=f"probe {wifi}")
    d.done()
    rec = (tmp_path / "C9.txt").read_text()
    assert wifi not in rec and wifi not in capsys.readouterr().out
    assert "cloud-host$ probe <wifi-ip>" in rec and "HTTP 403" in rec


@pytest.mark.parametrize("script,ids", [("tools/demo.py", [f"C{i}" for i in range(1, 9)]),
                                        ("remote-client/demo.py", [f"R{i}" for i in range(1, 9)])])
def test_scene_lists_match_the_scenario(script, ids):
    out = subprocess.run([sys.executable, str(ROOT / script), "--list"], capture_output=True, text=True,
                         cwd=ROOT).stdout
    assert [l.split()[0] for l in out.splitlines()] == ids
    doc = (ROOT / "docs/24-scenario-demo.md").read_text()
    for i in ids:
        assert f"`{i}`" in doc, f"{i} missing from the scenario"


def test_captures_render_and_are_sanitised_again(tmp_path):
    pytest.importorskip("PIL")
    render = load("tools/render_captures.py", "render_captures")
    src = tmp_path / "cloud-host"
    src.mkdir()
    (src / "C1.txt").write_text(f"# Le cloud\ncloud-host$ virsh list\n {socket.gethostname()} running\n"
                                "   [REFUSED (as expected)] x\n")
    out = tmp_path / "png"
    subprocess.run([sys.executable, str(ROOT / "tools/render_captures.py"), str(src), "--out", str(out)],
                   check=True, capture_output=True)
    png = out / "cloud-host-C1.png"
    from PIL import Image
    assert png.exists() and Image.open(png).size[0] > 1000
    assert render.color("   [REFUSED (as expected)] x", "cloud-host$") == render.GREEN
