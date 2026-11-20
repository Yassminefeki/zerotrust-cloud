"""Stage 13 — the attack suites themselves, tested offline.

* the catalogue names only tests that exist, and only remote checks that are implemented;
* the runner maps pytest results back to attacks (DEFENDED / BREACH / INCOMPLETE) and writes the report;
* the port scanner tells open, refused and silent apart;
* remote-client/attack.py reads every address from the policy, and against the real services
  (the local bank harness) reports DEFENDED — and BREACH when a defence is missing.
"""
import ast
import importlib.util
import json
import re
import shutil
import socket
import subprocess
import sys
import textwrap
from argparse import Namespace

import pytest
import yaml

from test_bank_app import bank  # noqa: F401  (fixture: the three services + PostgreSQL, locally)
from unit_helpers import ROOT

CATALOGUE = yaml.safe_load((ROOT / "tests/attacks/catalogue.yaml").read_text())


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


attack = load("remote-client/attack.py", "rc_attack")
runner = load("tools/zt-attack.py", "zt_attack")


# --------------------------------------------------------------- catalogue --
def test_catalogue_is_a1_to_a11_with_every_field():
    assert list(CATALOGUE) == [f"A{i}" for i in range(1, 12)]
    for a, spec in CATALOGUE.items():
        assert {"title", "attacker", "goal", "defence", "tests"} <= set(spec), a
        assert spec["tests"], a


def _functions(path):
    return {n.name for n in ast.walk(ast.parse((ROOT / path).read_text())) if isinstance(n, ast.FunctionDef)}


@pytest.mark.parametrize("ref", sorted({r for s in CATALOGUE.values() for r in s["tests"]}))
def test_every_catalogue_test_exists(ref):
    path, _, func = ref.partition("::")
    assert (ROOT / path).is_file(), ref
    if func:
        assert func in _functions(path), ref


def test_every_remote_check_is_implemented():
    remote = {b for s in CATALOGUE.values() for b in s.get("remote", [])}
    assert remote <= set(attack.CHECKS) and set(attack.CHECKS) == set(attack.RUN)
    assert remote == set(attack.CHECKS), "every remote check belongs to an attack"


def test_new_live_tests_are_all_in_the_catalogue():
    refs = {r for s in CATALOGUE.values() for r in s["tests"]}
    for f in sorted(_functions("tests/attacks/test_attacks.py")):
        if f.startswith("test_"):
            assert f"tests/attacks/test_attacks.py::{f}" in refs, f


# ------------------------------------------------------------------ runner --
def test_runner_matching():
    assert runner.covers("tests/a/test_x.py::test_y", "tests/a/test_x.py::test_y")
    assert runner.covers("tests/a/test_x.py::test_y", "tests/a/test_x.py::test_y[p1-2]")
    assert not runner.covers("tests/a/test_x.py::test_y", "tests/a/test_x.py::test_y_other")
    assert runner.covers("tests/a/test_x.py", "tests/a/test_x.py::anything")
    assert runner.verdict([{"result": "passed"}]) == "DEFENDED"
    assert runner.verdict([{"result": "passed"}, {"result": "failed"}]) == "BREACH"
    assert runner.verdict([{"result": "skipped"}]) == "INCOMPLETE"
    assert runner.verdict([]) == "INCOMPLETE"


def test_runner_end_to_end(tmp_path, monkeypatch):
    """A fake catalogue over a fake test module: one attack defended, one breached, one whose test
    is skipped, one with a test that does not exist."""
    (tmp_path / "tests/fake").mkdir(parents=True)
    (tmp_path / "tests/fake/test_fake.py").write_text(textwrap.dedent("""
        import pytest
        def test_ok(): pass
        @pytest.mark.parametrize("x", [1, 2])
        def test_param(x): pass
        def test_broken(): assert False, "the door was open"
        def test_skip(): pytest.skip("no VM")
    """))
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    cat = {"A1": {"title": "t1", "attacker": "x", "goal": "g", "defence": "d",
                  "tests": ["tests/fake/test_fake.py::test_ok", "tests/fake/test_fake.py::test_param"]},
           "A2": {"title": "t2", "attacker": "x", "goal": "g", "defence": "d",
                  "tests": ["tests/fake/test_fake.py::test_ok", "tests/fake/test_fake.py::test_broken"]},
           "A3": {"title": "t3", "attacker": "x", "goal": "g", "defence": "d",
                  "tests": ["tests/fake/test_fake.py::test_skip"]}}
    (tmp_path / "cat.yaml").write_text(yaml.safe_dump(cat))
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    monkeypatch.setattr(runner, "CATALOGUE", tmp_path / "cat.yaml")
    monkeypatch.setattr(runner, "REPORTS", tmp_path / "reports")
    monkeypatch.setattr(sys, "argv", ["zt-attack.py", "-q"])
    assert runner.main() == 1
    rep = json.loads((tmp_path / "reports/attacks.json").read_text())["attacks"]
    assert {a: v["verdict"] for a, v in rep.items()} == {"A1": "DEFENDED", "A2": "BREACH", "A3": "INCOMPLETE"}
    assert len(rep["A1"]["tests"]) == 3            # test_ok + both parameters
    md = (tmp_path / "reports/attacks.md").read_text()
    assert "❌ BREACH" in md and "the door was open" in md and "✅ DEFENDED" in md
    monkeypatch.setattr(sys, "argv", ["zt-attack.py", "--only", "1", "-q"])
    assert runner.main() == 0


def test_runner_rejects_unknown_attacks():
    with pytest.raises(SystemExit):
        runner.select(CATALOGUE, "A99")
    assert runner.select(CATALOGUE, "1, a5") == ["A1", "A5"]


# ---------------------------------------------------------------- scanner --
def test_port_scan_tells_open_refused_and_silent():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        r = subprocess.run([sys.executable, str(ROOT / "tests/port_scan.py"), "127.0.0.1",
                            "--ports", f"{port},{port + 1 if port < 65535 else port - 1}"],
                           capture_output=True, text=True, check=True)
    finally:
        srv.close()
    out = json.loads(r.stdout)
    assert out["open"] == [port] and out["refused"] == 1 and out["scanned"] == 2


# ----------------------------------------------------------- remote client --
def ctx(**over):
    a = Namespace(cloud_host="cloud-host.local", partner_port=0, alice="/nonexistent", dev="/nonexistent",
                  iface="wg0", quick=True, minutes=0.2, poll=0.5, report="r.json")
    c = attack.Ctx(a)
    for k, v in over.items():
        setattr(c, k, v)
    return c


def test_remote_client_reads_everything_from_the_policy():
    c = ctx()
    pol = yaml.safe_load((ROOT / "policy.yaml").read_text())
    s = pol["services"]["https"]
    assert (c.web_ip, c.web_port) == (pol["nodes"][s["node"]]["interfaces"][s["network"]], s["port"])
    assert c.partner_port == pol["services"]["partner-api"]["port"]
    inside = {(ip, p) for ip, p, _ in c.inside}
    db = pol["services"]["postgres"]
    assert (pol["nodes"][db["node"]]["interfaces"][db["network"]], db["port"]) in inside
    assert (c.web_ip, c.web_port) not in inside
    assert not any(ip.startswith(pol["networks"]["wan"]["cidr"].rsplit(".", 1)[0] + ".") for ip, _, _ in c.inside)
    assert set(c.nets) == {n["cidr"] for k, n in pol["networks"].items() if k != "wan"}


def test_remote_client_script_has_no_address_of_its_own():
    src = (ROOT / "remote-client/attack.py").read_text()
    assert not re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", src)


@pytest.fixture(scope="module")
def remote(bank, tmp_path_factory):  # noqa: F811
    """The friend's folders, as exported by the cloud host, made from the harness certificates."""
    d, out = bank["dir"], {}
    base = tmp_path_factory.mktemp("downloads")
    for actor in ("alice", "dev"):
        f = base / f"zt-{actor}"
        f.mkdir()
        shutil.copy(d / f"{actor}.crt", f / "client.crt")
        shutil.copy(d / f"{actor}.key", f / "client.key")
        shutil.copy(d / "root.crt", f / "root_ca.crt")
        out[actor] = f
    web_ip, web_port = bank["url"].rsplit(":", 1)
    p_ip, p_port = bank["partner_url"].rsplit(":", 1)
    return dict(web_ip=web_ip, web_port=int(web_port), cloud_host=p_ip, partner_port=int(p_port),
                actors=out, root=str(out["alice"] / "root_ca.crt"))


def play(check, **over):
    res = attack.Result(check)
    attack.RUN[check](ctx(**over), res)
    return res


@pytest.mark.parametrize("check", ["B2", "B4", "B5"])
def test_remote_checks_against_the_real_services(remote, check, capsys):
    """(run with -s and ZT_SHOW=1 to see the probes)"""
    res = play(check, **remote)
    assert res.verdict == "DEFENDED", json.dumps(res.as_dict(), indent=1)
    assert len(res.probes) >= 3, res.probes
    out = capsys.readouterr().out
    assert "BEGIN" not in out and "PRIVATE" not in out
    if __import__("os").environ.get("ZT_SHOW"):
        with capsys.disabled():
            print(out)


def test_remote_check_reports_a_breach_when_a_defence_is_missing(remote):
    """Make the script believe Alice's own account is someone else's: reading it succeeds, which
    must be reported as a BREACH (the checker is not a rubber stamp)."""
    res = play("B4", customers={"alice": "alice", "bob": "alice"}, **remote)
    assert res.verdict == "BREACH"
    assert any(not p["refused"] and "IDOR" in p["probe"] for p in res.probes)


def test_remote_b6_sees_the_revocation(remote, bank):  # noqa: F811
    from test_bank_app import write_revoked
    serial = subprocess.run(["openssl", "x509", "-in", str(remote["actors"]["alice"] / "client.crt"),
                             "-noout", "-serial"], capture_output=True, text=True, check=True).stdout
    serial = serial.strip().split("=")[1]
    res = attack.Result("B6")
    c = ctx(**remote)
    import threading
    import time

    def later():
        time.sleep(1.5)
        write_revoked(bank["dir"] / "revoked.json", [serial])
    t = threading.Thread(target=later)
    t.start()
    try:
        attack.RUN["B6"](c, res)
    finally:
        t.join()
        write_revoked(bank["dir"] / "revoked.json", [])
    assert res.verdict == "DEFENDED" and "revoked" in res.probes[0]["detail"], res.as_dict()


def test_remote_checks_skip_cleanly_without_tunnel_or_files():
    res = play("B4")                                   # no Alice folder
    assert res.verdict == "SKIPPED"
    res = play("B3")
    assert res.verdict == "SKIPPED"                    # not root (or no wg) here
