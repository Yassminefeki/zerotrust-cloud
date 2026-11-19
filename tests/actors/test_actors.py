"""Stage 9 — actors and per-route permissions. Run with `make test-9` (on the i5, sudo).

Every actor of policy.yaml calls every route of the frontend through the WireGuard tunnel, with
its own certificate. The expected answer comes from the policy (routes x roles):
  * route open to the actor's role  -> passes the route check (200, or 501 if not deployed yet);
  * route not open to it            -> 403, logged by the frontend;
  * method + path not in the policy -> 404, whoever asks.
"""
import json
import re
import time

import pytest
import yaml

from ztlib import ROOT
from ztlive import (PKI, VMs, actor_creds, actor_identity, ensure_peer, frontend_node, frontend_url,
                    mtls, probe_tunnel, push, run_script, ROOT_CA)

pytestmark = pytest.mark.actors

POLICY = yaml.safe_load((ROOT / "policy.yaml").read_text())
ACTORS = [a for a in POLICY.get("actors", {}) if POLICY["actors"][a].get("entry") == "tunnel"]
ROUTES = POLICY.get("routes", {}).get("https", [])


def concrete(path):
    return path.replace("*", "A-0001")


def case_id(c):
    a, r = c
    return f"{a}:{r['method']} {r['path']}"


CASES = [(a, r) for a in ACTORS for r in ROUTES]


@pytest.fixture(scope="module")
def peer():
    return ensure_peer()


@pytest.fixture(scope="module")
def vm():
    return VMs()


def call(actor, method, path, data=None):
    return probe_tunnel(frontend_url(path), *actor_creds(actor), method=method,
                        data=("{}" if method != "GET" and data is None else data))


def route_refusal(r):
    """True when the refusal came from the ROUTE layer (not a later business check)."""
    reason = r["body"].get("reason", "") if isinstance(r["body"], dict) else ""
    return r["status"] in (403, 404) and (reason.startswith("route ") or reason.startswith("no route"))


@pytest.mark.parametrize("case", CASES, ids=[case_id(c) for c in CASES])
def test_route_matrix(peer, case):
    actor, route = case
    allowed = POLICY["actors"][actor]["role"] in route["allow"]
    r = call(actor, route["method"], concrete(route["path"]))
    assert r["tls"] == "TLSv1.3", r
    if allowed:
        # passing the route check: 200 when implemented, 501 until its stage is deployed;
        # later business refusals (e.g. someone else's account) are not route refusals
        assert not route_refusal(r), f"{actor} should pass route {route['name']}: {r}"
    else:
        assert r["status"] == 403 and route_refusal(r), f"{actor} must be refused {route['name']}: {r}"


@pytest.mark.parametrize("actor", ACTORS)
def test_whoami(peer, actor):
    r = call(actor, "GET", "/api/me")
    spec = POLICY["actors"][actor]
    assert r["status"] == 200, r
    b = r["body"]
    assert b["actor"] == actor and b["role"] == spec["role"]
    assert b["identity"] == actor_identity(actor)["uri"]
    assert b.get("customer") == spec.get("customer"), "customer id only for customers"


@pytest.mark.parametrize("actor", ACTORS)
@pytest.mark.parametrize("method,path", [("GET", "/admin"), ("DELETE", "/api/me"), ("GET", "/api/accounts/x/y/transactions"),
                                         ("PUT", "/api/transfers"), ("GET", "/../etc/passwd")])
def test_unknown_routes_are_404(peer, actor, method, path):
    r = call(actor, method, path)
    assert r["status"] == 404 and route_refusal(r), r


def test_route_refusal_is_logged_with_the_actor(peer, vm):
    fe = vm(frontend_node())
    since = fe.check_output("date '+%Y-%m-%d %H:%M:%S'").strip()
    time.sleep(1)
    call("bob", "GET", "/api/status")
    time.sleep(1)
    log = fe.check_output(f"journalctl -u zt-mtls --since '{since}' --no-pager")
    assert re.search(r"refused 10\.10\.0\.200: route status \(GET /api/status\) not allowed for "
                     r"spiffe://cloud\.local/customer/bob", log), log[-1500:]


def test_live_routes_are_the_policy(vm):
    """The routes the frontend enforces are exactly the generated ones (drift)."""
    node = frontend_node()
    live = json.loads(vm(node).file("/etc/zt/mtls.json").content_string)
    assert live == mtls(node)
    assert [(r["method"], r["path"]) for r in live["serves"]["https"]["routes"]] == \
        [(r["method"], r["path"]) for r in ROUTES]


def test_inner_unknown_route_is_404_even_for_the_right_caller(vm):
    """service-a accepts the frontend's identity, but only on its declared routes."""
    fe = vm(frontend_node())
    listen = next(iter(mtls("service-a")["serves"].values()))["listen"]
    f = push(fe, {"root.crt": ROOT_CA})
    try:
        r = run_script(fe, "tls_probe.py", ["--url", f"https://{listen}/admin", "--ca", f["root.crt"],
                                            "--cert", "/etc/zt/pki/cert.crt", "--key", "/etc/zt/pki/cert.key"])
    finally:
        fe.run(f"rm -rf {f['_dir']}")
    assert r["status"] == 404 and r["tls"] == "TLSv1.3", r


def test_bot_certificate_is_short_lived():
    import subprocess
    from datetime import datetime
    crt = actor_creds("statements")[0]
    out = subprocess.run(["openssl", "x509", "-in", str(crt), "-noout", "-startdate", "-enddate"],
                         capture_output=True, text=True, check=True).stdout
    d = dict(l.split("=", 1) for l in out.splitlines())
    fmt = "%b %d %H:%M:%S %Y %Z"
    hours = (datetime.strptime(d["notAfter"].strip(), fmt) - datetime.strptime(d["notBefore"].strip(), fmt)).total_seconds() / 3600
    assert abs(hours - 1) < 0.1, f"bot certificate lives {hours}h"


def test_same_machine_different_rights():
    """Alice and Dev are both exported to the i7: same device, same tunnel, different permissions."""
    i7 = [i for i in PKI["identities"].values() if i.get("export_to") == "i7"]
    assert {i["actor"] for i in i7} == {"alice", "dev"}
    alice_routes = {r["name"] for r in ROUTES if "customer" in r["allow"]}
    dev_routes = {r["name"] for r in ROUTES if "staff" in r["allow"]}
    assert "accounts" in alice_routes - dev_routes and "status" in dev_routes - alice_routes
