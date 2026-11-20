"""Stage 13 — revocation is deployed and operated from the policy (offline checks of what is generated
and of the playbooks; the mechanism itself is tested in test_revocation.py)."""
import json

import yaml

from unit_helpers import ROOT

APP = yaml.safe_load((ROOT / "ansible/roles/app/tasks/main.yml").read_text())
REVOKE = yaml.safe_load((ROOT / "ansible/revoke.yml").read_text())


def test_every_https_service_enforces_the_ca_crl(build):
    policy = yaml.safe_load((ROOT / "policy.yaml").read_text())
    ca = policy["services"]["step-ca"]
    url = f"https://{policy['nodes'][ca['node']]['interfaces'][ca['network']]}:{ca['port']}/1.0/crl"
    seen = 0
    for p in (build / "nodes").glob("*/mtls.json"):
        m = json.loads(p.read_text())
        if any(s.get("protocol", "https") == "https" for s in m["serves"].values()):
            assert m["revocation"] == {"crl_url": url, "file": "/etc/zt/pki/revoked.json"}, p
            seen += 1
    assert seen == 3


def test_ca_publishes_a_crl_regenerated_on_revoke():
    tasks = (ROOT / "ansible/roles/ca/tasks/main.yml").read_text()
    assert "crl: {enabled: true, generateOnRevoke: true" in tasks.replace("\n", " ") or \
        "generateOnRevoke: true" in tasks


def _names(tasks):
    return [t["name"] for t in tasks]


def test_crl_is_fetched_before_the_service_starts_and_then_every_minute():
    names = _names(APP)
    fetch = names.index("Revocation list fetched now (zt-mtls refuses everyone without a fresh one)")
    assert fetch < names.index("Running and enabled") and fetch < names.index("Hardened systemd unit")
    assert "Revocation list present and fresh" in names and "CRL timer enabled" in names
    timer = (ROOT / "ansible/roles/app/templates/zt-crl.timer.j2").read_text()
    assert "OnUnitActiveSec=60s" in timer
    unit = (ROOT / "ansible/roles/app/templates/zt-crl.service.j2").read_text()
    assert "ProtectSystem=strict" in unit and "ReadWritePaths=/etc/zt/pki" in unit


def test_revoke_token_never_logged_nor_on_a_command_line():
    tasks = {t["name"]: t for t in REVOKE[0]["tasks"]}
    mint = tasks["One-time revocation token, minted on the CA"]
    assert mint["no_log"] is True and mint["delegate_to"] == "{{ zt_pki.ca.node }}"
    rev = next(t for n, t in tasks.items() if n.startswith("Revoke serial"))
    cmd = rev["ansible.builtin.shell"]
    assert '--token "$ZT_TOKEN"' in cmd and "revoke_token" not in cmd
    assert "revoke_token.stdout" in rev["environment"]["ZT_TOKEN"]
    assert cmd.strip().endswith("{{ serial_dec }}"), "step: flags first, the serial last"
    assert "--provisioner-password-file" in mint["ansible.builtin.shell"]


def test_revoke_refreshes_every_service_and_checks_the_serial():
    play = REVOKE[1]
    assert play["hosts"] == "app"
    assert any("zt-crl.service" in json.dumps(t) for t in play["tasks"])
    assert any("serial_hex" in json.dumps(t) for t in play["tasks"])


def test_a_revoked_workload_certificate_is_replaced_not_renewed():
    pki = (ROOT / "ansible/roles/pki-client/tasks/main.yml").read_text()
    assert "revoked.json" in pki and "echo revoked" in pki


def test_make_revoke_exists():
    mk = (ROOT / "Makefile").read_text()
    for t in ("revoke:", "test-13:", "attacks:", "attack:", "audit:", "demo:"):
        assert f"\n{t}" in mk, t
