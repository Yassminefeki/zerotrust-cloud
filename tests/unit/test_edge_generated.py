"""Stage 12 offline: what the generator makes of the bot and the partner (policy.yaml)."""
import json

import pytest

import gen_rules
from unit_helpers import mtls, nft


def lines(build, node, needle):
    return [l.strip() for l in nft(build, node).splitlines() if needle in l]


# --------------------------------------------------------------------------- partner --
def test_partner_port_published_through_the_gateway_only(build):
    pre = lines(build, "gateway", "dnat ip to")
    post = lines(build, "gateway", "snat ip to")
    assert pre == ['iifname "wan0" ip daddr 192.168.122.10 tcp dport 8444 dnat ip to 10.20.0.10:8444 '
                   'comment "flows:partner-webhook"']
    assert post == ['oifname "dmz0" ip daddr 10.20.0.10 tcp dport 8444 ct status dnat snat ip to 10.20.0.1 '
                    'comment "flows:partner-webhook"']
    fwd = lines(build, "gateway", "flows:partner-webhook")
    assert any("ct status dnat ct state new accept" in l and '"wan0" oifname "dmz0"' in l for l in fwd), \
        "only translated traffic is forwarded from the WAN side"
    for node in ("frontend", "service-a", "service-b", "database", "ca"):
        assert not lines(build, node, "dnat") and not lines(build, node, "snat")


def test_frontend_sees_the_partner_as_the_gateway_only(build):
    assert lines(build, "frontend", "dport 8444") == [
        'iifname "dmz0" ip saddr 10.20.0.1 ip daddr 10.20.0.10 tcp dport 8444 ct state new accept '
        'comment "flows:partner-webhook"']
    p = mtls(build, "frontend")["serves"]["partner-api"]
    assert p["allowed_sources"] == ["10.20.0.1"] and p["allowed_ids"] == ["spiffe://cloud.local/partner/payflow"]
    assert [(r["method"], r["path"]) for r in p["routes"]] == [("POST", "/webhook")]
    assert p["partners"] == {"spiffe://cloud.local/partner/payflow":
                             {"partner": "payflow", "key_file": "/etc/zt/partners/payflow.key"}}
    assert p["max_skew_s"] == 300


def test_cloud_host_forwards_the_partner_port_by_interface_name(build, env):
    host = (build / "host/nftables-zt.conf").read_text()
    assert (f'iifname "{env["wan_interface"]}" tcp dport 8444 dnat ip to 192.168.122.10:8444 '
            f'comment "flows:partner-webhook"') in host
    hook = (build / "host/libvirt-hook-network").read_text()
    assert "-d 192.168.122.10/32 -p tcp --dport 8444 -m conntrack --ctstate DNAT" in hook


def test_partner_identity_cannot_use_the_customer_site_nor_the_tunnel(build):
    https = mtls(build, "frontend")["serves"]["https"]
    assert "spiffe://cloud.local/partner/payflow" not in https["allowed_ids"]
    for c in ("client-remote-client.conf.j2", "client-bot.conf.j2"):
        assert "8444" not in (build / "wireguard" / c).read_text()


def test_partners_in_the_bank_data(build):
    b = json.loads((build / "bank/bank.json").read_text())
    assert b["partners"] == [{"id": "payflow", "name": "PayFlow SAS", "account": "ZTB-PAYFLOW-00",
                              "identity": "spiffe://cloud.local/partner/payflow"}]
    assert b["webhook_max_skew_s"] == 300
    for node in ("frontend", "service-a", "service-b"):
        assert mtls(build, node)["bank"]["partners"] == {"spiffe://cloud.local/partner/payflow": "payflow"}


# ------------------------------------------------------------------------------- bot --
def test_bot_peer_is_a_real_client_living_on_the_cloud_host(build):
    conf = (build / "wireguard/client-bot.conf.j2").read_text()
    assert "Address = 10.10.0.3/32" in conf
    assert "Endpoint = 192.168.122.10:51820" in conf, "on the cloud host: the NAT network directly"
    assert "AllowedIPs = 10.20.0.10/32" in conf, "routes only what the tunnel may reach (unlike the test peer)"
    wg = json.loads((build / "wireguard/wireguard.json").read_text())
    assert next(p for p in wg["peers"] if p["name"] == "bot")["netns"] == "zt-bot"


def test_bot_connection_limit_comes_before_any_accept(build):
    fwd = nft(build, "gateway").split("chain forward {")[1].split("}")[0].strip().splitlines()
    body = [l.strip() for l in fwd if ("accept" in l and "comment" in l) or "limit rate over" in l]
    assert body[0] == (  # before every policy accept (only conntrack housekeeping precedes it)
        'iifname "wg0" ip saddr 10.10.0.3 ct state new limit rate over 5/second burst 10 packets '
                       'drop comment "peer:bot:conn-limit"'), body
    assert not any("limit rate over" in l for n in ("frontend", "service-a") for l in nft(build, n).splitlines())


def test_actor_directory_rate_and_device(build):
    a = mtls(build, "frontend")["actors"]
    assert a["spiffe://cloud.local/bot/statements"]["sources"] == ["10.10.0.3/32"]
    assert a["spiffe://cloud.local/bot/statements"]["rate_per_min"] == 20
    assert "sources" not in a["spiffe://cloud.local/customer/alice"], "only device-bound identities"
    assert a["spiffe://cloud.local/partner/payflow"]["rate_per_min"] == 60


def test_pki_web_url_only_for_tunnel_actors(build):
    ids = json.loads((build / "pki/pki.json").read_text())["identities"]
    assert ids["partner-payflow"]["kind"] == "client" and "web_url" not in ids["partner-payflow"]
    assert ids["customer-alice"]["web_url"] == "https://10.20.0.10:8443/"


@pytest.mark.parametrize("rate,per_min", [("240/min", 240), ("5/second", 300), ("120/h", 2), ("1/s", 60)])
def test_per_minute(rate, per_min):
    assert gen_rules.per_minute(rate) == per_min


@pytest.mark.parametrize("mutate,msg", [
    (lambda p: p["actors"]["statements"].update(device="test-peer"), "device must be a real"),
    (lambda p: p["actors"]["statements"].update(device="nope"), "device must be a real"),
    (lambda p: p["actors"]["payflow"].update(device="bot"), "entry: tunnel"),
    (lambda p: p["actors"]["payflow"].update(entry="tunnel"), "partners come from the internet"),
    (lambda p: p["roles"]["bot"].update(rate_limit="fast"), "rate_limit must look like"),
    (lambda p: p["wireguard"]["peers"][1].update(conn_limit="5/min"), "conn_limit must look like"),
    (lambda p: p["wireguard"]["peers"][1].update(netns="bot-namespace"), "netns must look like"),
    (lambda p: p.update(webhook={"max_skew_seconds": 5}), "max_skew_seconds"),
])
def test_bad_edge_policy_rejected(policy, mutate, msg):
    p = json.loads(json.dumps(policy))
    mutate(p)
    errs = gen_rules.validate_policy(p)
    assert any(msg in e for e in errs), errs


def test_client_certs_refresh_the_ca_policy_first():
    """`make client-certs` (--tags clients) must also push the CA's issuance policy, else a NEW
    actor (stage 12: payflow) is refused: 'dns name "partner-payflow" not allowed'."""
    import yaml
    from unit_helpers import ROOT
    tasks = yaml.safe_load((ROOT / "ansible/roles/ca/tasks/main.yml").read_text())
    tagged = [t["name"] for t in tasks if "clients" in t.get("tags", [])]
    assert tagged == ["Read the generated ca.json", "Merge lifetime, TLS 1.3-only and the issuance policy into ca.json",
                      "Apply config changes now", "Wait for the CA on the mgmt address"]
    certs = yaml.safe_load((ROOT / "ansible/certs.yml").read_text())
    assert certs[0]["ansible.builtin.import_playbook"] == "ca.yml", "the CA play comes before the client play"
