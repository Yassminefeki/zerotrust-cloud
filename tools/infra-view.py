#!/usr/bin/env python3
"""Vues EN DIRECT de l'infrastructure (cloud host), à afficher à l'écran puis capturer ou filmer.
Toutes les données sont lues sur le système réel : libvirt, les VM (SSH), WireGuard, les connexions
TCP établies, les journaux nftables. Rien n'est dessiné à l'avance.

    python3 tools/infra-view.py map            carte vivante : VM, réseaux, tunnel, flux actifs
    python3 tools/infra-view.py vms            chaque VM : état, mémoire, sur quels réseaux (libvirt)
    python3 tools/infra-view.py nets           les réseaux virtuels, leurs ponts, l'adresse de l'hôte
    python3 tools/infra-view.py wg             le tunnel : pairs, dernière poignée de main, octets
    python3 tools/infra-view.py conns          les connexions établies maintenant, qui -> qui
    python3 tools/infra-view.py drops          les derniers paquets rejetés (nftables), qui -> où
    python3 tools/infra-view.py map --watch 2  rafraîchi toutes les 2 s (Ctrl-C pour arrêter)

Ce qui identifie les machines (adresses Wi-Fi, MAC, utilisateur, nom d'hôte) est masqué ; les
clés WireGuard sont remplacées par le nom du pair.
"""
import argparse
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_lib import C, REPO, Sanitizer  # noqa: E402

BUILD = REPO / "build"
POLICY = yaml.safe_load((REPO / "policy.yaml").read_text())
CLEAN = Sanitizer("cloud-host")
VIRSH = ["virsh", "-c", "qemu:///system"]
NODES = list(POLICY["nodes"])


# ------------------------------------------------------------------ helpers --
def sh(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def ssh(node, cmd):
    return sh(["ssh", "-F", str(BUILD / "ssh_config"), "-o", "BatchMode=yes", node, cmd])


def on_all(nodes, cmd):
    with ThreadPoolExecutor(len(nodes)) as ex:
        return dict(zip(nodes, ex.map(lambda n: ssh(n, cmd), nodes)))


def who(ip):
    """A policy address -> a readable name (VM, peer, host); anything else is masked."""
    for n, d in POLICY["nodes"].items():
        for net, a in d["interfaces"].items():
            if a == ip:
                return f"{n}({net})"
    for p in POLICY["wireguard"]["peers"]:
        if p["ip"] == ip:
            return f"{p['name']}(tunnel)"
    for net, d in POLICY["networks"].items():
        if d.get("host_ip") == ip:
            return f"cloud-host({net})"
    return CLEAN(ip)


def port_name(port):
    for name, s in POLICY["services"].items():
        if str(s["port"]) == str(port):
            return name
    return str(port)


def ok(s):
    return f"{C['g']}{s}{C['n']}"


def bad(s):
    return f"{C['r']}{s}{C['n']}"


def dim(s):
    return f"{C['d']}{s}{C['n']}"


def title(s):
    print(f"{C['b']}{C['c']}{s}{C['n']}")


# -------------------------------------------------------------------- views --
def libvirt():
    """{vm: {"state", "mem_mb", "vcpus", "nics": [(network, policy_net)]}} from libvirt."""
    bridges = {d["bridge"]: n for n, d in POLICY["networks"].items() if d.get("bridge")}
    netbr = {}
    for line in sh(VIRSH + ["net-list", "--all", "--name"]).split():
        info = sh(VIRSH + ["net-info", line])
        m = re.search(r"Bridge:\s+(\S+)", info)
        netbr[line] = bridges.get(m.group(1), "?") if m else "?"
    out = {}
    for vm in NODES:
        st = sh(VIRSH + ["domstate", vm]).strip() or "absent"
        info = sh(VIRSH + ["dominfo", vm])
        mem = re.search(r"Max memory:\s+(\d+)", info)
        cpu = re.search(r"CPU\(s\):\s+(\d+)", info)
        nics = []
        for line in sh(VIRSH + ["domiflist", vm]).splitlines()[2:]:
            f = line.split()
            if len(f) >= 3:
                nics.append((f[2], netbr.get(f[2], "?")))
        out[vm] = {"state": st, "mem_mb": int(mem.group(1)) // 1024 if mem else 0,
                   "vcpus": cpu.group(1) if cpu else "?", "nics": nics}
    return out


def view_vms():
    title("Machines virtuelles (libvirt) et leur position sur les réseaux")
    lv = libvirt()
    print(f"  {'VM':10} {'état':10} {'RAM':>6} {'vCPU':>4}   interfaces  (réseau libvirt → adresse de la politique)")
    for vm, d in lv.items():
        st = ok(d["state"]) if d["state"] == "running" else bad(d["state"])
        ifs = "  ".join(f"{net}:{POLICY['nodes'][vm]['interfaces'].get(net, '-')}" for _, net in d["nics"] if net != "?")
        print(f"  {vm:10} {st:19} {d['mem_mb']:>4} Mo {d['vcpus']:>4}   {ifs}")
    gw_routes = ssh("frontend", "ip -br route")
    if gw_routes:
        print(dim("\n  routes du frontend (les seules : son réseau + retour vers le tunnel) :"))
        for l in gw_routes.splitlines():
            print("   ", CLEAN(l))


def view_nets():
    title("Réseaux virtuels (libvirt) — l'hôte n'a d'adresse que sur wan et mgmt")
    print(f"  {'réseau':8} {'mode':10} {'pont':14} {'actif':6} {'adresse de l hôte':18} VM branchées")
    lv = libvirt()
    for net, d in POLICY["networks"].items():
        if net == "tunnel":
            continue
        br = d.get("bridge", "")
        addr = sh(["ip", "-br", "-4", "addr", "show", "dev", br]).split()
        host = addr[2] if len(addr) > 2 else "(aucune)"
        up = ok("oui") if addr else bad("non")
        vms = [vm for vm, v in lv.items() if any(n == net for _, n in v["nics"])]
        print(f"  {net:8} {d['mode']:10} {br:14} {up:15} {CLEAN(host):18} {', '.join(vms)}")


def wg_peers():
    keys = {}
    for f in (REPO / "ansible/.secrets/wireguard").glob("*.pub"):
        keys[f.read_text().strip()] = f.stem
    dump = ssh("gateway", "sudo wg show wg0 dump")
    peers = []
    for line in dump.splitlines()[1:]:
        f = line.split("\t")
        if len(f) >= 8:
            age = int(time.time()) - int(f[4]) if f[4] != "0" else None
            peers.append({"name": keys.get(f[0], "inconnu"), "allowed": f[3], "age": age,
                          "rx": int(f[5]), "tx": int(f[6]), "endpoint": "via DNAT du cloud host" if f[2] != "(none)" else "-"})
    return peers


def human(n):
    for u in ("o", "Ko", "Mo", "Go"):
        if n < 1024:
            return f"{n:.0f} {u}"
        n /= 1024
    return f"{n:.1f} To"


def view_wg():
    title("Le tunnel WireGuard, vu du gateway (wg0 10.10.0.1)")
    print(f"  {'pair':14} {'adresse autorisée':18} {'poignée de main':16} {'reçu':>9} {'envoyé':>9}  arrivée")
    for p in wg_peers():
        age = "jamais" if p["age"] is None else f"il y a {p['age']} s"
        col = ok if p["age"] is not None and p["age"] < 180 else dim
        print(f"  {p['name']:14} {p['allowed']:18} {col(f'{age:16}')} {human(p['rx']):>9} {human(p['tx']):>9}  {p['endpoint']}")


def connections():
    ports = {str(s["port"]) for s in POLICY["services"].values()} - {"22"}
    raw = on_all(NODES, "ss -Htn state established")
    seen = set()
    for node, out in raw.items():
        for line in out.splitlines():
            f = line.split()
            if len(f) < 4:
                continue
            local, peer = f[-2], f[-1]
            lip, lport = local.rsplit(":", 1)
            pip, pport = peer.rsplit(":", 1)
            lip, pip = lip.strip("[]").replace("::ffff:", ""), pip.strip("[]").replace("::ffff:", "")
            if lport in ports:
                seen.add((pip, lip, lport))
            elif pport in ports:
                seen.add((lip, pip, pport))
    return sorted(seen, key=lambda x: (x[2], x[1], x[0]))


def view_conns():
    title("Connexions établies en ce moment (toutes les VM, ss)")
    rows = connections()
    if not rows:
        print(dim("  aucune — ouvrez la banque dans Firefox ou lancez une scène de démo"))
    for src, dst, port in rows:
        tls = "WireGuard" if port == "51820" else "mTLS TLS 1.3"
        print(f"  {who(src):26} → {who(dst):24} :{port:<5} {port_name(port):12} {dim(tls)}")


def drops(n=12):
    raw = on_all(NODES, f"sudo journalctl -k -n 400 -o short-iso --no-pager | grep zt-drop- | tail -{n}")
    rows = []
    for node, out in raw.items():
        for line in out.splitlines():
            m = re.search(r"^(\S+).*zt-drop-(\S+?): .*?SRC=(\S+) DST=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?", line)
            if m:
                rows.append((m.group(1)[11:19], node, m.group(2), m.group(3), m.group(4), m.group(5), m.group(6) or ""))
    return sorted(rows)[-n:]


def view_drops():
    title("Derniers paquets rejetés par les pare-feu (nftables, journal du noyau)")
    rows = drops()
    if not rows:
        print(dim("  aucun rejet récent"))
    for t, node, chain, src, dst, proto, dpt in rows:
        print(f"  {t}  {node:10} {bad('DROP'):13} {chain:8} {who(src):24} → {who(dst)}:{dpt} {dim(proto)}")


def view_map():
    lv = libvirt()
    peers = {p["name"]: p for p in wg_peers()}
    conns = connections()

    def vm(name):
        st = lv.get(name, {}).get("state", "?")
        return ok(f"● {name}") if st == "running" else bad(f"○ {name}")

    def live(src_pred, port):
        return sum(1 for s, d, p in conns if p == str(port) and src_pred(s))

    def flow(n, label):
        return ok(f"══ {n} connexion(s) active(s) ══▶") if n else dim(f"── {label} (au repos) ──▶")

    rc = peers.get("remote-client", {})
    age = rc.get("age")
    tun = ok(f"handshake il y a {age} s") if age is not None and age < 180 else dim("pas de poignée de main récente")
    fe_from_tunnel = live(lambda s: s.startswith("10.10.0."), POLICY["services"]["https"]["port"])
    fe_partner = live(lambda s: True, POLICY["services"]["partner-api"]["port"])
    a = live(lambda s: True, POLICY["services"]["api-a"]["port"])
    b = live(lambda s: s == POLICY["nodes"]["service-a"]["interfaces"]["app"], POLICY["services"]["api-b"]["port"])
    pg = live(lambda s: True, POLICY["services"]["postgres"]["port"])
    title("ZT Bank — carte vivante de l'infrastructure (cloud host)")
    print(f"""
  poste distant ──WireGuard──▶ cloud host (DNAT par nom d'interface) ──▶ {vm('gateway')}   {tun}
                                                                          │ wan 192.168.122.10 · wg0 10.10.0.1
  PayFlow (Internet) ──TCP 8444──▶ cloud host ──▶ gateway (DNAT+SNAT)    │ nftables : tunnel → :8443 seulement
                                                                          ▼
  [dmz 10.20.0.0/24]   {vm('frontend')}  10.20.0.10      tunnel {flow(fe_from_tunnel, ':8443')}  partenaire {flow(fe_partner, ':8444')}
                              │ mTLS {flow(a, ':9443')}
  [app 10.30.0.0/24]   {vm('service-a')} 10.30.0.11   (core : règles métier, rôles, plafonds)
                              │ mTLS {flow(b, ':9443')}
                       {vm('service-b')} 10.30.0.12   (ledger : seul client de la base)
                              │ TLS 1.3 + certificat {flow(pg, ':5432')}
  [data 10.40.0.0/24]  {vm('database')}  10.40.0.10   (PostgreSQL : RLS, append-only)

  [mgmt 10.50.0.0/24]  {vm('ca')} 10.50.0.10:9000 (step-ca, CRL)   · cloud host 10.50.0.1 (SSH, cache apt)
""")
    d = drops(4)
    if d:
        print(dim("  derniers rejets :"))
        for t, node, chain, src, dst, proto, dpt in d:
            print(f"    {t} {node:9} {bad('DROP')} {who(src)} → {who(dst)}:{dpt}")


VIEWS = {"map": view_map, "vms": view_vms, "nets": view_nets, "wg": view_wg, "conns": view_conns,
         "drops": view_drops}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("view", choices=[*VIEWS, "all"])
    ap.add_argument("--watch", type=float, default=0, help="rafraîchir toutes les N secondes")
    a = ap.parse_args()
    views = list(VIEWS.values())[1:] if a.view == "all" else [VIEWS[a.view]]
    try:
        while True:
            if a.watch:
                print("\033[2J\033[H", end="")
            for v in views:
                v()
                print()
            if not a.watch:
                return 0
            print(dim(f"  {time.strftime('%H:%M:%S')} — rafraîchi toutes les {a.watch:g} s, Ctrl-C pour arrêter"))
            time.sleep(a.watch)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
