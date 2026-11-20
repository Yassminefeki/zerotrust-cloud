#!/usr/bin/env python3
"""Démo commentée — côté CLOUD HOST (la machine qui héberge les 6 VM).

    python3 tools/demo.py --list           les scènes
    python3 tools/demo.py                  toutes, dans l'ordre, avec une pause entre chaque étape
    python3 tools/demo.py C3 C4            quelques scènes
    python3 tools/demo.py --fast           sans pause (répétition)

À lancer avec remote-client/demo.py sur le poste distant : l'ordre commun est dans
docs/24-scenario-demo.md, et le script annonce en jaune ce qu'il faut lancer de l'autre côté.
Tout ce qui s'affiche est anonymisé (utilisateur, nom de machine, dossier personnel, adresse
Wi-Fi, adresses MAC remplacés) et enregistré dans build/demo/cloud-host/<scène>.txt.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_lib import REPO, Demo  # noqa: E402

PY = str(REPO / ".venv/bin/python") if (REPO / ".venv/bin/python").exists() else sys.executable
BUILD = REPO / "build"
PKI = json.loads((BUILD / "pki/pki.json").read_text()) if (BUILD / "pki/pki.json").exists() else {"identities": {}}
CA = BUILD / "pki/root_ca.crt"
PEER = "zt-peer"


def cn(actor):
    return next(k for k, v in PKI["identities"].items() if v.get("actor") == actor)


def web():
    m = json.loads((BUILD / "nodes/frontend/mtls.json").read_text())
    s = next(v for v in m["serves"].values() if v.get("app") == "web")
    return f"https://{s['listen']}"


def as_actor(d, who, method, path, data=None, headers=(), creds=None):
    """One request from inside the tunnel (the test peer's namespace), as an actor."""
    c = creds or (REPO / "ansible/.secrets/pki" / cn(who))
    args = ["sudo", "-n", "ip", "netns", "exec", PEER, "python3", "tests/tls_probe.py", "--url", web() + path,
            "--ca", str(CA), "--cert", str(c / "client.crt"), "--key", str(c / "client.key"), "--method", method]
    if data:
        args += ["--data", data]
    for h in headers:
        args += ["--header", h]
    shown = f"curl-mtls --cert {who}.crt {method} {path}" + "".join(f" -H '{h}'" for h in headers)
    out = subprocess.run(args, cwd=REPO, capture_output=True, text=True)
    d.run(["true"], shown=shown)
    try:
        r = json.loads(out.stdout)
        body = json.dumps(r.get("body"), ensure_ascii=False)
        line = f"   HTTP {r.get('status')}  {body[:220]}"
    except ValueError:
        line = "   " + (out.stderr.strip().splitlines() or ["(no answer)"])[-1]
    line = d.clean(line)
    print(line)
    d.log.write(line + "\n")


SCENES = {}


def scene(sid, title):
    def deco(fn):
        SCENES[sid] = (title, fn)
        return fn
    return deco


@scene("C1", "Le cloud et sa politique")
def c1(d):
    d.scene("C1", "Le cloud et sa politique", [
        "Six machines virtuelles sur un seul portable. Toutes les règles viennent d'un seul fichier,",
        "policy.yaml ; le générateur en tire pare-feu, mTLS, PKI, base de données… et les tests."])
    d.run("virsh -c qemu:///system list --all")
    d.pause()
    d.run([PY, "-c", "import yaml; p=yaml.safe_load(open('policy.yaml'))\n"
           "print('acteurs :'); [print(f'  {a:11} {v[\"role\"]:9} via {v[\"entry\"]}') for a,v in p['actors'].items()]\n"
           "print('flux autorisés (tout le reste est refusé) :'); [print(f'  {f[\"from\"]:10} -> {f[\"to\"]}') for f in p['flows']]"],
          shown="python3 -c 'résumé de policy.yaml'")
    d.pause()
    d.run([PY, "tools/gen_rules.py", "--out", "build"], shown="make gen")


@scene("C2", "Isolation réseau : le tunnel n'atteint que le site")
def c2(d):
    d.scene("C2", "Isolation réseau", [
        "Un client VPN hostile (espace réseau zt-peer) route TOUS les réseaux internes dans son tunnel",
        "et scanne le frontend : seul le port du site répond. Les refus sont silencieux et journalisés."])
    if PEER not in subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout:
        d.run(["sudo", "tools/zt-test-peer", "up", "build/export/test-peer/wg0.conf"], shown="make test-peer")
    ip = web().split("//")[1].split(":")[0]
    d.run(["sudo", "-n", "ip", "netns", "exec", PEER, "python3", "tests/port_scan.py", ip, "--ports",
           "1-1024,3142,5432,8443,8444,9000,9443"], shown=f"port_scan {ip} (depuis le tunnel)")
    d.pause()
    for target in ("10.30.0.11:9443", "10.40.0.10:5432", "10.50.0.10:9000"):
        h, p = target.split(":")
        d.run(["sudo", "-n", "ip", "netns", "exec", PEER, "python3", "tests/port_scan.py", h, "--ports", p,
               "--timeout", "2"], shown=f"port_scan {target}   # service interne, depuis le tunnel")
    d.pause()
    d.run("ssh -F build/ssh_config gateway \"sudo journalctl -k --since '-2min' -o cat | grep zt-drop | tail -4\"",
          shown="ssh gateway journalctl -k | grep zt-drop | tail -4")


@scene("C3", "Les identités décident, pas le réseau")
def c3(d):
    d.scene("C3", "Les identités décident", [
        "Même tunnel, certificats différents : Bob ne voit pas le compte d'Alice (404, comme s'il n'existait",
        "pas) ; les en-têtes d'identité qu'il forge sont ignorés ; Dev voit l'état du système, pas les comptes."])
    as_actor(d, "bob", "GET", "/api/accounts")
    as_actor(d, "bob", "GET", "/api/accounts/ZTB-ALICE-01/transactions")
    as_actor(d, "bob", "GET", "/api/accounts", headers=["X-ZT-Customer: alice", "X-ZT-Role: customer"])
    d.pause()
    as_actor(d, "dev", "GET", "/api/status")
    as_actor(d, "dev", "GET", "/api/accounts")
    d.pause()
    as_actor(d, "alice", "POST", "/api/transfers", data='{"from":"ZTB-ALICE-01","to":"ZTB-BOB-01","amount":"500.00"}',
             headers=["Origin: https://evil.example", "Sec-Fetch-Site: cross-site"])
    d.note("une page malveillante qui tente un virement avec le navigateur d'Alice : refusé (CSRF)")


@scene("C4", "Le robot de relevés et le partenaire PayFlow")
def c4(d):
    d.scene("C4", "Robot et partenaire", [
        "Le robot vit dans son propre espace réseau, avec un certificat d'1 h lié à sa machine.",
        "PayFlow paie depuis Internet sans VPN : certificat, signature HMAC, ±300 s, nonce à usage unique."])
    d.run("make -s bot-run 2>&1 | tail -6", shown="make bot-run")
    d.pause()
    d.run("make -s pay TO=ZTB-ALICE-01 AMOUNT=2.50", shown="make pay TO=ZTB-ALICE-01 AMOUNT=2.50")
    d.run([PY, "tools/payflow.py", "--to", "ZTB-ALICE-01", "--amount", "1.00", "--replay"],
          shown="payflow.py --to ZTB-ALICE-01 --amount 1.00 --replay   # la même requête, rejouée")
    d.run([PY, "tools/payflow.py", "--to", "ZTB-ALICE-01", "--amount", "1.00", "--tamper"],
          shown="payflow.py --to ZTB-ALICE-01 --amount 1.00 --tamper   # corps modifié après signature")


@scene("C5", "Le catalogue d'attaques")
def c5(d):
    d.scene("C5", "Le catalogue d'attaques", [
        "Onze attaques, chacune liée aux tests qui prouvent sa défense. Le catalogue complet tourne",
        "en 5 minutes (make attacks, lancé avant l'enregistrement) ; ici, son rapport, puis une attaque en direct."])
    rep = BUILD / "reports/attacks.json"
    if rep.exists():
        d.run([PY, "-c", "import json; a=json.load(open('build/reports/attacks.json'))\n"
               "print('rapport du', a['when'])\n"
               "[print(f'  {k:4} {v[\"verdict\"]:10} {v[\"title\"]}') for k,v in a['attacks'].items()]"],
              shown="cat build/reports/attacks.md   # résumé")
    else:
        d.note("pas encore de rapport : lancer `make attacks` avant l'enregistrement")
    d.pause()
    d.run("make -s attack A=8 2>&1 | tail -12", shown="make attack A=8   # CSRF, en direct")


@scene("C6", "Portable volé : révocation en direct")
def c6(d):
    d.scene("C6", "Révocation en direct", [
        "Le portable d'Alice est déclaré volé. On révoque son certificat : chaque service télécharge la",
        "CRL signée et refuse la copie volée, sans redémarrage. Sans liste fraîche : tout le monde est refusé."])
    d.other_side("python3 remote-client/demo.py R7   (B6 surveille, Firefox Alice ouvert)")
    d.pause("Entrée quand le poste distant attend")
    d.run("make -s revoke ACTOR=alice REASON='stolen laptop (demo)' 2>&1 | grep -E 'TASK|changed|ok:|>>|failed' | tail -12",
          shown="make revoke ACTOR=alice REASON='stolen laptop'")
    revoked = sorted((REPO / "ansible/.secrets/pki" / cn("alice") / "revoked").glob("*/"), key=os.path.getmtime)
    if revoked:
        d.pause()
        as_actor(d, "alice", "GET", "/api/me", creds=revoked[-1])
        d.note("la copie volée (l'ancien certificat) est refusée : 403 « revoked »")
    d.other_side("rechargez Firefox (profil zt-alice) : même refus")


@scene("C7", "Un nouveau certificat pour Alice")
def c7(d):
    d.scene("C7", "Nouveau certificat", [
        "Alice reçoit une nouvelle clé et un nouveau certificat (24 h) ; l'ancien reste révoqué."])
    d.run("make -s client-certs 2>&1 | grep -E 'changed|failed' | tail -6", shown="make client-certs")
    d.run(["openssl", "x509", "-in", "build/export/remote-client/alice/client.crt", "-noout", "-subject", "-serial",
           "-enddate"], shown="openssl x509 -in alice/client.crt -noout -subject -serial -enddate")
    d.other_side("python3 remote-client/demo.py R8   (récupère et importe le nouveau certificat)")


@scene("C8", "Audit")
def c8(d):
    d.scene("C8", "Audit", [
        "Lecture seule : requêtes par identité, chaque refus et sa raison, CRL de chaque service, certificats,",
        "rejets du pare-feu, audit de la banque, grand livre, rapports d'attaque des deux machines."])
    d.run("make -s audit SINCE='1 hour ago' 2>&1 | head -12", shown="make audit")
    d.run("grep -A12 '^## 3. Revocation' build/reports/audit.md | head -14",
          shown="grep -A12 'Revocation' build/reports/audit.md")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenes", nargs="*")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--out", default=str(BUILD / "demo/cloud-host"))
    a = ap.parse_args()
    if a.list:
        for k, (t, _) in SCENES.items():
            print(f"{k}  {t}")
        return 0
    chosen = [s.upper() for s in a.scenes] or list(SCENES)
    bad = [s for s in chosen if s not in SCENES]
    if bad:
        sys.exit(f"scènes inconnues {bad} ; connues : {', '.join(SCENES)}")
    d = Demo("cloud-host", "cloud-host$", a.out, fast=a.fast)
    subprocess.call(["sudo", "-v"])          # mot de passe une fois, avant d'enregistrer
    os.system("clear")
    for sid in chosen:
        SCENES[sid][1](d)
        d.pause("Entrée : scène suivante")
    d.done()
    return 0


if __name__ == "__main__":
    sys.exit(main())
