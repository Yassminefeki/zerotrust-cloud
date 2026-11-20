#!/usr/bin/env python3
"""Démo commentée — côté POSTE DISTANT (l'utilisateur : Firefox, WireGuard).

    python3 remote-client/demo.py --list
    python3 remote-client/demo.py R1 R2 R3       quelques scènes (voir l'ordre commun : docs/24-scenario-demo.md)
    python3 remote-client/demo.py --fast ...     sans pause

Avant d'enregistrer, HORS CAMÉRA, dans le même terminal :
    export ZT_CLOUD_HOST=<adresse Wi-Fi du cloud host>          # pour B1/B5 (jamais affichée)
    export ZT_CLOUD_SSH=<utilisateur>@<adresse Wi-Fi du cloud host>   # pour R8 (récupérer le nouveau certificat)
    export ZT_CLOUD_REPO=<chemin du dépôt sur le cloud host>
    export PS1='remote-client$ '
    sudo -v

Tout ce qui s'affiche est anonymisé et enregistré dans ~/zt-demo-captures/<scène>.txt.
"""
import argparse
import glob
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from demo_lib import REPO, Demo  # noqa: E402

WEB = "https://10.20.0.10:8443/"
HOME = Path.home()
CLOUD = os.environ.get("ZT_CLOUD_HOST", "")
SSH = os.environ.get("ZT_CLOUD_SSH", "")
CREPO = os.environ.get("ZT_CLOUD_REPO", "")


def folder(actor):
    return HOME / "Downloads" / f"zt-{actor}"


def profile(name):
    for base in (HOME / "snap/firefox/common/.mozilla/firefox", HOME / ".mozilla/firefox"):
        hits = glob.glob(str(base / f"*.{name}"))
        if hits:
            return hits[0]
    return None


def firefox(d, prof, url=WEB):
    d.run(f"nohup firefox -P {prof} --no-remote {url} >/dev/null 2>&1 &", shown=f"firefox -P {prof} {url}")
    time.sleep(3)


SCENES = {}


def scene(sid, title):
    def deco(fn):
        SCENES[sid] = (title, fn)
        return fn
    return deco


@scene("R1", "Le tunnel WireGuard")
def r1(d):
    d.scene("R1", "Le tunnel WireGuard", [
        "Le poste distant n'atteint la banque que par WireGuard ; son tunnel ne route qu'une adresse :",
        "celle du site. Ce qui identifie l'utilisateur, ce sont ensuite ses certificats."])
    d.run("ip -br addr show wg0")
    d.run("ip route show dev wg0")
    out = subprocess.run(["sudo", "-n", "wg", "show", "wg0", "latest-handshakes"], capture_output=True, text=True).stdout
    ages = [int(time.time()) - int(x.split()[1]) for x in out.splitlines() if len(x.split()) == 2 and x.split()[1] != "0"]
    d.run(["true"], shown="sudo wg show wg0 latest-handshakes")
    line = f"   dernière poignée de main : il y a {min(ages)} s" if ages else "   pas encore de poignée de main"
    print(line)
    d.log.write(line + "\n")
    d.run(["python3", "-c", "import socket; s=socket.create_connection(('10.20.0.10',8443),3); print('   10.20.0.10:8443 joignable par le tunnel')"],
          shown="nc -vz 10.20.0.10 8443")


@scene("R2", "Alice dans Firefox, sans mot de passe")
def r2(d):
    d.scene("R2", "Alice dans Firefox", [
        "Firefox présente le certificat d'Alice pendant la poignée de main TLS : pas d'écran de connexion.",
        "À FAIRE À L'ÉCRAN : montrer les comptes ; virement de 1,00 € vers ZTB-BOB-01 ;",
        "puis un virement avec la description <script>alert(1)</script> : elle s'affiche comme du texte.",
        "CAPTURES : firefox-alice-comptes.png, firefox-alice-virement.png"])
    firefox(d, "zt-alice")
    d.pause("Entrée quand la scène Firefox est terminée")


@scene("R3", "Dev : même poste, autres droits")
def r3(d):
    d.scene("R3", "Dev dans Firefox", [
        "Même portable, même tunnel, autre certificat : Dev voit la santé de la banque, jamais un compte.",
        "CAPTURE : firefox-dev-operations.png"])
    firefox(d, "zt-dev")
    d.pause("Entrée quand la scène Firefox est terminée")


@scene("R4", "Alice tente de déborder ; identités forgées")
def r4(d):
    d.scene("R4", "Débordements et identités forgées", [
        "B2 : sans certificat, avec des certificats autosignés, en TLS 1.2 : refus à la poignée de main.",
        "B4 : le compte de Bob, des en-têtes forgés, les routes du support, des requêtes inter-sites."])
    d.run([sys.executable, "remote-client/attack.py", "B2", "B4"], shown="python3 remote-client/attack.py B2 B4")


@scene("R5", "Un client VPN devient hostile")
def r5(d):
    d.scene("R5", "Mouvement latéral", [
        "Le script route TOUS les réseaux internes de la banque dans le tunnel et frappe à chaque service,",
        "puis usurpe l'adresse d'un autre client VPN. Le gateway seul doit tout arrêter. Routes restaurées à la fin."])
    d.run(["sudo", sys.executable, "remote-client/attack.py", "B3"], shown="sudo python3 remote-client/attack.py B3")


@scene("R6", "Depuis le Wi-Fi, sans VPN : scan et faux paiements")
def r6(d):
    d.scene("R6", "Depuis l'extérieur", [
        "B1 : scan des 65 535 ports du cloud host ; chaque port ouvert est interrogé sur son certificat.",
        "B5 : faux paiements sur l'API partenaire publiée ; le solde d'Alice ne doit pas bouger."])
    if not CLOUD:
        d.note("ZT_CLOUD_HOST n'est pas défini (export hors caméra) : scène sautée")
        return
    d.run([sys.executable, "remote-client/attack.py", "B1", "B5", "--cloud-host", CLOUD],
          shown="python3 remote-client/attack.py B1 B5 --cloud-host $ZT_CLOUD_HOST")


@scene("R7", "Portable volé : la révocation vue du poste distant")
def r7(d):
    d.scene("R7", "Révocation vue du poste distant", [
        "B6 appelle la banque en Alice toutes les 2 s. Pendant ce temps, le cloud host révoque son certificat.",
        "CAPTURE : firefox-alice-revoquee.png (recharger Firefox après le refus)"])
    firefox(d, "zt-alice")
    d.other_side("python3 tools/demo.py C6   (make revoke ACTOR=alice)")
    d.run([sys.executable, "remote-client/attack.py", "B6", "--minutes", "5", "--poll", "2"],
          shown="python3 remote-client/attack.py B6")
    d.say("Rechargez Firefox (profil zt-alice) : même refus. Capture : firefox-alice-revoquee.png")
    d.pause("Entrée après la capture")


@scene("R8", "Le nouveau certificat d'Alice")
def r8(d):
    d.scene("R8", "Nouveau certificat", [
        "Le cloud host a émis une nouvelle clé et un nouveau certificat. On les récupère par SSH,",
        "on remplace l'ancien dans Firefox, et Alice retrouve ses comptes.",
        "CAPTURE : firefox-alice-nouveau-certificat.png"])
    if not (SSH and CREPO):
        d.note("ZT_CLOUD_SSH / ZT_CLOUD_REPO non définis (export hors caméra) : scène sautée")
        return
    dst = folder("alice")
    dst.mkdir(parents=True, exist_ok=True)
    os.chmod(dst, 0o700)
    d.run(["scp", "-q", f"{SSH}:{CREPO}/build/export/remote-client/alice/*", str(dst)],
          shown="scp cloud-host:<repo>/build/export/remote-client/alice/* ~/Downloads/zt-alice/", interactive=True)
    d.run(["openssl", "x509", "-in", str(dst / "client.crt"), "-noout", "-serial", "-enddate"],
          shown="openssl x509 -in ~/Downloads/zt-alice/client.crt -noout -serial -enddate")
    d.run("pkill -f 'firefox.*zt-alice' ; sleep 2", shown="(fermer Firefox)")
    prof = profile("zt-alice")
    if not prof:
        d.note("profil Firefox zt-alice introuvable")
        return
    script = (f'P="{prof}"; certutil -L -d sql:"$P" | awk \'NR>4 && tolower($0) ~ /alice/ {{NF--; print}}\' | '
              'while read -r n; do certutil -F -d sql:"$P" -n "$n" 2>/dev/null || certutil -D -d sql:"$P" -n "$n"; done; '
              f'pk12util -i "{dst}/alice.p12" -d sql:"$P" -W "$(cat "{dst}/p12-password.txt")" && rm -f "{dst}/p12-password.txt"; '
              'certutil -L -d sql:"$P" | grep -i alice')
    d.run(script, shown="certutil (retirer l'ancien) && pk12util -i alice.p12 (importer le nouveau)")
    firefox(d, "zt-alice")
    d.pause("Entrée après la capture")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenes", nargs="*")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--out", default=str(HOME / "zt-demo-captures"))
    a = ap.parse_args()
    if a.list:
        for k, (t, _) in SCENES.items():
            print(f"{k}  {t}")
        return 0
    chosen = [s.upper() for s in a.scenes] or list(SCENES)
    bad = [s for s in chosen if s not in SCENES]
    if bad:
        sys.exit(f"scènes inconnues {bad} ; connues : {', '.join(SCENES)}")
    os.chdir(REPO)
    d = Demo("remote-client", "remote-client$", a.out, fast=a.fast, extra_hidden=(CLOUD, SSH, CREPO))
    for sid in chosen:
        SCENES[sid][1](d)
        if sid != chosen[-1]:
            d.pause("Entrée : scène suivante")
    d.done()
    return 0


if __name__ == "__main__":
    sys.exit(main())
