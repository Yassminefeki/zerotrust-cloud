# 19 — Le poste distant (remote client)

Le poste distant est le poste de travail des utilisateurs. Ce dépôt ne le gère pas : il lui
**exporte** une configuration, et lui fournit une suite d'attaques à lancer depuis l'extérieur.

## 1. Logiciels

```bash
sudo apt install -y wireguard-tools libnss3-tools python3-yaml openssl git
```

## 2. Recevoir la configuration (canal de confiance)

Sur le cloud host, après `make wireguard client-certs` :

```
build/export/remote-client/
├── wg0.conf                    configuration VPN (clé privée du poste distant incluse)
├── alice/  alice.p12  p12-password.txt  client.crt  client.key  root_ca.crt  FIREFOX.txt
└── dev/    dev.p12    p12-password.txt  client.crt  client.key  root_ca.crt  FIREFOX.txt
```

Le poste distant la récupère, par exemple en SSH depuis le cloud host (ou clé USB) :

```bash
mkdir -p ~/Downloads/zt-alice ~/Downloads/zt-dev && chmod 700 ~/Downloads/zt-*
scp '<utilisateur>@<adresse-wifi-du-cloud-host>:<chemin-du-dépôt>/build/export/remote-client/wg0.conf' ~/Downloads/
scp '<utilisateur>@<adresse-wifi-du-cloud-host>:<chemin-du-dépôt>/build/export/remote-client/alice/*' ~/Downloads/zt-alice/
scp '<utilisateur>@<adresse-wifi-du-cloud-host>:<chemin-du-dépôt>/build/export/remote-client/dev/*'   ~/Downloads/zt-dev/
chmod 600 ~/Downloads/zt-*/* ~/Downloads/wg0.conf
```

Ces fichiers sont des **secrets** : ne jamais les mettre dans un dépôt, un e-mail ou une messagerie.

## 3. Le VPN

```bash
sudo install -m 600 ~/Downloads/wg0.conf /etc/wireguard/wg0.conf && rm ~/Downloads/wg0.conf
sudo wg-quick up wg0
sudo wg show wg0 latest-handshakes
```

Si le nom `<hostname>.local` du cloud host ne se résout pas (mDNS filtré par le Wi-Fi), ajouter
une ligne à `/etc/hosts` du poste distant : `<adresse-wifi-du-cloud-host> <hostname>.local`.

## 4. Firefox, un profil par identité

Firefox (y compris en snap) doit être fermé :

```bash
firefox -CreateProfile zt-alice
P=$(ls -d ~/snap/firefox/common/.mozilla/firefox/*.zt-alice 2>/dev/null || ls -d ~/.mozilla/firefox/*.zt-alice)
# l'autorité racine de la banque, de confiance pour les sites web
certutil -A -d sql:"$P" -n "ZT Bank root" -t "C,," -i ~/Downloads/zt-alice/root_ca.crt
# le certificat et la clé d'Alice
pk12util -i ~/Downloads/zt-alice/alice.p12 -d sql:"$P" -W "$(cat ~/Downloads/zt-alice/p12-password.txt)"
rm -f ~/Downloads/zt-alice/p12-password.txt
firefox -P zt-alice --no-remote https://10.20.0.10:8443/ &
```

Avant de faire confiance à la racine, comparer son empreinte avec celle de `FIREFOX.txt`
(`openssl x509 -in root_ca.crt -noout -fingerprint -sha256`). Même chose pour Dev (`zt-dev`).

**Remplacer un certificat** (après 24 h ou après une révocation) : retirer l'ancien puis importer le nouveau :

```bash
certutil -L -d sql:"$P" | awk 'NR>4 && tolower($0) ~ /alice/ {NF--; print}' | while read -r n; do
  certutil -F -d sql:"$P" -n "$n" 2>/dev/null || certutil -D -d sql:"$P" -n "$n"; done
pk12util -i ~/Downloads/zt-alice/alice.p12 -d sql:"$P" -W "$(cat ~/Downloads/zt-alice/p12-password.txt)"
```

## 5. La suite d'attaques B1–B6

Depuis un clone du dépôt (aucune adresse n'y est écrite : tout vient de `policy.yaml`) :

```bash
git pull
python3 remote-client/attack.py --cloud-host <adresse-wifi-du-cloud-host>   # B1 B2 B4 B5
sudo python3 remote-client/attack.py B3                                       # nécessite root
python3 remote-client/attack.py B6        # pendant que le cloud host lance : make revoke ACTOR=alice
```

| | Ce qu'on tente | Attendu |
|---|---|---|
| B1 | scanner les 65 535 ports TCP du cloud host depuis le Wi-Fi, puis demander son certificat à chaque port ouvert | seule l'API partenaire 8444 présente le certificat de la banque ; les autres ports ouverts sont des services propres au cloud host, listés |
| B2 | le site sans certificat, avec des certificats autosignés se disant Alice/Dev, en TLS 1.2 | refus à la poignée de main |
| B3 | router **tous** les réseaux de la banque dans le tunnel et frapper à l'intérieur ; usurper l'adresse d'un autre client VPN | silence : le gateway seul arrête |
| B4 | en Alice : lire l'historique de Bob, payer depuis son compte, forger des en-têtes, routes staff/bot, POST inter-sites ; en Dev : données client | 404 / 403 / 415 |
| B5 | notifications de paiement forgées depuis Internet | refusées, solde d'Alice inchangé |
| B6 | portable déclaré volé : appelle la banque en Alice pendant la révocation | refusé (403 « revoked ») dans la minute |

Chaque sonde affiche `REFUSED (as expected)` ou `BREACH`. Le rapport `remote-client-report.json`
(ignoré par Git) cumule les exécutions ; le copier dans `build/reports/` du cloud host puis
lancer `make audit`. Le script n'affiche jamais de clé ni de mot de passe.
