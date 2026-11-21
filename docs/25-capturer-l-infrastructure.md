# 25 — Capturer l'infrastructure réelle (VM, réseaux, connexions)

Pas d'images préparées : ces vues lisent le système **en direct** sur le cloud host. On les affiche,
puis on prend la capture d'écran (`Alt+Impr` pour une fenêtre sous GNOME) ou on les filme.
Enregistrer les captures dans `docs/screens/demo/` sous les noms indiqués : le rapport les inclut
automatiquement (section « Démonstration », « L'infrastructure, en direct »).

Avant toute capture : `export PS1='cloud-host$ '`, fermer les notifications et les autres fenêtres.

## 0. La carte graphique en direct (navigateur)

```bash
make infra-live          # ou : python3 tools/infra-live.py
xdg-open http://127.0.0.1:8099
```

Une page web locale (n'écoute que sur 127.0.0.1) qui dessine l'infrastructure et se met à jour
toutes les 2 s à partir des **données réelles** : chaque VM (verte si elle tourne, lu dans libvirt),
les réseaux, le tunnel (âge de la dernière poignée de main WireGuard), chaque flux autorisé — animé
avec le nombre de connexions établies quand il est utilisé (lu par `ss` sur chaque VM) — et les
paquets rejetés par les pare-feu (flèches rouges, lus dans les journaux nftables).

Pour la voir s'animer : Alice navigue dans Firefox sur le poste distant (flux tunnel → frontend →
service-a → service-b → base), `make pay` (flux partenaire), `python3 tools/demo.py C2` (rejets).
Capture : `infra-carte-graphique.png` (plein écran : `F11` dans le navigateur).

## 1. Les VM et les réseaux dans virt-manager (interface graphique)

```bash
sudo apt install -y virt-manager      # si besoin
virt-manager -c qemu:///system &
```

| Capture | Où cliquer |
|---|---|
| `infra-virt-manager-vms.png` | fenêtre principale : les 6 VM « Running », graphes CPU (Édition → Préférences → Statistiques pour afficher la mémoire) |
| `infra-virt-manager-reseaux.png` | Édition → Détails de la connexion → onglet **Réseaux virtuels** : `zt-wan` (NAT), `zt-dmz`, `zt-app`, `zt-data`, `zt-mgmt` (isolés) |
| `infra-virt-manager-nic-frontend.png` | double-clic sur `frontend` → icône « i » (détails) → les cartes réseau : source `zt-dmz`, `zt-app`, `zt-mgmt` |

Les adresses MAC visibles sont celles, virtuelles, générées pour les VM : elles n'identifient pas
votre ordinateur. Ne pas capturer l'onglet « Disques » : il montre le chemin du pool dans votre dossier personnel.

## 2. Les vues en direct dans le terminal

```bash
python3 tools/infra-view.py map              # carte vivante : VM, tunnel, flux actifs, derniers rejets
python3 tools/infra-view.py vms              # chaque VM, son état et sa position sur les réseaux (libvirt)
python3 tools/infra-view.py nets             # les réseaux, leurs ponts, l'adresse de l'hôte
python3 tools/infra-view.py wg               # le tunnel vu du gateway : pairs, poignée de main, octets
python3 tools/infra-view.py conns            # les connexions établies maintenant, qui → qui
python3 tools/infra-view.py drops            # les derniers paquets rejetés, qui → où
python3 tools/infra-view.py map --watch 2    # rafraîchi toutes les 2 s (à filmer pendant la démo)
```

Les adresses Wi-Fi, MAC, nom d'utilisateur et de machine sont masqués ; les clés WireGuard sont
remplacées par le nom du pair.

**Pour voir des flux actifs**, il faut du trafic au moment de la capture : sur le poste distant,
ouvrir la banque dans Firefox (profil `zt-alice`) et cliquer sur un compte, ou lancer
`python3 remote-client/demo.py R4` ; sur le cloud host, `make bot-run` ou `make pay`. Les connexions
mTLS sont réutilisées quelques secondes : lancer `conns` juste après.

| Capture | Commande, au moment où… |
|---|---|
| `infra-carte-vivante.png` | `map --watch 2` pendant qu'Alice navigue dans Firefox |
| `infra-vms.png` | `vms` |
| `infra-connexions.png` | `conns` juste après un virement dans Firefox |

## 3. Le tableau de bord (4 panneaux en direct)

```bash
sudo apt install -y tmux
tools/infra-dashboard.sh        # carte | connexions | tunnel | rejets — Ctrl-b d pour quitter
```

Capture : `infra-tableau-de-bord.png`, pendant la démo (idéal en arrière-plan de la vidéo).
Pour provoquer des rejets visibles : `python3 tools/demo.py C2` (scan depuis le client hostile).

## 4. Le trafic chiffré sur un pont (Wireshark)

```bash
sudo apt install -y wireshark
sudo wireshark -i virbr-zt-app -k -f "tcp port 9443" &
```

Puis faire une action dans Firefox : on voit `Client Hello`, `Server Hello`, puis uniquement
`TLSv1.3 Application Data` entre `10.30.0.10` (frontend) et `10.30.0.11` (service-a) — aucune donnée
lisible. Capture : `infra-wireshark-tls13.png`. Même chose sur `virbr-zt-data` (`tcp port 5432`) pour
la base. **Ne pas** capturer l'interface Wi-Fi ni `virbr-zt-wan` (on y verrait l'adresse Wi-Fi du
poste distant).

## 5. Inclure dans le rapport

```bash
ls docs/screens/demo/infra-*.png
cd docs/rapport && xelatex rapport.tex && xelatex rapport.tex
```
