# 03 — Reproduire le projet pas à pas

Ce guide part d'un ordinateur sous Ubuntu fraîchement installé et va jusqu'à la banque qui
fonctionne, attaquée et auditée. Comptez environ 1 h 30 la première fois (dont le téléchargement
de l'image Ubuntu et des paquets), quelques minutes ensuite.

> Dans tout ce guide, `<…>` désigne une valeur propre à **votre** installation (nom d'interface,
> adresse Wi-Fi, utilisateur). Aucune de ces valeurs ne doit être écrite dans le dépôt : elles
> vont dans `env.yaml`, qui n'est pas versionné.

## 1. Matériel

| Machine | Rôle | Minimum conseillé |
|---|---|---|
| **cloud host** | héberge les 6 VM, exécute tout le dépôt | processeur 64 bits avec virtualisation (VT-x/AMD-V activée dans le BIOS), **16 Go de RAM** (les VM en utilisent 7), 40 Go libres, Ubuntu 22.04 ou 24.04 |
| **poste distant** | utilisateur final (Firefox, WireGuard) | n'importe quel Linux récent avec Firefox |

Les deux machines doivent être sur le même réseau local (Wi-Fi ou Ethernet) et ce réseau doit
laisser passer le mDNS (noms en `.local`) ; sinon voir [22 — Dépannage](22-depannage.md).

## 2. Logiciels sur le cloud host

```bash
sudo apt update
sudo apt install -y git make python3-venv python3-pip pipx openssl netcat-openbsd
pipx install --include-deps ansible-core          # ansible-core >= 2.15
pipx ensurepath && exec "$SHELL"                  # recharger le PATH
```

Terraform (>= 1.5) depuis le dépôt officiel HashiCorp :

```bash
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y terraform
```

Une clé SSH (elle servira à administrer les VM) :

```bash
[ -f ~/.ssh/id_ed25519.pub ] || ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
```

Le reste (KVM, libvirt, avahi, WireGuard, tcpdump, apt-cacher-ng…) est installé par `make host`.

## 3. Récupérer le dépôt et décrire **votre** machine

```bash
git clone https://github.com/<compte>/<dépôt>.git zerotrust-cloud
cd zerotrust-cloud
cp env.example.yaml env.yaml
ip -br link                       # repérer l'interface Wi-Fi (ou Ethernet) : wlo1, wlan0, enp3s0…
hostname                          # le nom mDNS sera <hostname>.local
```

Éditez `env.yaml` :

| Clé | Valeur |
|---|---|
| `entry_point` | `<hostname>.local` — un **nom**, jamais une adresse IP (le générateur refuse une IP) |
| `wan_interface` | l'interface repérée ci-dessus |
| `wan_port` | `51820` (port UDP de WireGuard publié par le cloud host) |
| `ssh_public_key_file` | `~/.ssh/id_ed25519.pub` |

Le reste peut rester tel quel. `policy.yaml` ne se modifie pas pour reproduire le projet.

## 4. Vérifier hors ligne (sans VM)

```bash
make test-0
```

Crée l'environnement Python (`.venv`), génère `build/` depuis la politique et exécute les tests
hors ligne : politique valide, règles générées exactes, service mTLS et refus, absence de données
personnelles dans le dépôt, etc. Certains tests sont « skipped » s'il manque un outil
(PostgreSQL local, navigateur Playwright, droits pour créer un espace réseau) : c'est normal.

## 5. Construire, étape par étape

Chaque étape est idempotente : on peut la relancer sans risque. Après chacune, son test.

```bash
make host        && make test-1     # prépare le cloud host (demande le mot de passe sudo)
make infra       && make test-2     # 5 réseaux virtuels + 6 VM (Terraform, cloud-init)
make ca          && make test-3     # step-ca sur la VM ca
make firewall    && make test-4     # nftables default-drop sur chaque VM
make wireguard   && make test-5     # VPN : clés, gateway, client de test
make certs       && make test-6     # certificats SPIFFE 24 h sur chaque VM + renouvellement
make services    && make test-7     # PostgreSQL + services mTLS
                    make test-8     # captures réseau : rien en clair ; dérive ; matrice N×N
                    make test-9     # chaque acteur × chaque route
                    make test-10    # la banque de bout en bout
                    make test-11    # le site web, CSRF, paquets Firefox
make bot         && make test-12    # robot de relevés + partenaire PayFlow
                    make test-13    # attaques en direct : révocation, frontend compromis, scans
```

Ou tout d'un coup : `make up && make test` (s'arrête au premier échec).

Ce que chaque étape modifie et comment elle est vérifiée : fiches 10 à 18b.

## 6. Préparer le poste distant

Résumé (détails dans [19 — Le poste distant](19-poste-distant.md)) :

1. sur le cloud host, `make wireguard` et `make client-certs` remplissent `build/export/remote-client/` :
   `wg0.conf` (VPN) et un dossier par acteur (`alice/`, `dev/`) avec certificat, clé, racine,
   paquet Firefox `.p12` et son mot de passe ;
2. copier ce dossier sur le poste distant par un canal de confiance (`scp`, clé USB), puis
   l'effacer de tout support intermédiaire ;
3. sur le poste distant : `sudo cp wg0.conf /etc/wireguard/ && sudo wg-quick up wg0`,
   importer `alice.p12` dans un profil Firefox dédié et ouvrir `https://10.20.0.10:8443/`.

## 7. Utiliser la banque

| Action | Où | Commande |
|---|---|---|
| se connecter comme Alice | poste distant | Firefox, profil `zt-alice` → `https://10.20.0.10:8443/` |
| faire un virement | idem | formulaire « New transfer » |
| voir l'état du système | poste distant | profil `zt-dev` |
| lancer le robot de relevés | cloud host | `make bot-run` (relevés dans `build/bot/`) |
| simuler un paiement entrant | cloud host | `make pay TO=ZTB-ALICE-01 AMOUNT=10.00` |
| déclarer un portable volé | cloud host | `make revoke ACTOR=alice REASON="vol"` puis `make client-certs` |
| rejouer les attaques | cloud host | `make attacks` (rapport `build/reports/attacks.md`) |
| attaquer depuis le poste distant | poste distant | `python3 remote-client/attack.py --cloud-host <adresse-wifi-du-cloud-host>` |
| auditer | cloud host | `make audit` (rapport `build/reports/audit.md`) |
| démonstration commentée | cloud host | `make demo` |

## 8. Arrêter, recommencer

```bash
make destroy        # supprime les VM et les réseaux (la préparation de l'hôte reste)
make up             # tout reconstruire (l'image Ubuntu est en cache)
make clean          # supprime build/ (garde env.yaml et les secrets)
```

Les secrets de `ansible/.secrets/` sont conservés entre deux reconstructions. Pour repartir
vraiment de zéro, supprimez aussi ce dossier (les clés seront régénérées et il faudra
renvoyer la configuration au poste distant).

## 9. Après un arrêt du cloud host

Les certificats vivent 24 h. Si les VM ont été éteintes plus longtemps :

```bash
make certs client-certs services     # ré-enrôle les VM, réémet les certificats des acteurs
```

puis renvoyer `build/export/remote-client/<acteur>/` au poste distant.
