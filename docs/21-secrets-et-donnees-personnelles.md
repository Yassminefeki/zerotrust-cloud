# 21 — Secrets et données personnelles

Le dépôt est public. Il ne contient **aucun** secret ni aucune information qui identifie les
machines ou les personnes qui l'ont exécuté. Cette fiche dit où sont les secrets et comment
vérifier avant de publier.

## Où sont les secrets (jamais dans Git)

| Secret | Emplacement | Créé par |
|---|---|---|
| mots de passe de la CA, du provisionneur | `ansible/.secrets/` (cloud host), `/etc/step-ca/secrets/` (VM ca) | `make ca` |
| clés WireGuard + clés pré-partagées | `ansible/.secrets/wireguard/`, `/etc/wireguard/` (gateway) | `make wireguard` |
| clés des acteurs, paquets `.p12` et leurs mots de passe | `ansible/.secrets/pki/<cn>/` | `make client-certs` |
| clé de chaque VM | `/etc/zt/pki/cert.key` sur la VM (générée sur place) | `make certs` |
| secret du webhook PayFlow | `ansible/.secrets/partners/`, `/etc/zt/partners/` (frontend) | `make services` |
| exports pour le poste distant | `build/export/` | `make wireguard client-certs` |

`.gitignore` exclut : `env.yaml`, `build/`, `ansible/.secrets/`, `*.key`, `*.pem`, `wg-*.conf`,
les états Terraform, `remote-client-report.json`. Les tâches Ansible qui manipulent un secret
sont en `no_log: true` ; les outils (`make audit`, `attack.py`) n'affichent que des identités,
numéros de série, dates et compteurs.

## Ce qui dépend de votre machine (jamais dans Git)

`env.yaml` seulement : nom mDNS, interface réseau, chemin du pool libvirt, utilisateur SSH des
VM, clé SSH publique. Le dépôt ne contient **aucune adresse Wi-Fi** : le poste distant joint le
cloud host par un nom, et le pare-feu de l'hôte filtre par nom d'interface. Les adresses du
dépôt (`10.x`, `192.168.122.x`) sont celles des réseaux **virtuels** internes de la politique.

Les données de la banque (Alice Martin, Bob Durand, comptes, montants) sont **fictives**.

## Vérifier avant chaque publication

```bash
git status --short                              # rien sous ansible/.secrets, build/, aucun *.key / *.p12
git ls-files | grep -Ei 'secret|\.key$|\.p12|\.pem|env\.yaml|tfstate'   # doit être vide
make test-0                                     # inclut test_no_personal_data.py
git log --all -p | grep -E 'PRIVATE KEY|PrivateKey *= *[A-Za-z0-9+/]{40}'   # historique : doit être vide
```

`tests/unit/test_no_personal_data.py` échoue si un fichier suivi contient un chemin
`/home/<nom>`, une adresse MAC, une adresse e-mail, une clé privée, une valeur de clé WireGuard ou
une adresse de réseau domestique ; il n'affiche que l'emplacement, jamais le contenu.

## Si un secret a été publié par erreur

1. le considérer comme compromis : le **régénérer** (supprimer le fichier dans `ansible/.secrets/`
   puis relancer l'étape qui le crée ; pour un certificat, `make revoke`) ;
2. seulement ensuite, nettoyer l'historique (`git filter-repo`) et forcer la publication —
   le retirer de l'historique ne suffit pas, il a pu être copié.

## Note sur les métadonnées Git

Le nom et l'adresse e-mail de l'auteur de chaque commit sont publics sur GitHub. Pour ne pas
exposer une adresse personnelle, configurer l'adresse « noreply » fournie par GitHub
(*Settings → Emails → Keep my email address private*) avant de committer :
`git config user.email "<id>+<compte>@users.noreply.github.com"`.
