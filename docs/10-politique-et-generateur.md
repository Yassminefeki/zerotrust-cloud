# 10 — La politique et le générateur (étape 0)

## Rôle

`tools/gen_rules.py` lit `policy.yaml` (versionné, identique pour tout le monde) et `env.yaml`
(propre à la machine, non versionné) et écrit tout `build/`. Ni Terraform, ni Ansible, ni les tests
ne répètent une adresse : ils lisent `build/`.

```bash
make check     # valide policy.yaml + env.yaml, n'écrit rien
make gen       # écrit build/
make test-0    # tests hors ligne
```

## Structure de `policy.yaml`

| Section | Contenu |
|---|---|
| `trust_domain` | `cloud.local` → identités `spiffe://cloud.local/...` |
| `networks` | wan (NAT libvirt), dmz, app, data, mgmt (isolés), tunnel (WireGuard) |
| `nodes` | les 6 VM, leurs adresses par réseau, mémoire, routes |
| `principals` | `internet`, `tunnel`, `host` : sources qui ne sont pas des VM |
| `services` | qui écoute où (nœud, réseau, port, mTLS, application) |
| `flows` / `infra` | flux métier / d'administration autorisés — **tout le reste est refusé** |
| `pki` | durée des certificats (24 h), renouvellement (8 h avant), CA |
| `roles`, `actors` | qui utilise la banque, avec quel rôle, depuis où, avec quelle limite de débit |
| `routes` | méthode + chemin autorisés par service et par rôle (refus par défaut) |
| `bank`, `webhook` | plafonds (5 000 € / virement, 2 000 € / jour), fenêtre ±300 s du webhook |
| `wireguard.peers` | pairs VPN : poste distant, bot, client de test hostile |

## Ce que produit le générateur

| Fichier | Utilisé par | Contenu |
|---|---|---|
| `nodes/<vm>/nftables.conf` | rôle Ansible `nftables` | une table `inet zt`, *policy drop* partout, journalisation avant chaque rejet |
| `nodes/<vm>/mtls.json` | service `zt-mtls` | identité attendue, appelants autorisés et leurs adresses, routes, prochain saut épinglé, URL de la CRL |
| `nodes/database/pg_hba.conf`, `pg_ident.conf` | PostgreSQL | une seule ligne `hostssl … cert` pour service-b |
| `host/nftables-zt.conf`, `host/libvirt-hook` | rôle `host` | DNAT par **nom d'interface** (jamais d'adresse Wi-Fi) |
| `wireguard/*.j2`, `wireguard.json` | rôle `wireguard` | configurations avec des emplacements pour les clés |
| `pki/pki.json` | rôles `ca`, `pki-client`, `certs.yml` | identités et SANs, politique d'émission de la CA |
| `bank/bank.json` | rôle `postgres` | clients, comptes du partenaire, plafonds |
| `terraform.tfvars.json`, `inventory.yml`, `ssh_config` | Terraform, Ansible, SSH | VM, adresses MAC, groupes |
| `matrix.json` | tests | chaque source × destination × port avec le verdict attendu |

## Validations (le générateur refuse)

- une adresse IP comme `entry_point`, une interface au nom invalide ;
- un flux d'administration hors du réseau mgmt, un flux métier sur mgmt ;
- une adresse hors du CIDR de son réseau, une adresse en double ;
- un flux entre deux VM qui ne partagent pas de réseau (les VM ne sont jamais routées) ;
- un acteur à rôle inconnu, un client sans `customer`, une route sans rôle, une méthode invalide ;
- une durée de certificat au-delà du maximum de la CA ; un débit mal écrit (`240/min`, `5/second`).

## Tests de l'étape 0 (`make test-0`)

`tests/unit/` : validité de la politique, règles exactes générées pour chaque VM, *default drop*
partout, SSH uniquement depuis l'hôte, seul le gateway route, matrice cohérente avec les flux,
service mTLS réel (refus sans certificat, autre CA, expiré, identité non autorisée, TLS 1.2),
banque complète sur un PostgreSQL local (si installé), absence de données personnelles dans le dépôt.

## Modifier la politique

```bash
vi policy.yaml               # ex. ajouter un flux
make check && make test-0
make firewall services       # appliquer
make test                    # tout revérifier (les tests suivent la politique)
```
