# 02 — Conception et architecture

## Vue d'ensemble

```
 poste distant ──WireGuard (UDP 51820)──► cloud host (Wi-Fi, DNAT par nom d'interface)
                                              │
                                              ▼
                        VM1 gateway  wan 192.168.122.10 · wg0 10.10.0.1
                              │ nftables : tunnel → frontend:8443 uniquement
 réseau dmz 10.20.0.0/24 ─────┤
                        VM2 frontend 10.20.0.10 :8443 site + API (mTLS) · :8444 API partenaire (mTLS)
 réseau app 10.30.0.0/24       │ mTLS
                        VM3 service-a 10.30.0.11:9443  « core » : règles métier, rôles, plafonds
                               │ mTLS
                        VM4 service-b 10.30.0.12:9443  « ledger » : seul client de la base
 réseau data 10.40.0.0/24      │ TLS 1.3 + certificat client
                        VM5 database 10.40.0.10:5432   PostgreSQL 16 (RLS, append-only)
 réseau mgmt 10.50.0.0/24  cloud host 10.50.0.1 (SSH, cache apt) · VM6 ca 10.50.0.10:9000 (step-ca)
```

Ces adresses sont celles de `policy.yaml` (réseaux virtuels internes, isolés) ; elles ne
dépendent pas du Wi-Fi utilisé.

## Trois verrous indépendants sur chaque saut

1. **Réseau** — nftables *default drop* en entrée, sortie et transit sur chaque VM ; un flux n'est
   ouvert que si les deux extrémités l'autorisent ; chaque rejet est journalisé.
2. **Transport** — WireGuard depuis l'extérieur, TLS 1.3 uniquement à l'intérieur (PostgreSQL compris).
3. **Identité** — certificat SPIFFE de 24 h émis par la CA interne ; chaque serveur vérifie la
   chaîne **et** que l'identité figure dans sa liste d'autorisation, puis que la route est ouverte
   au rôle de l'appelant.

Un attaquant doit donc franchir les trois à la fois ; les tests prouvent chacun séparément.

## Une source de vérité : `policy.yaml`

`policy.yaml` décrit : réseaux, nœuds et adresses, services, **flux métier** (`flows`), flux
d'administration (`infra`), PKI (domaine de confiance, durées), pairs WireGuard, **acteurs** et
**rôles**, **routes** par service, paramètres de la banque et du webhook.

`env.yaml` (non versionné) contient ce qui dépend de la machine : le nom mDNS du cloud host,
l'interface Wi-Fi, le port publié, le chemin du pool libvirt, l'utilisateur SSH des VM.

```
policy.yaml + env.yaml ──► tools/gen_rules.py ──► build/
   ├─ nodes/<vm>/nftables.conf      pare-feu de chaque VM
   ├─ nodes/<vm>/mtls.json          identité, listes d'autorisation, routes, prochain saut attendu
   ├─ nodes/database/pg_hba.conf    accès PostgreSQL (service-b uniquement, par certificat)
   ├─ host/nftables-zt.conf         DNAT du cloud host par nom d'interface
   ├─ wireguard/*.j2                configurations WireGuard (clés insérées par Ansible)
   ├─ pki/pki.json                  identités et politique d'émission de la CA
   ├─ bank/bank.json                clients, plafonds, partenaires
   ├─ terraform.tfvars.json, inventory.yml, ssh_config
   └─ matrix.json                   tous les couples source × destination × port, avec le verdict attendu
```

Le générateur **refuse** une politique incohérente : une adresse IP comme point d'entrée, un flux
d'administration hors mgmt, un flux métier sur mgmt, une adresse hors de son réseau, des doublons,
un flux entre deux VM sans réseau commun, un acteur sans route, etc.

## Les flux autorisés (tout le reste est rejeté)

| Flux | De | Vers |
|---|---|---|
| wg-ingress | Internet | gateway UDP 51820 |
| client-frontend | tunnel | frontend 8443 |
| partner-webhook | Internet | frontend 8444 (via DNAT + SNAT du gateway) |
| frontend-service-a | frontend | service-a 9443 |
| service-a-service-b | service-a | service-b 9443 |
| service-b-database | service-b | database 5432 |
| admin-ssh | cloud host | SSH de chaque VM (mgmt) |
| pki | toute VM | step-ca 9000 (mgmt) |
| packages | toute VM | cache apt du cloud host (mgmt) |

## Les acteurs et leurs droits

| Acteur | Identité | Rôle | Peut | Arrive par |
|---|---|---|---|---|
| alice | `spiffe://cloud.local/customer/alice` | customer | ses comptes, son historique, ses virements | tunnel (poste distant) |
| bob | `spiffe://cloud.local/customer/bob` | customer | idem pour son argent | tunnel (client de test) |
| dev | `spiffe://cloud.local/staff/dev` | staff | état du système, jamais de données client | tunnel (poste distant) |
| statements | `spiffe://cloud.local/bot/statements` | bot | relevés ; certificat 1 h lié à sa machine | tunnel (espace réseau dédié) |
| payflow | `spiffe://cloud.local/partner/payflow` | partner | `POST /webhook` signé | Internet, sans VPN |

## Choix techniques et raisons

| Choix | Raison |
|---|---|
| KVM/libvirt + Terraform (`dmacvicar/libvirt` 0.8) | VM légères, réseaux isolés « purs L2 », infrastructure en code |
| Ansible | configuration idempotente, génération des secrets hors Git, `no_log` sur tout secret |
| Générateur Python maison | une seule source de vérité ; les tests comparent le réel au généré (détection de dérive) |
| step-ca | CA interne simple, jetons à usage unique, politique d'émission, CRL |
| SPIFFE | identités normalisées, indépendantes des adresses |
| WireGuard + clé pré-partagée | VPN minimal, silencieux sans clé valide |
| nftables | une table par VM, *default drop*, journalisation, retour arrière automatique |
| Python stdlib pour les services (`zt-mtls`) | aucun framework : le code de sécurité est court et lisible |
| PostgreSQL 16 | authentification par certificat, RLS, déclencheurs append-only, fonctions `SECURITY DEFINER` |
| pytest + testinfra | les mêmes tests en local et sur les VM |

## Séquence d'un virement

1. Alice (Firefox, profil `zt-alice`) envoie `POST /api/transfers` dans le tunnel.
2. Le gateway ne laisse passer que vers `frontend:8443`.
3. Le frontend vérifie le certificat (chaîne, révocation, identité, route, CSRF, débit), en déduit
   « customer = alice » **depuis le certificat seulement** et appelle service-a en mTLS.
4. service-a vérifie que l'appelant est bien le frontend, revérifie le rôle et les plafonds,
   appelle service-b en mTLS.
5. service-b vérifie que l'appelant est service-a et appelle `bank.transfer()` dans PostgreSQL
   (certificat client, TLS 1.3).
6. La fonction contrôle la propriété du compte, le plafond, la limite journalière, le solde
   (sous verrou), l'idempotence, écrit en partie double et ajoute une ligne d'audit avec l'identité SPIFFE.
