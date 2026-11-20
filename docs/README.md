# Documentation — zerotrust-cloud / ZT Bank

Mini-cloud **zero trust** sur un seul ordinateur portable : 6 machines virtuelles, une banque
de démonstration (« ZT Bank ») et un second poste qui l'utilise à travers un tunnel WireGuard.
Chaque règle (« qui parle à qui ») est écrite **une seule fois** dans `policy.yaml`, puis
générée en configuration (pare-feu, mTLS, certificats, base de données) et **prouvée par des tests**.

## Par où commencer

| Vous voulez… | Lire |
|---|---|
| comprendre le sujet et les choix | [01 — Analyse du sujet](01-analyse-du-sujet.md) |
| voir l'architecture | [02 — Conception et architecture](02-architecture.md) |
| **refaire le projet de zéro** | [03 — Reproduire le projet pas à pas](03-reproduire-pas-a-pas.md) |
| le détail d'une partie | les fiches 10 à 18 ci-dessous |
| préparer le second poste | [19 — Le poste distant](19-poste-distant.md) |
| savoir ce que prouvent les tests | [20 — Stratégie de test](20-tests.md) |
| publier sans rien exposer | [21 — Secrets et données personnelles](21-secrets-et-donnees-personnelles.md) |
| un problème | [22 — Dépannage](22-depannage.md) |
| les risques résiduels | [THREAT-MODEL.md](THREAT-MODEL.md) (modèle de menace, en anglais) |
| le rapport | [rapport/rapport.pdf](rapport/rapport.pdf) (source LaTeX : `rapport/rapport.tex`) |
| la vidéo de démo | [video/zt-bank-demo.mp4](video/zt-bank-demo.mp4) — narration et guide d'enregistrement : [23](23-video-demo.md) |
| **filmer la démo sur les deux machines** | [24 — Scénario de la démo](24-scenario-demo.md) (scripts `tools/demo.py` et `remote-client/demo.py`) |

## Les fiches, dans l'ordre de construction

| Étape(s) | Fiche | Commande | Test |
|---|---|---|---|
| 0 | [10 — Générateur et politique](10-politique-et-generateur.md) | `make gen` | `make test-0` |
| 1–2 | [11 — Hôte, réseaux et VM](11-hote-reseaux-vm.md) | `make host infra` | `make test-1 test-2` |
| 3, 6 | [12 — Autorité de certification et certificats](12-pki.md) | `make ca certs` | `make test-3 test-6` |
| 4 | [13 — Pare-feu sur chaque VM](13-pare-feu.md) | `make firewall` | `make test-4` |
| 5 | [14 — WireGuard](14-wireguard.md) | `make wireguard` | `make test-5` |
| 7–8 | [15 — Services mTLS, PostgreSQL, confidentialité](15-services-mtls.md) | `make services` | `make test-7 test-8` |
| 9–10 | [16 — ZT Bank : acteurs et application](16-zt-bank.md) | `make services client-certs` | `make test-9 test-10` |
| 11 | [17 — Site web et Firefox](17-site-web.md) | `make client-certs` | `make test-11` |
| 12 | [18 — Bot et partenaire de paiement](18-bot-et-partenaire.md) | `make bot` | `make test-12` |
| 13 | [18b — Attaques, révocation, audit](18b-attaques-revocation-audit.md) | `make revoke`, `make attacks`, `make audit` | `make test-13` |

## Vocabulaire

- **cloud host** : l'ordinateur portable qui héberge les 6 VM (l'hyperviseur). Tout ce dépôt s'y exécute.
- **remote client** (poste distant) : un second portable sur le même Wi-Fi, poste de travail des
  utilisateurs (Alice, Dev). Il n'est pas géré par ce dépôt ; on lui exporte seulement sa configuration.
- **identité SPIFFE** : nom d'une machine ou d'une personne dans un certificat,
  par exemple `spiffe://cloud.local/customer/alice`.
- **mTLS** : TLS mutuel, le client présente lui aussi un certificat.
- **politique** (`policy.yaml`) : la source unique de vérité ; tout le reste en est dérivé.
