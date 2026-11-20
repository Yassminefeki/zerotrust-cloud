# 20 — Stratégie de test

## Deux niveaux

| Niveau | Où | Quand | Ce qu'il prouve |
|---|---|---|---|
| **hors ligne** (`tests/unit/`, `make test-0`) | n'importe quelle machine, sans VM | à chaque modification | la politique, le générateur, les vrais programmes (`zt-mtls`, `zt-crl`, l'application) lancés en local avec de vrais certificats, la banque sur un vrai PostgreSQL, le site dans un vrai navigateur |
| **en direct** (`tests/<étape>/`, `make test-N`) | cloud host, sur les VM | après chaque `make <étape>` | que ce qui tourne est exactement ce qui est généré, et que les refus ont lieu réellement sur le réseau |

## Principes

- **Chaque refus est testé** autant que chaque succès : un test qui ne vérifierait que ce qui
  marche ne prouverait rien sur la sécurité.
- **Contrôles témoins** : un test de « rien en clair » vérifie aussi que la capture voit un
  paquet témoin en clair, sinon il pourrait passer sans rien capturer.
- **Dérive** : la configuration réelle est comparée à une génération fraîche depuis `policy.yaml`.
- **Client hostile** : le client de test route tous les réseaux dans le tunnel ; un refus prouve
  donc que c'est le gateway qui bloque, pas la configuration du client.
- **Aucun secret dans la sortie** : les tests sur les clés comparent des booléens ; un échec
  n'affiche jamais de clé.
- **Pas de données personnelles dans le dépôt** : `tests/unit/test_no_personal_data.py` cherche
  chemins personnels, adresses MAC, e-mails, clés privées, clés WireGuard et adresses de réseau
  domestique dans chaque fichier suivi par Git.

## Les commandes

| Commande | Contenu |
|---|---|
| `make test-0` | hors ligne (environ 350 tests ; certains sautés si un outil manque) |
| `make test-1` … `make test-13` | une étape en direct |
| `make test` | toutes les étapes dans l'ordre, s'arrête au premier échec |
| `make attacks` | le catalogue A1–A11 (119 tests), avec rapport |
| `python3 remote-client/attack.py` | B1–B6 depuis le poste distant |

## Tests hors ligne qui demandent des outils

| Outil | Tests concernés | Variable |
|---|---|---|
| PostgreSQL (`initdb`, `pg_ctl`) + `psycopg2` | banque, partenaire, révocation sur les vrais services | `ZT_TEST_PG_DSN`, `ZT_TEST_PG_RUNAS` (si exécuté en root) |
| Playwright + Chromium | site dans un vrai navigateur | — |
| `libnss3-tools` | import du paquet Firefox | — |
| droits pour créer un espace réseau | validation `nft -c` des règles générées | — |

Sans eux, ces tests sont marqués « skipped » ; les tests en direct couvrent les mêmes comportements sur les VM.
