# 15 — Services mTLS, PostgreSQL et confidentialité (étapes 7 et 8)

## Étape 7 — les services (`make services`, `make test-7`)

### zt-mtls

`ansible/roles/app/files/zt-mtls` (Python, bibliothèque standard seulement) fait tourner le
frontend, service-a et service-b à partir de leur `mtls.json` généré.

**En serveur**, dans l'ordre :

1. TLS 1.3 uniquement, certificat client exigé et vérifié contre la racine ;
2. le numéro de série n'est pas **révoqué**, et la liste de révocation est fraîche
   (sinon 503 pour tout le monde : *fail-closed*) ;
3. l'identité SPIFFE est dans la liste d'autorisation **et** l'adresse source est déclarée (sinon 403) ;
4. pour un acteur lié à un appareil (le bot), l'adresse correspond à son appareil ;
5. limite de débit par identité (429 + `Retry-After`) ;
6. la route (méthode + chemin) est déclarée (sinon 404) et ouverte au rôle (sinon 403, journalisé).

**En client** : TLS 1.3, son propre certificat ; l'IP **et** l'identité SPIFFE du serveur sont
vérifiées avant d'envoyer la requête (épinglage du prochain saut), ainsi que sa non-révocation.

Utilisateur non privilégié, unité systemd durcie, chaque refus journalisé
(`journalctl -u zt-mtls | grep refused`). En-têtes de sécurité (CSP, HSTS, COOP, CORP, etc.).

### PostgreSQL 16

- écoute sur `10.40.0.10` seulement, `ssl_min_protocol_version = TLSv1.3` ;
- `pg_hba.conf` : une seule ligne `hostssl appdb service_b 10.40.0.11/32 cert` ;
- `pg_ident.conf` : le CN `service-b` du certificat devient le rôle `service_b`, sans mot de passe.

`GET https://10.20.0.10:8443/chain?marker=x` (réservé au rôle staff) traverse toute la chaîne et
renvoie ce que chaque saut a vu : identité de l'appelant, version TLS, utilisateur PostgreSQL.

**Tests** (`tests/services/`) : services non privilégiés sur la bonne adresse, PostgreSQL sur le
plan de données seulement, chaîne de bout en bout, épinglage du serveur, refus du frontend (sans
certificat, autre CA, identité non autorisée, expiré), TLS 1.2 refusé, services internes qui
refusent une identité valide mais non listée, base qui refuse sans certificat, en clair, ou une
autre identité, certificat renouvelé effectivement servi.

## Étape 8 — confidentialité et dérive (`make test-8`)

- **Confidentialité** (`tests/final/test_confidentiality.py`) : tcpdump sur **chaque** pont
  `virbr-zt-*` pendant qu'un marqueur aléatoire traverse tunnel → frontend → A → B → base.
  Le marqueur ne doit apparaître dans **aucune** capture. Contrôles : un paquet témoin en clair
  sur mgmt **doit** être capturé (la capture fonctionne) et les paquets de chaque saut doivent
  être présents (vus, mais chiffrés). Tous les sauts sont en TLS 1.3 ; TLS 1.2 est refusé partout.
- **Dérive** (`tests/final/test_drift.py`) : `build/` est identique à une génération fraîche ;
  chaque configuration en service est identique à celle générée ; la **matrice complète N×N**
  (6 VM + hôte + client tunnel × chaque adresse × chaque port de la politique) est sondée :
  l'ensemble joignable doit être **exactement** les flux déclarés, chaque flux déclaré doit
  atteindre un service actif, aucun refus ne doit répondre. Rapport : `build/drift-report.json`.
