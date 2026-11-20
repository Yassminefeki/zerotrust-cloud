# 12 — Autorité de certification et certificats (étapes 3 et 6)

## Étape 3 — la CA (`make ca`, `make test-3`)

step-ca tourne sur la VM `ca`, sous un utilisateur `step` sans privilège, unité systemd durcie,
à l'écoute **uniquement** sur `10.50.0.10:9000` (mgmt), **TLS 1.3 seulement**.

- Les paquets step sont téléchargés une fois sur le cloud host (`build/artifacts/`) puis copiés :
  les VM n'ont pas Internet.
- Secrets : mot de passe des clés et mot de passe du provisionneur JWK, aléatoires, générés par
  Ansible dans `ansible/.secrets/` (0600, ignoré par Git), copiés en 0400 sur la CA.
- Durée : 24 h par défaut et au maximum ; renouvellement en mTLS avec le certificat courant,
  jamais après expiration.
- **Politique d'émission** (générée) : la CA refuse toute URI hors `spiffe://cloud.local/`, tout
  nom qui n'est pas une identité déclarée, toute IP qui n'est pas une adresse de plan de données
  (mgmt n'est jamais certifié), toute durée > 24 h.
- **CRL** activée et régénérée à chaque révocation (étape 13).
- Ancre de confiance : `build/pki/root_ca.crt` et son empreinte `root_ca.fingerprint`.

**Tests** (`tests/ca/`) : utilisateur non privilégié, écoute sur mgmt seulement, secrets privés,
configuration conforme à la politique, empreinte de la racine, TLS 1.2 refusé, émission d'un
certificat SPIFFE de 24 h, refus (domaine étranger, nom inconnu, adresse mgmt, durée 48 h),
renouvellement.

## Étape 6 — certificats des VM et des acteurs (`make certs`, `make client-certs`, `make test-6`)

### VM (frontend, service-a, service-b, database)

- la clé privée est générée **sur la VM** et ne la quitte jamais ;
- l'enrôlement utilise un **jeton à usage unique** créé sur la CA (5 min, lié aux SANs de
  l'identité ; le mot de passe du provisionneur ne quitte pas la CA ; un jeton rejoué est refusé) ;
- certificat : `CN=<vm>`, SAN `spiffe://cloud.local/<vm>`, adresses de plan de données seulement, 24 h ;
- `/etc/zt/pki/` : `cert.crt`, `cert.key` (root:zt-tls 0640), `root_ca.crt` ;
- `zt-cert-renew.timer` vérifie chaque heure et renouvelle quand il reste moins de 8 h ;
- un certificat **révoqué** est remplacé par une nouvelle clé (ré-enrôlement), pas renouvelé.

### Acteurs (alice, bob, dev, statements, payflow)

- clé générée **sur le cloud host** (`ansible/.secrets/pki/<cn>/`, 0600) ; seule la CSR va à la CA ;
- signée avec la durée de l'acteur (24 h, 1 h pour le bot) ;
- pour les acteurs du poste distant : paquet Firefox `.p12` (AES-256, mot de passe aléatoire)
  et guide `FIREFOX.txt`, exportés dans `build/export/remote-client/<acteur>/` ;
- `make client-certs` réémet ce qui manque ou expire bientôt (avant chaque test qui en a besoin).

**Tests** (`tests/pki/`) : identité de chaque VM, fichiers et permissions, minuterie, renouvellement
forcé, jeton à usage unique, certificats clients, rien de secret suivi par Git, exports.
