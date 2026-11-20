# 18b — Attaques, révocation et audit (étape 13)

## Le catalogue d'attaques

`tests/attacks/catalogue.yaml` (`make attack-list`) décrit, pour chaque attaque, l'attaquant,
son but, la défense et les tests qui la prouvent. `make attacks` les rejoue toutes et écrit
`build/reports/attacks.md` ; une attaque n'est **DEFENDED** que si tous ses tests passent.

| | Attaque | Défense prouvée | Poste distant |
|---|---|---|---|
| A1 | portable volé (copie du certificat d'Alice) | révocation → refusé partout en moins d'une minute, le certificat d'Alice continue de marcher, la CA refuse de renouveler, *fail-closed* | B6 |
| A2 | root sur le frontend | n'atteint que service-a, la CA et le cache apt ; ne détient aucune autre clé ; refusé par le ledger | — |
| A3 | mouvement latéral depuis le VPN, usurpation d'adresse | le gateway n'ouvre que le site | B3 |
| A4 | identités forgées (autre CA, expirée, aucune, autre identité) | refus à la poignée de main ou par la liste d'autorisation | B2 |
| A5 | scans TCP complets, du tunnel et de l'extérieur | seul 8443 dans le tunnel, seul 8444 dehors ; refus silencieux, journalisés | B1 |
| A6 | clé WireGuard volée sans la clé pré-partagée | aucune réponse | — |
| A7 | client qui déborde (IDOR, en-têtes forgés, autres rôles) | 404 / ignorés / 403, RLS | B4 |
| A8 | CSRF depuis une page malveillante | 415 / 403, jamais transmis | B4 |
| A9 | notification de paiement forgée ou rejouée | mTLS partenaire, HMAC, ±300 s, nonce et référence uniques | B5 |
| A10 | inondation | 429 par identité, limite de connexions par pair | — |
| A11 | écoute et déclassement (TLS 1.2, clair) | TLS 1.3 partout, PostgreSQL compris | — |

Résultat obtenu : **les 11 attaques DEFENDED** (119 tests en direct) et **B1–B6 DEFENDED** depuis le poste distant.

```bash
make test-13          # les nouvelles attaques en direct : A1, A2, A5
make attacks          # tout le catalogue
make attack A=1,5     # quelques-unes
```

## La révocation

- step-ca publie une CRL (`generateOnRevoke`).
- Sur chaque VM à service mTLS, `zt-crl` (minuterie systemd, chaque minute, `ProtectSystem=strict`,
  n'écrit que dans `/etc/zt/pki`) télécharge la CRL en TLS 1.3 épinglé sur la racine, **vérifie sa
  signature**, refuse une CRL datée du futur ou dont le numéro **diminue** (rejeu), puis publie
  les numéros de série révoqués.
- `zt-mtls` refuse un appelant révoqué (403, journalisé avec le numéro de série) et un serveur
  amont révoqué (502), **sans redémarrage**.
- Pas de liste, liste illisible ou périmée : **tout le monde** reçoit 503 (*fail-closed*). Bloquer
  la CA peut donc empêcher le service, jamais contourner une révocation.

```bash
make revoke ACTOR=alice REASON="portable volé"   # un acteur
make client-certs                                 # nouvelle clé + nouveau certificat pour Alice
make revoke NODE=service-a REASON="compromis"     # une VM
make certs                                        # la VM se ré-enrôle avec une nouvelle clé
```

`make revoke` crée sur la CA un jeton de révocation à usage unique (le mot de passe ne quitte pas
la VM), révoque, puis rafraîchit immédiatement chaque service. Pour un acteur, l'ancienne clé est
mise de côté (`ansible/.secrets/pki/<cn>/revoked/<série>/`).

Pourquoi pas la vérification CRL native d'OpenSSL : la CRL de step-ca porte un *Issuing
Distribution Point* et nos certificats n'ont pas de *CRL Distribution Point* ; OpenSSL la rejette
(« different CRL scope »). D'où le petit vérificateur dédié, testé contre un vrai step-ca.

## L'audit

`make audit [SINCE="2 hours ago"]` lit en SSH et en lecture seule : requêtes par identité, chaque
refus avec sa raison, la CRL appliquée par chaque service, l'expiration des certificats, les rejets
nftables de chaque VM, l'activité de step-ca, la table d'audit de la banque et l'équilibre du grand
livre, et les derniers rapports d'attaque (cloud host et poste distant). Il signale : une CRL
périmée ou différente d'un service à l'autre, un grand livre déséquilibré, une attaque non
défendue, une VM injoignable. Rapport : `build/reports/audit.md`. Il n'affiche aucune clé, aucun
jeton, aucun mot de passe.

## La démonstration

Deux scripts commentés, un par machine : `make demo` (ou `python3 tools/demo.py`) sur le cloud host,
`python3 remote-client/demo.py` sur le poste distant. Scènes, ordre commun, captures pour le rapport :
[24 — Scénario de la démo](24-scenario-demo.md).

## Risques résiduels

Voir [THREAT-MODEL.md](THREAT-MODEL.md) : un frontend compromis peut agir au nom de n'importe quel
client (dans les limites des routes client) ; le cloud host détient toutes les clés et expose ses
propres services au Wi-Fi ; la VM ca ; latence de révocation ≤ 60 s ; PostgreSQL ne vérifie pas la
CRL ; pas de redondance ; pas de cryptographie post-quantique.
