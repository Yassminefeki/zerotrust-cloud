# 16 — ZT Bank : acteurs et application (étapes 9 et 10)

## Étape 9 — acteurs et routes (`make test-9`)

La politique déclare **qui** utilise la banque (`actors`, avec un `role`) et **ce que** chaque rôle
peut faire sur chaque service (`routes`, refus par défaut). Le générateur les transforme en
`mtls.json` ; `zt-mtls` répond :

- **404** à une méthode + chemin non déclarés ;
- **403** à une route déclarée mais pas ouverte à l'appelant (journalisé avec son identité) ;
- sinon, sert la requête.

Les services internes n'acceptent que leur nœud amont, et seulement sur leurs propres routes.
Même machine, droits différents : Alice et Dev travaillent depuis le même poste distant et le
même tunnel ; c'est leur certificat, pas le réseau, qui décide.

**Tests** (`tests/actors/`) : chaque acteur × chaque route (200 / 403 / 404 exactement comme la
politique), `whoami`, routes inconnues, refus journalisés, routes en service = routes générées,
certificat du bot d'une heure.

## Étape 10 — l'application (`make test-10`)

```
acteur (certificat) ─► frontend : web ─► service-a : core ─► service-b : ledger ─► PostgreSQL
                       identité tirée     validation,          seul client de      RLS, append-only,
                       du certificat      rôles, plafonds      la base             bank.transfer()
```

| API (frontend) | Qui | Quoi |
|---|---|---|
| `GET /api/me` | tous | qui suis-je (acteur, rôle, client) |
| `GET /api/accounts` | clients | ses comptes et soldes |
| `GET /api/accounts/<id>/transactions` | clients | historique ; le compte d'un autre = **404**, comme un compte inexistant |
| `POST /api/transfers` | clients | `{"from","to","amount","description","idempotency_key"}` ; même clé = même virement, payé une fois |
| `GET /api/statements?month=AAAA-MM` | bot | relevés, sans contreparties |
| `GET /api/status` | staff | compteurs, intégrité du grand livre, plafonds — jamais de données client |

**Qui est qui.** Le frontend tire l'identité, le rôle et le client **uniquement du certificat** ;
les en-têtes d'identité envoyés par un client sont ignorés. Les services internes reçoivent
l'identité dans des en-têtes `X-ZT-*`, qu'ils acceptent parce que seul leur nœud amont peut les
joindre (pare-feu + mTLS + routes), et ils revérifient le rôle.

**Dans la base** (`ansible/roles/postgres/templates/bank.sql.j2`) :

- tables appartenant à `bank_owner` (sans connexion) ; le rôle applicatif ne peut que lire —
  sous **sécurité au niveau des lignes** liée au paramètre de transaction `zt.customer` — et
  appeler trois fonctions ; aucun `INSERT`/`UPDATE`/`DELETE` ;
- l'argent ne bouge que par `bank.transfer()` : propriété du compte source, montant positif,
  plafond par virement et **limite journalière**, solde suffisant **sous verrou** (pas de double
  dépense), **clé d'idempotence**, **partie double**, ligne d'**audit** avec l'identité SPIFFE ;
- le grand livre est **append-only** : un déclencheur refuse `UPDATE`/`DELETE`/`TRUNCATE`, même
  pour l'administrateur de la base.

Données de démonstration : `ansible/roles/postgres/files/seed.yaml` (personnes fictives).

**Tests** (`tests/bank/`) : chacun ne voit que ses comptes, historique, IDOR → 404, en-têtes
d'identité ignorés, virement Alice → Bob, nouvelle tentative payée une fois, refus (compte
d'autrui, destination inconnue, montant négatif, plafond, même compte), relevés du bot, état pour
le staff, RLS dans la vraie base, le rôle applicatif ne peut pas écrire, historique non modifiable
même par l'administrateur, audit avec l'identité du certificat, refus nommant le vrai acteur à
chaque couche, grand livre équilibré.
