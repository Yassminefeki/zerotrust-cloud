# 18 — Le robot de relevés et le partenaire de paiement (étape 12)

`make bot`, `make bot-run`, `make pay`, `make test-12`.

```
cloud host, espace réseau zt-bot ──wg (sa clé, 10.10.0.3)──► gateway ─[≤5 conn./s]─► frontend:8443 (relevés)
PayFlow (Internet, sans VPN) ─► Wi-Fi du cloud host:8444 ─DNAT─► gateway ─DNAT+SNAT─► frontend:8444 /webhook
```

## Le robot (`tools/zt-bot.py`)

- vit dans son propre espace réseau Linux sur le cloud host, dont la **seule** interface est son
  propre pair WireGuard, routé vers le frontend uniquement ;
- certificat d'**une heure**, **lié à son appareil** (`device: bot`) : le même certificat présenté
  depuis une autre adresse du tunnel reçoit 403 — une clé volée est inutile ailleurs ;
- `make bot-run` = nouveau certificat + une exécution ; relevés écrits dans `build/bot/`.

## Limites de débit

- par identité au frontend (`roles.<rôle>.rate_limit` : client/staff 240/min, bot 20/min,
  partenaire 60/min) : seau à jetons, **429** + `Retry-After`, journalisé une fois par rafale ;
- par pair au gateway (`conn_limit`, bot : 5 nouvelles connexions/s) : même un bot compromis ne
  peut pas inonder la banque.

## Le partenaire PayFlow

Un seul port de plus est publié (8444, filtré par **nom d'interface** sur le cloud host) ; le
gateway le traduit vers l'écoute partenaire du frontend, qui n'accepte que le certificat du
partenaire et seulement `POST /webhook`.

| Contrôle | Où | Refus |
|---|---|---|
| certificat = le partenaire | zt-mtls (frontend) | poignée de main / 403 |
| HMAC-SHA256(secret, `horodatage.nonce.corps`) | frontend | 401 (toute modification du corps aussi) |
| horodatage à ±300 s | frontend, puis la base | 401 |
| nonce jamais vu | **base** (`bank.partner_nonces`) | 409 requête rejouée |
| référence déjà créditée | base (`bank.incoming`) | mêmes valeurs : 200 `replayed`, payé une fois ; autres : 409 |
| destination = compte client, montant ≤ plafond | core + base | 404 / 422 |

Le secret est généré sur le cloud host (`ansible/.secrets/partners/`, jamais versionné ni
journalisé) et déployé seulement sur le frontend (root:zt-app 0640). L'argent arrive en partie
double depuis le compte de règlement du partenaire, audité avec son identité SPIFFE.

```bash
make pay TO=ZTB-ALICE-01 AMOUNT=10.00
.venv/bin/python tools/payflow.py --to ZTB-ALICE-01 --amount 1 --replay     # ou --skew -900, --tamper, --wrong-secret
```

**Tests** (`tests/edge/`) : espace réseau du bot limité à son tunnel, son pair sur le gateway,
relevés produits, il n'atteint que le frontend, certificat volé inutile ailleurs, limites de
débit, publication par nom d'interface, paiement depuis l'extérieur, rejeu refusé, nouvelle
tentative non repayée, refus, partenaire limité au webhook et refusé dans le tunnel, secret
uniquement sur le frontend, paiement audité.
