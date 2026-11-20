# 24 — Scénario de la démo filmée (deux machines)

Deux scripts Python commentés, un par machine. Chacun affiche ce qu'il fait, lance les vraies
commandes, **anonymise tout ce qui s'affiche** (utilisateur, nom de machine, dossier personnel,
adresse Wi-Fi, adresses MAC) et enregistre une transcription par scène, transformée ensuite en
captures pour le rapport.

| Machine | Script | Transcriptions |
|---|---|---|
| **cloud host** (l'hyperviseur) | `python3 tools/demo.py` | `build/demo/cloud-host/C*.txt` |
| **poste distant** (l'utilisateur) | `python3 remote-client/demo.py` | `~/zt-demo-captures/R*.txt` |

Durée filmée : environ 8 à 10 minutes de matière brute, à monter en 3–5 minutes.

## 1. Préparer (hors caméra)

**Cloud host**

```bash
cd <dépôt> && git pull
make up && make test-0          # tout est en place
make attacks                    # 5 min : le rapport sera montré en C5
make client-certs               # certificats frais (24 h) ; envoyer alice/ et dev/ au poste distant
export PS1='cloud-host$ '       # invite sans nom d'utilisateur ni de machine
sudo -v
clear
```

**Poste distant**

```bash
cd <dépôt> && git pull
sudo wg-quick up wg0            # le tunnel
export ZT_CLOUD_HOST=<adresse Wi-Fi du cloud host>             # jamais affichée par les scripts
export ZT_CLOUD_SSH=<utilisateur>@<adresse Wi-Fi du cloud host>  # pour R8
export ZT_CLOUD_REPO=<chemin du dépôt sur le cloud host>        # pour R8
export PS1='remote-client$ '
sudo -v
clear
```

Fermer tout ce qui montre des données personnelles (notifications, autres onglets, gestionnaire
de fichiers). Firefox : profils `zt-alice` et `zt-dev` déjà configurés ([19](19-poste-distant.md)).

Enregistrer : OBS Studio sur chaque machine, ou l'enregistreur intégré de GNOME
(`Ctrl+Alt+Maj+R`). Deux vidéos, montées ensuite (ou un seul écran filmé avec un terminal SSH).

## 2. Les scènes

### Cloud host — `python3 tools/demo.py <scène>`

| | Scène | Ce que l'on voit | Message |
|---|---|---|---|
| `C1` | Le cloud et sa politique | `virsh list` (6 VM), acteurs et flux de `policy.yaml`, `make gen` | une seule source de vérité |
| `C2` | Isolation réseau | scan depuis le client VPN hostile : seul 8443 ; services internes silencieux ; rejets journalisés sur le gateway | ne jamais croire le réseau |
| `C3` | Les identités décident | Bob : compte d'Alice → 404, en-têtes forgés ignorés ; Dev : état 200, comptes 403 ; CSRF → 403 | moindre privilège |
| `C4` | Robot et partenaire | `make bot-run` ; `make pay` ; requête rejouée → 409 ; corps modifié → 401 | identités de machine, anti-rejeu |
| `C5` | Catalogue d'attaques | rapport A1–A11 DEFENDED ; `make attack A=8` en direct | sécurité mesurée |
| `C6` | Révocation en direct | `make revoke ACTOR=alice` ; la copie volée → 403 « revoked » | supposer la compromission |
| `C7` | Nouveau certificat | `make client-certs`, nouveau numéro de série | récupération |
| `C8` | Audit | `make audit` : aucune anomalie ; CRL de chaque service | tout journaliser |

### Poste distant — `python3 remote-client/demo.py <scène>`

| | Scène | Ce que l'on voit | Message |
|---|---|---|---|
| `R1` | Le tunnel | `wg0`, une seule route (le site), poignée de main récente | entrée unique |
| `R2` | Alice dans Firefox | comptes, virement de 1,00 € vers Bob, description `<script>…` affichée comme du texte | pas de mot de passe, pas d'injection |
| `R3` | Dev dans Firefox | santé du système, aucun compte | même poste, autres droits |
| `R4` | Débordements | `attack.py B2 B4` : identités forgées, compte de Bob, en-têtes, routes, CSRF | tout REFUSED |
| `R5` | Mouvement latéral | `sudo attack.py B3` : tous les réseaux routés dans le tunnel, silence | le gateway seul suffit |
| `R6` | Depuis l'extérieur | `attack.py B1 B5` : scan complet, faux paiements | une seule porte publiée |
| `R7` | Révocation vue du poste distant | B6 en attente → refus « revoked » ; Firefox refusé | moins d'une minute |
| `R8` | Nouveau certificat | récupération par SSH, import dans Firefox, Alice retrouve ses comptes | récupération |

## 3. L'ordre commun (à suivre pendant l'enregistrement)

| # | Cloud host | Poste distant |
|---|---|---|
| 1 | `C1` puis `C2` | — |
| 2 | — | `R1`, `R2`, `R3` |
| 3 | `C3` | — |
| 4 | — | `R4`, `R5`, `R6` |
| 5 | `C4`, `C5` | — |
| 6 | — | `R7` (laisser tourner : B6 attend) |
| 7 | `C6` (révoque) | R7 voit le refus ; recharger Firefox |
| 8 | `C7` | `R8` |
| 9 | `C8` (après avoir copié `remote-client-report.json` dans `build/reports/`) | — |

Les scripts annoncent en jaune, encadré, ce qu'il faut lancer **sur l'autre machine** à ce moment-là.
Pour tout enchaîner sur une machine : `python3 tools/demo.py` (toutes les scènes, pause entre chaque étape).

## 4. Les captures pour le rapport

**Automatiques** (transcriptions anonymisées → images de terminal) :

```bash
# cloud host
python3 tools/render_captures.py build/demo/cloud-host            # docs/screens/demo/cloud-host-C1.png …
# poste distant (puis copier les PNG vers docs/screens/demo/ du cloud host)
python3 tools/render_captures.py ~/zt-demo-captures --prefix remote-client
```

**À prendre à la main dans Firefox** (poste distant), à enregistrer dans `docs/screens/demo/` :

| Fichier | Quand |
|---|---|
| `firefox-alice-comptes.png` | R2, page d'accueil d'Alice |
| `firefox-alice-virement.png` | R2, après le virement (message de confirmation et historique) |
| `firefox-dev-operations.png` | R3 |
| `firefox-alice-revoquee.png` | R7, Firefox rechargé après la révocation |
| `firefox-alice-nouveau-certificat.png` | R8, Alice de retour avec son nouveau certificat |

Capture d'une fenêtre : `Alt+Impr` (GNOME), ou l'outil Capture d'écran. Vérifier qu'aucune barre
d'adresse, onglet ou notification ne montre autre chose que la banque.

Le rapport (`docs/rapport/rapport.tex`, section « Démonstration ») inclut automatiquement toutes ces
images dès qu'elles sont présentes ; recompiler : `cd docs/rapport && xelatex rapport.tex && xelatex rapport.tex`.

## 5. Avant de publier la vidéo ou les captures

- relire chaque image et la vidéo : aucune adresse Wi-Fi, aucun nom de machine ou d'utilisateur ;
- `make test-0` (le garde-fou `test_no_personal_data.py` vérifie aussi les fichiers texte du dépôt) ;
- ne jamais filmer `p12-password.txt`, `wg0.conf` ni le contenu de `ansible/.secrets/`.
