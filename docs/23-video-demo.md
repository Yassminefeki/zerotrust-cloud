# 23 — La vidéo de démonstration

`docs/video/zt-bank-demo.mp4` (3 min 50, 1080p) : visite du projet construite à partir des
**sorties réelles** des tests et des attaques, condensées et anonymisées (aucun nom de machine,
d'utilisateur ni d'adresse Wi-Fi). Elle est muette, avec des sous-titres ; le texte ci-dessous
permet d'y enregistrer une voix.

## Narration (une ligne par scène)

| Temps | Scène | Texte à dire |
|---|---|---|
| 0:00 | Titre | « ZT Bank : un mini-cloud zero trust complet, sur un seul ordinateur portable. » |
| 0:07 | Le sujet | « Le zero trust ne fait confiance à rien par défaut : à chaque saut, chaque requête doit prouver qui l'envoie, par où elle passe et ce qu'elle a le droit de faire. Voici comment chaque principe devient un mécanisme. » |
| 0:22 | Architecture | « Six machines virtuelles sur quatre réseaux isolés. Le poste distant entre par WireGuard ; le partenaire de paiement par un seul port publié. Chaque saut franchit trois verrous : le pare-feu, le chiffrement, l'identité. » |
| 0:42 | Politique | « Toutes les règles sont écrites une seule fois dans policy.yaml. Un générateur en tire le pare-feu, le mTLS, la base de données, la CA… et les tests. » |
| 0:57 | Construction | « Chaque étape se construit avec une commande et se vérifie avec ses tests, directement sur les VM. » |
| 1:11 | Alice | « Alice n'a pas de mot de passe : son certificat est son identité. Même un script dans une description reste du texte. » |
| 1:25 | Moindre privilège | « Depuis le poste distant, Alice tente de lire le compte de Bob, de payer à sa place, de forger des en-têtes, d'utiliser les routes du support, et un CSRF : tout est refusé. » |
| 1:45 | Dev | « Dev travaille depuis le même portable et le même tunnel, mais son certificat ne lui montre que la santé du système. » |
| 1:55 | PayFlow | « Depuis Internet, de faux paiements : sans le certificat du partenaire, sa signature et un nonce neuf, rien ne passe, et le solde d'Alice ne bouge pas. » |
| 2:09 | Catalogue | « Onze attaques rejouées depuis le cloud host : 119 tests, toutes repoussées. » |
| 2:31 | Mouvement latéral | « Un client VPN devenu hostile route tous les réseaux internes dans son tunnel : seul le site répond, le reste se tait. » |
| 2:49 | Révocation | « Le portable d'Alice est volé : on révoque son certificat. Moins d'une minute plus tard, la copie volée est refusée partout, sans redémarrer aucun service. » |
| 3:09 | Scan | « Un scan complet depuis le Wi-Fi : seul le port partenaire est un service de la banque. Le scan révèle aussi des services propres au portable : c'est documenté. » |
| 3:23 | Audit | « L'audit final relit les journaux, la révocation, le pare-feu et la base : aucune anomalie. » |
| 3:36 | Bilan | « Tout est dans le dépôt, avec la documentation pas à pas, le rapport et les risques résiduels. » |

Ajouter la voix (fichier `voix.m4a` enregistré par-dessus) sans réencoder l'image :

```bash
ffmpeg -i docs/video/zt-bank-demo.mp4 -i voix.m4a -map 0:v -map 1:a -c:v copy -c:a aac -shortest zt-bank-demo-voix.mp4
```

## Enregistrer une vraie démo à l'écran

Le scénario complet sur les deux machines (scènes C1–C8 et R1–R8, ordre commun, captures pour
le rapport) est dans [24 — Scénario de la démo](24-scenario-demo.md). Les scripts anonymisent
eux-mêmes ce qu'ils affichent ; relire quand même la vidéo avant de la publier.

Régénérer la vidéo muette : `python3 tools/video/make_video.py` (Pillow + ffmpeg ; chemins en tête du script).
