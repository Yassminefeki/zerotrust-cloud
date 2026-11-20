# 01 — Analyse du sujet

## Le besoin

Construire, sur du matériel personnel, un petit « cloud » qui applique le modèle **zero trust** :
aucune confiance accordée à une machine du seul fait de sa position sur le réseau. Chaque requête
doit prouver **qui** l'envoie, **par où** elle passe et **ce qu'elle a le droit de faire**, à chaque
saut, et tout refus doit être tracé.

Contraintes retenues :

| Contrainte | Conséquence dans le projet |
|---|---|
| Un seul ordinateur pour le cloud, un second pour l'utilisateur | KVM/libvirt sur le cloud host, WireGuard vers le poste distant |
| Reproductible et vérifiable | tout est du code (Terraform, Ansible, générateur Python) ; chaque étape a ses tests |
| Aucun secret dans Git | clés et mots de passe générés par Ansible dans `ansible/.secrets/` (ignoré par Git) |
| Indépendant du réseau Wi-Fi | aucune adresse Wi-Fi écrite nulle part : le poste distant joint le cloud host par un **nom** (mDNS), le pare-feu de l'hôte filtre par **nom d'interface** |
| Avancer étape par étape | 14 étapes (0 à 13), chacune avec `make <étape>` et `make test-<N>` |

## Les principes zero trust traduits en mécanismes

| Principe (NIST SP 800-207) | Mécanisme |
|---|---|
| Ne jamais faire confiance au réseau | pare-feu *default drop* sur **chaque** VM, pas seulement en bordure ; aucune VM n'est routée vers une autre |
| Authentifier chaque requête | mTLS TLS 1.3 sur chaque saut (client → frontend → service-a → service-b → PostgreSQL) |
| Identité forte et de courte durée | certificats SPIFFE de 24 h (1 h pour le bot), émis par une CA interne (step-ca), renouvelés automatiquement |
| Moindre privilège | listes d'autorisation par service, routes par rôle, rôle PostgreSQL sans droit d'écriture, sécurité au niveau des lignes (RLS) |
| Supposer la compromission | chaque couche revérifie ; une VM compromise n'atteint que ses flux déclarés ; révocation en moins d'une minute |
| Tout journaliser | refus journalisés avec l'identité réelle à chaque couche ; audit en base ; `make audit` |

## Le cas d'usage : ZT Bank

Pour que la sécurité porte sur quelque chose de concret, le cloud héberge une banque :

- **Alice** et **Bob**, clients : consultent leurs comptes et font des virements ;
- **Dev**, support : voit l'état du système, jamais les données des clients ;
- **statements**, un robot : produit les relevés mensuels, certificat d'une heure, lié à sa machine ;
- **PayFlow**, partenaire de paiement : notifie des paiements entrants depuis Internet, sans VPN.

Chaque acteur n'a **pas de mot de passe** : son certificat client est son identité.

## Ce qui est hors périmètre

- la haute disponibilité (une VM par rôle) ;
- la sécurité du poste distant lui-même et du navigateur ;
- la cryptographie post-quantique (TLS et WireGuard utilisent X25519 / P-256) ;
- les services propres au cloud host qui ne font pas partie de la banque
  (voir le risque résiduel 2 du [modèle de menace](THREAT-MODEL.md)).

## Démarche

1. écrire la politique (`policy.yaml`) et un générateur qui la transforme en configurations ;
2. construire l'infrastructure couche par couche (hôte, réseaux, CA, pare-feu, VPN, certificats, services) ;
3. ajouter l'application (acteurs, banque, site, bot, partenaire) ;
4. attaquer le tout (catalogue A1–A11 depuis le cloud host, B1–B6 depuis le poste distant),
   ajouter la révocation et l'audit, documenter les risques résiduels.

À chaque étape : tests hors ligne (sans VM) puis tests en direct sur les VM.
