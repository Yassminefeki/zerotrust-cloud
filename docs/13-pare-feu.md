# 13 — Le pare-feu sur chaque VM (étape 4)

`make firewall`, `make test-4`.

Chaque VM charge `build/nodes/<vm>/nftables.conf` (généré) : une table `inet zt`, politique
**drop** en entrée, sortie et transit, conntrack pour les réponses, et une journalisation limitée
en débit avant chaque rejet (`journalctl -k | grep zt-drop-`). Un flux n'est ouvert que si les
**deux** extrémités l'autorisent : la sortie de la source et l'entrée de la destination.

Les refus sont **silencieux** (ni RST, ni ICMP) : un scanner ne distingue pas un port fermé d'une
machine absente.

## Protection contre le verrouillage

1. le SSH depuis le cloud host fait partie de la politique (`infra: admin-ssh`) ;
2. seul SSH peut répondre sans état conntrack (`stateless_replies`), car la session Ansible qui
   charge la toute première règle a été ouverte avant que conntrack ne la connaisse ;
3. `zt-nft-apply` sauvegarde les règles actives, arme un retour arrière de 120 s, charge les
   nouvelles ; Ansible ouvre alors une **nouvelle** connexion SSH et confirme. Si le SSH est coupé,
   la VM revient seule à l'état précédent et le playbook échoue clairement.

## Tests (`tests/firewall/`)

- les règles actives sont exactement les règles générées, persistantes, sans retour arrière en attente ;
- les réponses SSH survivent à la perte de l'état conntrack ;
- **matrice** : une vraie connexion TCP pour chaque source × destination × port de `build/matrix.json`
  (autorisé = poignée de main ou RST ; refusé = délai dépassé ou pas de route) ;
- refus silencieux, journalisés en entrée de la destination et en sortie de la source.

## Diagnostiquer un flux bloqué

```bash
ssh -F build/ssh_config <vm> sudo journalctl -k | grep zt-drop     # sur les deux extrémités
ssh -F build/ssh_config <vm> sudo nft list ruleset
```
