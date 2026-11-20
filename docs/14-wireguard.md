# 14 — WireGuard (étape 5)

`make wireguard`, `make test-5`.

- génère sur le cloud host, une seule fois, une paire de clés par nœud/pair et une **clé
  pré-partagée** par pair, dans `ansible/.secrets/wireguard/` (0600, ignoré par Git, jamais écrasé) ;
- installe `/etc/wireguard/wg0.conf` (0600) sur le gateway, `wg-quick@wg0` au démarrage ;
- écrit une configuration par pair dans `build/export/<pair>/wg0.conf` (0600).

| Pair | Adresse | Particularité |
|---|---|---|
| remote-client | 10.10.0.2 | le poste distant ; `Endpoint = <entry_point>:51820` (un **nom**), `AllowedIPs = 10.20.0.10/32` |
| bot | 10.10.0.3 | vit dans l'espace réseau `zt-bot` du cloud host ; limité à 5 nouvelles connexions/s |
| test-peer | 10.10.0.200 | client **hostile** pour les tests (`zt-peer`) : route **tous** les réseaux dans le tunnel, pour prouver que c'est le gateway qui bloque |

## Chemin d'un paquet du poste distant

Wi-Fi → interface du cloud host → DNAT (par nom d'interface) → `192.168.122.10:51820` →
`wg0` du gateway → nftables n'autorise que `frontend:8443` → le frontend voit la vraie adresse
tunnel (pas de NAT sur le gateway).

## Ce que prouvent les tests (`tests/wireguard/`)

- clés privées, jamais suivies par Git ; modèles sans clé ;
- export du poste distant correct (nom, pas d'IP ; seule l'adresse du frontend routée) ;
- poignée de main des deux côtés ; le chiffré sort bien par l'hôte ;
- depuis le tunnel : **seul** `frontend:8443` répond ; les refus sont journalisés sur le gateway ;
- une adresse tunnel usurpée est rejetée (chaque clé possède son /32) ;
- une clé inconnue, ou une clé privée volée **sans** sa clé pré-partagée : aucune réponse.

## Vérification manuelle depuis le poste distant

```bash
sudo wg-quick up wg0
sudo wg show wg0 latest-handshakes      # un horodatage récent
nc -vz -w 3 10.20.0.10 8443             # joignable
```
