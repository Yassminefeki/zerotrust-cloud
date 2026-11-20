# 11 — Le cloud host, les réseaux et les VM (étapes 1 et 2)

## Étape 1 — préparer le cloud host (`make host`, `make test-1`)

Playbook `ansible/host.yml`, rôle `host`. Demande le mot de passe sudo une fois.

| Changement | Pourquoi |
|---|---|
| installe qemu-kvm, libvirt, genisoimage, avahi, libnss-mdns, apt-cacher-ng, wireguard-tools, tcpdump, nftables | VM, résolution du nom `.local`, paquets pour des VM sans Internet, outils de test |
| désactive le réseau libvirt `default` | il occupe 192.168.122.0/24, la plage du réseau `zt-wan` |
| `net.ipv4.ip_forward=1` (`/etc/sysctl.d/90-zerotrust.conf`) | le DNAT du Wi-Fi vers la VM gateway |
| avahi limité à l'interface Wi-Fi | le nom `.local` n'est annoncé que sur le réseau des clients |
| table nftables `inet zt_host` (jamais `flush ruleset`, jamais de *default drop*) | DNAT `iifname "<interface>" udp dport 51820` et `tcp dport 8444` vers le gateway ; cache apt joignable seulement depuis mgmt |
| hook libvirt `/etc/libvirt/hooks/network.d/zerotrust` | libvirt rejette le trafic entrant vers ses réseaux NAT ; le hook place l'acceptation WireGuard **avant** ce rejet, à chaque (re)démarrage |
| service `zerotrust-host` | réapplique le tout au démarrage, après libvirt et Docker |

Docker peut cohabiter : ses règles ne sont pas touchées.
Annuler : `sudo systemctl disable --now zerotrust-host && sudo rm /etc/libvirt/hooks/network.d/zerotrust`.

**Tests** (`tests/host/`) : l'interface existe, le nom `.local` se résout vers l'hôte, KVM
utilisable, versions des outils, DNAT par nom d'interface, aucune adresse Wi-Fi dans la
configuration installée, cache apt non exposé au Wi-Fi, avahi seulement sur le Wi-Fi.

## Étape 2 — réseaux et VM (`make infra`, `make test-2`)

`make image` télécharge une fois l'image Ubuntu 24.04 (cloud image), vérifiée par SHA-256, dans
`~/.cache/zerotrust`. Terraform (`terraform/`, fournisseur `dmacvicar/libvirt` 0.8) lit uniquement
`build/terraform.tfvars.json`.

| Réseau libvirt | Mode | Adresse de l'hôte | Rôle |
|---|---|---|---|
| zt-wan | NAT | 192.168.122.1 | seul le gateway y est ; cible du DNAT |
| zt-dmz, zt-app, zt-data | isolé | **aucune** (L2 pur) | plans de données : l'hôte ne peut pas les joindre |
| zt-mgmt | isolé | 10.50.0.1 | SSH/Ansible, enrôlement auprès de la CA, cache apt |

| VM | Mémoire | Interfaces |
|---|---|---|
| gateway | 1 Go | wan, dmz, mgmt (+ wg0 à l'étape 5) |
| frontend | 1 Go | dmz, app, mgmt |
| service-a | 1 Go | app, mgmt |
| service-b | 1 Go | app, data, mgmt |
| database | 2 Go | data, mgmt |
| ca | 1 Go | mgmt |

Pas de DHCP ni de DNS : adresses statiques par cloud-init (netplan par adresse MAC, interfaces
renommées `wan0 dmz0 app0 data0 mgmt0`), IPv6 désactivé, `rp_filter=1`, redirections désactivées,
routage activé **seulement** sur le gateway. Deux routes dans tout le cloud : la route par défaut
du gateway et la route retour du frontend vers le tunnel.

Les VM n'ont pas Internet : leurs paquets passent par le cache apt du cloud host (apt-cacher-ng).

Commandes utiles :

```bash
make wait              # attend que chaque VM réponde en SSH et que cloud-init ait fini
make recreate-vms      # recrée les 6 VM (garde réseaux et image)
ssh -F build/ssh_config frontend      # SSH vers une VM, par mgmt
```

**Tests** (`tests/infra/`) : réseaux actifs et dans le bon mode, l'hôte n'a d'adresse que sur
mgmt et wan, aucune route de l'hôte vers les plans de données, VM démarrées avec la bonne
mémoire, interfaces, adresses et routes exactes, durcissement sysctl, aucune sortie sauf par le
gateway, VM non routées entre réseaux, disques confinés au pool.
