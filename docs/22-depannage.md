# 22 — Dépannage

| Symptôme | Cause probable | Que faire |
|---|---|---|
| `make host` : interface introuvable | mauvais `wan_interface` | `ip -br link`, corriger `env.yaml`, `make gen host` |
| `make infra` : réseau 192.168.122.0/24 occupé | réseau libvirt `default` actif avec une VM | arrêter cette VM ; `make host` désactive `default` |
| `make wait` n'aboutit pas | VM lente au premier démarrage / cache apt | `make wait` à nouveau ; `virsh list --all` ; console `virsh console <vm>` |
| apt échoue sur une VM | cache apt du cloud host ou connexion lente | `systemctl status apt-cacher-ng` ; relancer l'étape (les tâches réessaient) |
| un flux expire | rejet nftables | `ssh -F build/ssh_config <vm> sudo journalctl -k \| grep zt-drop` sur les deux extrémités |
| changement de pare-feu, SSH perdu | règle qui coupe SSH | attendre 2 min : la VM revient seule à l'état précédent ; `make firewall` le signale |
| refus mTLS | identité, source ou route | `ssh -F build/ssh_config <vm> sudo journalctl -u zt-mtls \| grep refused` |
| 503 « revocation status unknown » partout | liste de révocation absente ou périmée (*fail-closed*) | `ssh -F build/ssh_config <vm> sudo systemctl start zt-crl` ; vérifier la CA (`make test-3`) |
| 403 « … is revoked » | certificat révoqué | `make client-certs` (acteur) ou `make certs` (VM) |
| certificat expiré (VM éteintes > 24 h) | durée 24 h | `make certs client-certs services` |
| le tunnel du poste distant ne monte pas | mDNS filtré, port non publié | `avahi-resolve -4 -n <hostname>.local` sur le poste distant, sinon ligne dans `/etc/hosts` ; `sudo wg show` des deux côtés ; `make test-1` |
| Firefox : « mot de passe incorrect » à l'import | dialogue d'import de Firefox | import en ligne de commande avec `pk12util` ([19](19-poste-distant.md)) |
| Firefox ne propose pas le certificat | profil différent | `firefox -P zt-alice --no-remote` |
| la base refuse | certificat de service-b, `pg_hba` | `ssh -F build/ssh_config database sudo journalctl -u 'postgresql@*'` |
| tests hors ligne « skipped » | outil absent (PostgreSQL, Playwright, NSS) | normal ; voir [20](20-tests.md) |
| `make audit` signale une CRL | une VM n'a pas récupéré la CRL depuis plus de 3 min | `systemctl status zt-crl.timer` sur la VM |
