# net-wan  : libvirt NAT, used only by the gateway VM (host = .1, masquerade to the Wi-Fi).
# net-dmz/app/data : isolated, NO address on the host => pure L2, the host cannot talk to them.
# net-mgmt : isolated, host = 10.50.0.1 (Ansible/SSH, apt cache). No DHCP, no DNS anywhere.

resource "libvirt_network" "net" {
  for_each = var.networks

  name      = each.value.name
  bridge    = each.value.bridge
  autostart = true
  # libvirt "none" mode == isolated: no forwarding, no NAT, no route to anything.
  mode      = each.value.mode == "nat" ? "nat" : "none"
  addresses = each.value.host_ip == null ? [] : [each.value.cidr]

  dhcp {
    enabled = false
  }

  dns {
    enabled = false
  }
}
