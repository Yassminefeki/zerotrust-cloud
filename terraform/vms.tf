# 6 Ubuntu Server cloud-image VMs. Static IPs via cloud-init network-config (netplan v2):
# every NIC is matched by MAC and renamed (wan0, dmz0, app0, data0, mgmt0) so nftables
# rules can match interface names on every VM.

resource "libvirt_pool" "zt" {
  name = var.pool_name
  type = "dir"
  target {
    path = var.pool_path
  }
}

resource "libvirt_volume" "base" {
  name   = "zt-base-ubuntu.qcow2"
  pool   = libvirt_pool.zt.name
  source = var.image_url
  format = "qcow2"
}

resource "libvirt_volume" "disk" {
  for_each = var.nodes

  name           = "zt-${each.key}.qcow2"
  pool           = libvirt_pool.zt.name
  base_volume_id = libvirt_volume.base.id
  format         = "qcow2"
  size           = var.disk_size_bytes
}

locals {
  user_data = {
    for name, node in var.nodes : name => join("\n", ["#cloud-config", yamlencode({
      hostname         = name
      manage_etc_hosts = true
      ssh_pwauth       = false
      disable_root     = true
      users = [{
        name                = var.ssh_user
        groups              = ["sudo"]
        shell               = "/bin/bash"
        sudo                = "ALL=(ALL) NOPASSWD:ALL"
        lock_passwd         = true
        ssh_authorized_keys = [local.ssh_public_key]
      }]
      # Isolated VMs have no internet: apt goes through apt-cacher-ng on the host (mgmt).
      apt             = { proxy = var.apt_proxy, http_proxy = var.apt_proxy }
      package_update  = false
      package_upgrade = false
      write_files = [{
        path        = "/etc/sysctl.d/90-zerotrust.conf"
        permissions = "0644"
        content     = <<-EOT
          # cloud-init (terraform/vms.tf) — only the gateway forwards
          net.ipv4.ip_forward = ${node.ip_forward ? 1 : 0}
          net.ipv6.conf.all.disable_ipv6 = 1
          net.ipv6.conf.default.disable_ipv6 = 1
          net.ipv4.conf.all.rp_filter = 1
          net.ipv4.conf.default.rp_filter = 1
          net.ipv4.conf.all.accept_redirects = 0
          net.ipv4.conf.all.send_redirects = 0
          net.ipv4.conf.all.accept_source_route = 0
          net.ipv4.conf.all.log_martians = 1
        EOT
      }]
      runcmd = [["sysctl", "--system"]]
    })])
  }

  network_config = {
    for name, node in var.nodes : name => yamlencode({
      version = 2
      ethernets = {
        for i in node.interfaces : i.iface => merge({
          match        = { macaddress = lower(i.mac) }
          "set-name"   = i.iface
          dhcp4        = false
          dhcp6        = false
          "accept-ra"  = false
          "link-local" = []
          addresses    = ["${i.ip}/${i.prefix}"]
        }, length(i.routes) > 0 ? { routes = i.routes } : {})
      }
    })
  }
}

resource "libvirt_cloudinit_disk" "ci" {
  for_each = var.nodes

  name           = "zt-${each.key}-cloudinit.iso"
  pool           = libvirt_pool.zt.name
  user_data      = local.user_data[each.key]
  network_config = local.network_config[each.key]
  meta_data = yamlencode({
    "instance-id"    = "zt-${each.key}-${substr(sha256(join("", [local.user_data[each.key], local.network_config[each.key]])), 0, 12)}"
    "local-hostname" = each.key
  })
}

resource "libvirt_domain" "vm" {
  for_each = var.nodes

  name      = "zt-${each.key}"
  memory    = each.value.memory_mb
  vcpu      = var.vcpu
  autostart = true
  running   = true
  cloudinit = libvirt_cloudinit_disk.ci[each.key].id

  cpu {
    mode = "host-passthrough"
  }

  disk {
    volume_id = libvirt_volume.disk[each.key].id
  }

  dynamic "network_interface" {
    for_each = each.value.interfaces
    content {
      network_id     = libvirt_network.net[network_interface.value.network].id
      mac            = upper(network_interface.value.mac)
      wait_for_lease = false
    }
  }

  console {
    type        = "pty"
    target_type = "serial"
    target_port = "0"
  }

  # Ubuntu's virt-aa-helper builds each VM's AppArmor profile from the domain XML but does not
  # resolve <disk type='volume'> (pool/volume references): the disk and its backing image were
  # missing from the profile, so QEMU got "Permission denied" on the base image.
  # This rewrites our pool's volume disks into <disk type='file'> with the same path, so
  # virt-aa-helper adds exactly this VM's disk (rw) and the shared base image (r) — AppArmor
  # stays enforcing, nothing is widened. The qcow2 driver set by the provider is kept, and the
  # provider maps file disks back to the same volume_id on read (no perpetual diff).
  xml {
    xslt = local.volume_disk_as_file_xslt
  }
}

locals {
  volume_disk_as_file_xslt = <<-EOT
    <?xml version="1.0"?>
    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
      <xsl:output omit-xml-declaration="yes" indent="yes"/>
      <xsl:template match="node()|@*">
        <xsl:copy><xsl:apply-templates select="node()|@*"/></xsl:copy>
      </xsl:template>
      <xsl:template match="/domain/devices/disk[@type='volume' and source/@pool='${var.pool_name}']/@type">
        <xsl:attribute name="type">file</xsl:attribute>
      </xsl:template>
      <xsl:template match="/domain/devices/disk[@type='volume']/source[@pool='${var.pool_name}']">
        <source file="${var.pool_path}/{@volume}"/>
      </xsl:template>
    </xsl:stylesheet>
  EOT
}

output "vms" {
  value = { for k, v in libvirt_domain.vm : k => v.name }
}
