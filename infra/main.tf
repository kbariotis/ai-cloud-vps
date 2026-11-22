locals {
  ssh_public_key = trimspace(file(pathexpand(var.ssh_public_key_path)))
  anywhere       = ["0.0.0.0/0", "::/0"]
}

resource "hcloud_ssh_key" "admin" {
  name       = "${var.name}-admin"
  public_key = local.ssh_public_key
}

# Network-edge firewall. Only the TLS endpoint is always public. SSH is closed by default and
# opened just-in-time to one /32 by `make ssh-open` / `make deploy` (Hetzner API, not SSH).
resource "hcloud_firewall" "this" {
  name = var.name

  rule {
    description = "ACME HTTP-01 + HTTPS redirect"
    direction   = "in"
    protocol    = "tcp"
    port        = "80"
    source_ips  = local.anywhere
  }

  rule {
    description = "HTTPS (OAuth-protected MCP gateway)"
    direction   = "in"
    protocol    = "tcp"
    port        = "443"
    source_ips  = local.anywhere
  }

  rule {
    description = "HTTP/3"
    direction   = "in"
    protocol    = "udp"
    port        = "443"
    source_ips  = local.anywhere
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = local.anywhere
  }

  # Present only while `make ssh-open`/`deploy` has set a /32; empty list = no SSH rule at all.
  dynamic "rule" {
    for_each = length(var.ssh_allowed_cidrs) > 0 ? [1] : []
    content {
      description = "Just-in-time admin SSH"
      direction   = "in"
      protocol    = "tcp"
      port        = "22"
      source_ips  = var.ssh_allowed_cidrs
    }
  }
}

resource "hcloud_server" "this" {
  name               = var.name
  server_type        = var.server_type
  image              = var.image
  location           = var.location
  ssh_keys           = [hcloud_ssh_key.admin.id]
  firewall_ids       = [hcloud_firewall.this.id]
  backups            = var.enable_backups
  delete_protection  = var.protect
  rebuild_protection = var.protect

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    admin_user     = var.admin_user
    ssh_public_key = local.ssh_public_key
  })

  # cloud-init only matters at first boot; Ansible owns the host afterwards.
  lifecycle {
    ignore_changes = [user_data, ssh_keys, image]
  }
}
