# Offline plan tests: `tofu -chdir=infra test`. No Hetzner token needed.
mock_provider "hcloud" {
  # Real Hetzner IDs are numeric strings; firewall_ids/ssh_keys require them.
  mock_resource "hcloud_firewall" {
    defaults = { id = "1001" }
  }
  mock_resource "hcloud_ssh_key" {
    defaults = { id = "2002" }
  }
}

variables {
  ssh_public_key_path = "./tests/test_key.pub"
}

run "default_has_no_public_ssh" {
  command = plan

  assert {
    condition     = length([for r in hcloud_firewall.this.rule : r if r.port == "22"]) == 0
    error_message = "SSH must not be open when ssh_allowed_cidrs is empty."
  }

  assert {
    condition     = toset([for r in hcloud_firewall.this.rule : "${r.protocol}/${coalesce(r.port, "-")}"]) == toset(["tcp/80", "tcp/443", "udp/443", "icmp/-"])
    error_message = "Unexpected public firewall surface."
  }

  assert {
    condition     = hcloud_server.this.delete_protection && hcloud_server.this.rebuild_protection
    error_message = "Server must be protected by default."
  }

  assert {
    condition     = strcontains(hcloud_server.this.user_data, "disable_root: true") && strcontains(hcloud_server.this.user_data, "test-only")
    error_message = "cloud-init must disable root and install the admin key."
  }
}

run "jit_ssh_is_scoped" {
  command = plan

  variables {
    ssh_allowed_cidrs = ["203.0.113.10/32"]
  }

  assert {
    condition     = one([for r in hcloud_firewall.this.rule : r.source_ips if r.port == "22"]) == toset(["203.0.113.10/32"])
    error_message = "Just-in-time SSH must be limited to the given CIDR."
  }
}

run "rejects_world_open_ssh" {
  command = plan

  variables {
    ssh_allowed_cidrs = ["0.0.0.0/0"]
  }

  expect_failures = [var.ssh_allowed_cidrs]
}
