output "ipv4" {
  value = hcloud_server.this.ipv4_address
}

output "ipv6" {
  value = hcloud_server.this.ipv6_address
}

output "dns_records" {
  description = "Create these at your current DNS provider for the MCP subdomain (e.g. mcp.example.com). Nothing else in your domain changes."
  value = {
    A    = hcloud_server.this.ipv4_address
    AAAA = hcloud_server.this.ipv6_address
  }
}
