variable "name" {
  description = "Base name for all resources."
  type        = string
  default     = "mcp"
}

variable "server_type" {
  description = "Hetzner server type. cax21 = 4 vCPU ARM / 8 GB RAM (~EUR 10.49/mo since 2026-06; check stock in the console)."
  type        = string
  default     = "cax21"
}

variable "location" {
  description = "Hetzner location (ARM types: fsn1, nbg1, hel1)."
  type        = string
  default     = "fsn1"
}

variable "image" {
  type    = string
  default = "ubuntu-24.04"
}

variable "admin_user" {
  description = "Non-root sudo user created by cloud-init; Ansible connects as this user."
  type        = string
  default     = "ops"
}

variable "ssh_public_key_path" {
  type    = string
  default = "~/.ssh/id_ed25519.pub"
}

variable "ssh_allowed_cidrs" {
  description = "CIDRs allowed to reach port 22. Keep [] at rest; `make ssh-open`/`make deploy` override it with your current /32 during a deploy."
  type        = list(string)
  default     = []

  validation {
    condition     = !contains(var.ssh_allowed_cidrs, "0.0.0.0/0") && !contains(var.ssh_allowed_cidrs, "::/0")
    error_message = "Never open SSH to the whole internet; use your own /32 (make ssh-open)."
  }
}

variable "enable_backups" {
  description = "Hetzner automated backups (+20% of server price). Off for now; flip to true when the box holds state worth keeping."
  type        = bool
  default     = false
}

variable "protect" {
  description = "Delete/rebuild protection on the server."
  type        = bool
  default     = true
}
