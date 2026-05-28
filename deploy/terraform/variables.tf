# Per-client parameters for the Kura DO baseline. One baseline serves every
# Standard-Regulated engagement: a deployment is fully described by a
# terraform.tfvars (non-secret, committed to the per-client repo) plus the
# sensitive values below, injected at apply time from Doppler — never
# committed, never baked into an image.

# ---------------------------------------------------------------------------
# Deployment identity and placement
# ---------------------------------------------------------------------------

variable "client_slug" {
  description = "Short, lowercase, DNS-safe name for this client deployment; prefixes every resource name (e.g. \"acme\" -> \"acme-api\", \"acme-backups\")."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}[a-z0-9]$", var.client_slug))
    error_message = "client_slug must be lowercase alphanumeric/hyphen, 3-32 chars, starting with a letter."
  }
}

variable "region" {
  description = "DigitalOcean region slug for the primary stack, e.g. \"nyc3\". Must align with the client's data-residency requirements."
  type        = string
  default     = "nyc3"
}

variable "backups_region" {
  description = "Region for the backups bucket. Defaults differ from region so backups live in a separate region from the primary (doc 03 principle 7)."
  type        = string
  default     = "sfo3"
}

variable "primary_domain" {
  description = "Public hostname the API is served on (TLS terminated at the Caddy proxy, configured in the 6tVWB leaf)."
  type        = string
}

# ---------------------------------------------------------------------------
# Sizing (Standard-Regulated defaults; raise per engagement)
# ---------------------------------------------------------------------------

variable "droplet_size" {
  description = "Droplet size slug for the API and PII-detection droplets."
  type        = string
  default     = "s-2vcpu-4gb"
}

variable "database_size" {
  description = "Managed Postgres node size slug."
  type        = string
  default     = "db-s-1vcpu-2gb"
}

variable "database_node_count" {
  description = "Managed Postgres node count (1 = single node; raise for HA)."
  type        = number
  default     = 1
}

variable "postgres_version" {
  description = "Managed Postgres major version. Verify pgaudit and pgcrypto are available on this version before raising it (doc 03 DO note)."
  type        = string
  default     = "16"
}

# ---------------------------------------------------------------------------
# Secrets — supplied at apply time from Doppler (TF_VAR_*), never committed
# ---------------------------------------------------------------------------

variable "do_token" {
  description = "DigitalOcean API token with write access to the target account."
  type        = string
  sensitive   = true
}

variable "spaces_access_key" {
  description = "Spaces access key used by Terraform to administer buckets (the admin credential domain, distinct from the runtime append-only writers)."
  type        = string
  sensitive   = true
}

variable "spaces_secret_key" {
  description = "Spaces secret key paired with spaces_access_key."
  type        = string
  sensitive   = true
}

variable "tailscale_auth_key" {
  description = "Tailscale auth key the droplets use to join the tailnet via cloud-init. Use an ephemeral, pre-authorized key."
  type        = string
  sensitive   = true
}

variable "ssh_key_fingerprints" {
  description = "Optional DO SSH key fingerprints to embed for break-glass console access. Empty by default: routine admin access is Tailscale-only, no public sshd."
  type        = list(string)
  default     = []
}
