# Non-secret outputs the operator and the per-client repo need after apply.
# Secrets (database password, Spaces keys, the Tailscale key) are never
# output; they live in Doppler. The runtime database DSN is assembled by
# the operator from these values plus the Doppler-held password.

output "vpc_id" {
  description = "ID of the private VPC every resource attaches to."
  value       = digitalocean_vpc.kura.id
}

output "database_private_host" {
  description = "Private-network host for the Managed Postgres cluster; the API connects here over the VPC."
  value       = digitalocean_database_cluster.kura.private_host
}

output "database_port" {
  description = "Managed Postgres port."
  value       = digitalocean_database_cluster.kura.port
}

output "database_name" {
  description = "Application database name."
  value       = digitalocean_database_db.kura.name
}

output "database_user" {
  description = "API server's database user (minimum-privilege, application schema only)."
  value       = digitalocean_database_user.api.name
}

output "backups_bucket" {
  description = "Concrete backups bucket name; set as KURA_DO_SPACES_BACKUPS_BUCKET on the API server."
  value       = digitalocean_spaces_bucket.backups.name
}

output "audit_log_bucket" {
  description = "Concrete audit-log bucket name."
  value       = digitalocean_spaces_bucket.audit_log.name
}

output "api_droplet_ip" {
  description = "Public IPv4 of the API droplet (only 443 is reachable; SSH is Tailscale-only)."
  value       = digitalocean_droplet.api.ipv4_address
}

output "pii_droplet_ip" {
  description = "Public IPv4 of the PII-detection droplet."
  value       = digitalocean_droplet.pii.ipv4_address
}
