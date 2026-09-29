# Database: DO Managed Postgres on the private VPC, reachable only by the
# tagged droplets. Doc 03 provisioning step 5 and database-layer musts.
#
# "No public port" on DO Managed Postgres is achieved by the database
# firewall, not by removing an endpoint: DO always exposes a managed
# hostname, but the firewall's trusted sources here are restricted to the
# deployment's droplet tag, so no arbitrary public source can connect, and
# the droplets reach the cluster over the private network. TLS is required
# by the DO managed default (and Kura's db.Open refuses non-TLS DSNs).
resource "digitalocean_database_cluster" "kura" {
  name       = "${local.name}-pg"
  engine     = "pg"
  version    = var.postgres_version
  size       = var.database_size
  region     = var.region
  node_count = var.database_node_count

  # Attach to the private VPC so droplet-to-database traffic never leaves
  # the private network.
  private_network_uuid = digitalocean_vpc.kura.id
}

# The application database. pgcrypto (field-level encryption) is created by
# Kura's own migration system on first server start, per the project's
# migration convention; pgaudit is available on the supported Postgres
# versions (verify for the pinned version, per the doc 03 DO note).
resource "digitalocean_database_db" "kura" {
  cluster_id = digitalocean_database_cluster.kura.id
  name       = "kura"
}

# The API server's own database user, with rights to the application schema
# only — never a superuser (doc 03: per-component users, minimum privilege).
# Granted the kura_api role during provisioning: read/write the application
# data, no DDL, no role management, and — critically — no access to the
# append-only set (kura.append_only_entities), so a compromised runtime
# credential cannot unfreeze an entity the manifest marked insert-only.
resource "digitalocean_database_user" "api" {
  cluster_id = digitalocean_database_cluster.kura.id
  name       = "${local.name}-api"
}

# The migrator/owner database user — the elevated startup credential,
# granted the kura_admin role during provisioning. Credential-domain
# separation, mirroring the object-storage posture (the admin Spaces keys
# administer the bucket; the runtime keys only append): this user owns
# schema evolution and the append-only objects (the SECURITY DEFINER trigger
# and kura.append_only_entities), while the runtime "api" user above cannot
# touch them. The server uses this DSN (KURA_ADMIN_DATABASE_URL) only at
# startup, for migrations and append-only reconciliation; the runtime
# request path uses the "api" user. Not a superuser and not BYPASSRLS —
# kura_admin stays tenant-isolation bound like every other component role.
resource "digitalocean_database_user" "migrator" {
  cluster_id = digitalocean_database_cluster.kura.id
  name       = "${local.name}-migrator"
}

# Trusted sources: only the tagged droplets may connect. This is the
# control that keeps the cluster off the public internet.
resource "digitalocean_database_firewall" "kura" {
  cluster_id = digitalocean_database_cluster.kura.id

  rule {
    type  = "tag"
    value = digitalocean_tag.kura.name
  }
}
