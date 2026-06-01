# Provider configuration and shared naming. The DigitalOcean provider is
# configured for both the control-plane API (do_token) and the
# S3-compatible Spaces endpoint (the spaces_* keys), so the storage
# resources administer buckets from the admin credential domain.
provider "digitalocean" {
  token             = var.do_token
  spaces_access_id  = var.spaces_access_key
  spaces_secret_key = var.spaces_secret_key
}

locals {
  # Every resource name is <client_slug>-<role>, so one glance at the DO
  # console says which client a resource belongs to.
  name = var.client_slug

  # The tag applied to droplets the database firewall and Cloud Firewall
  # rules target, so adding a droplet to the tag grants it network access
  # without editing firewall rules.
  droplet_tag = "${var.client_slug}-kura"
}
