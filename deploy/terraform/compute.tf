# Compute: two droplets on the private VPC — the PII detection service and
# the API server. Doc 03 provisioning step 6 stands the PII service up
# first because the API depends on it; the depends_on edge encodes that
# order. Both carry the deployment tag, so the Cloud Firewall and database
# firewall admit them, and both join the tailnet via cloud-init so there is
# no public SSH.

# Ubuntu LTS base image for both droplets.
locals {
  droplet_image = "ubuntu-24-04-x64"
}

# PII detection service (the self-hosted detector the API calls at ingestion
# and access time). Stood up first.
resource "digitalocean_droplet" "pii" {
  name     = "${local.name}-pii"
  image    = local.droplet_image
  region   = var.region
  size     = var.droplet_size
  vpc_uuid = digitalocean_vpc.kura.id
  tags     = [digitalocean_tag.kura.name]
  ssh_keys = var.ssh_key_fingerprints

  user_data = templatefile("${path.module}/cloud-init/tailscale.yaml.tftpl", {
    tailscale_auth_key = var.tailscale_auth_key
    hostname           = "${local.name}-pii"
  })
}

# API server. Caddy (configured in the 6tVWB leaf) terminates TLS in front
# of it; the firewall exposes only 443. Created after the PII droplet so the
# detector the API depends on exists first.
resource "digitalocean_droplet" "api" {
  name     = "${local.name}-api"
  image    = local.droplet_image
  region   = var.region
  size     = var.droplet_size
  vpc_uuid = digitalocean_vpc.kura.id
  tags     = [digitalocean_tag.kura.name]
  ssh_keys = var.ssh_key_fingerprints

  user_data = templatefile("${path.module}/cloud-init/tailscale.yaml.tftpl", {
    tailscale_auth_key = var.tailscale_auth_key
    hostname           = "${local.name}-api"
  })

  depends_on = [digitalocean_droplet.pii]
}
