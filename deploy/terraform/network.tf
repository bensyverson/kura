# Network: a private VPC for every resource, and a Cloud Firewall that
# leaves the droplets reachable only on 443 (TLS, terminated at the Caddy
# proxy) — never on a public SSH port. Administrative SSH reaches the
# droplets over the Tailscale interface instead (see compute.tf), so the
# firewall denies public 22 entirely. This is doc 03 provisioning step 2
# and principle 6 (network minimum exposure).

resource "digitalocean_vpc" "kura" {
  name     = "${local.name}-vpc"
  region   = var.region
  ip_range = "10.10.10.0/24"
}

resource "digitalocean_firewall" "kura" {
  name = "${local.name}-fw"

  # Applies to every droplet carrying the deployment tag.
  tags = [digitalocean_tag.kura.id]

  # Inbound: HTTPS only. The API runtime is never exposed directly; Caddy
  # terminates TLS and forwards to the API on the private network. There is
  # deliberately no public SSH rule.
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Inbound: Tailscale's WireGuard port, so droplets can establish direct
  # peer connections to the tailnet. Tailscale falls back to DERP relays
  # if this is blocked, but allowing it gives lower-latency admin access.
  inbound_rule {
    protocol         = "udp"
    port_range       = "41641"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Outbound: unrestricted, so droplets reach the Managed Postgres private
  # host, Spaces, Doppler, the Tailscale coordination server, and (for the
  # LLM gateway) the model provider. Egress is not the exposure surface
  # this baseline defends; ingress is.
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# The tag the firewall and database firewall target. A droplet joins the
# deployment's network posture simply by carrying this tag.
resource "digitalocean_tag" "kura" {
  name = local.droplet_tag
}
