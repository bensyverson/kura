# Provider and version pins for the Kura DigitalOcean Standard-Regulated
# baseline. Terraform/OpenTofu is a separate tool, not a Go-module
# dependency, so it does not touch Kura's supply-chain surface (see the
# Phase 0 dec-terraform decision).
terraform {
  required_version = ">= 1.6"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}
