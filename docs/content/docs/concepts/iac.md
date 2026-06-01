---
title: Infrastructure as code
weight: 4
---

Kura's DigitalOcean Standard-Regulated deployment is **declarative
infrastructure-as-code**, not an imperative `deploy.sh`. This page records the
**Terraform vs. Pulumi** decision for that baseline.

## The decision: Terraform

The DigitalOcean Standard-Regulated baseline uses **Terraform**, not Pulumi.

The deciding factor is the **handoff target**. The IaC ships inside the thin
per-client repo that is handed to an SMB's in-house tech owner — and declarative HCL
is far more readable to a non-Go person than Pulumi's Go code. "Configuration is
code" only helps if the person who inherits it can read it.

Supporting reasons:

- **Plan/apply maps to the playbook.** `terraform plan` before `terraform apply`
  mirrors the strategic playbook's "read the agent's plan before it runs."
- **The test strategy is already Terraform-shaped.** Kura's IaC test plan —
  `tflint` / Conftest static checks and `terraform plan` snapshot tests — assumes
  Terraform.
- **No supply-chain cost.** Terraform is a separate tool the deployment invokes, not
  a Go-module dependency, so it never touches Kura's own supply-chain surface.

## The baseline

The baseline lives in
[`deploy/terraform`](https://github.com/bensyverson/kura/tree/main/deploy/terraform)
as a flat, parameterized root module. One module serves every engagement: a
deployment is described by a per-client `terraform.tfvars` (non-secret, committed to
the per-client repo) plus secrets injected at apply time from Doppler — never
committed, never baked into an image. `kura init` embeds this directory into the
per-client repo and instantiates it.

It provisions, in doc 03's dependency order:

| Resource | Posture |
| --- | --- |
| **VPC + Cloud Firewall** | Private network for everything; inbound **443 only**, **no public SSH** — administrative access is [Tailscale](#administrative-access)-only |
| **Spaces × 2** (`backups`, `audit-log`) | Private, versioned, lifecycle retention (35 d / 730 d), and a **deny-delete bucket policy** administered from the admin credential domain — the "suspenders" to the Go [`AppendOnly` role](storage)'s "belt" |
| **Managed Postgres** | On the VPC; a **database firewall** admits only the tagged droplets, so there is no public access; TLS-only; pgaudit/pgcrypto |
| **Droplets × 2** (PII, API) | Tagged into the VPC; join the tailnet via cloud-init; the PII detector is stood up first because the API depends on it |

### Administrative access

There is no public SSH port. Each droplet joins the client's Tailscale tailnet via
cloud-init and enables Tailscale SSH, so break-glass access is authenticated through
the tailnet identity rather than a static key on an open port. The Cloud Firewall
admits only 443 (the API behind Caddy) and Tailscale's WireGuard port.

The operator runbook — prerequisites, the Doppler-injected secrets, and the
`plan → apply → destroy` sequence — is in the module's
[`README.md`](https://github.com/bensyverson/kura/tree/main/deploy/terraform).
Real `terraform apply` runs against the operator's own DO account; `terraform
validate`/`fmt` and the static policy and plan-snapshot tests are the per-commit
gates that need no cloud account.

## Scope

This decision is scoped to the **Standard-Regulated baseline** — the tested,
known-good IaC Kura ships and reuses. The Heavily-Regulated tier (AWS/GCP,
customer-managed keys) stays agent-generated per the reference architecture and is
not bound to Terraform.
