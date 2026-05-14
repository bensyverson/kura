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

## Scope

This decision is scoped to the **Standard-Regulated baseline** — the tested,
known-good IaC Kura ships and reuses. The Heavily-Regulated tier (AWS/GCP,
customer-managed keys) stays agent-generated per the reference architecture and is
not bound to Terraform.
