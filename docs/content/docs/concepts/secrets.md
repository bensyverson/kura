---
title: Secrets
weight: 2
---

Every secret Kura touches — database passwords, OAuth client secrets, field
encryption keys, API keys — comes from a **secrets manager**, injected at runtime.
Nothing is baked into a container image, and nothing is committed. Secret access is
itself authenticated and audited, and encryption keys are managed and rotatable, not
hardcoded.

This page records the **secrets-backend decision** for the DigitalOcean
Standard-Regulated tier — Kura's happy-path deployment.

## The decision: Doppler

The Standard-Regulated secrets backend is **Doppler**.

- **Self-hosted Vault — rejected.** Too much ongoing operations burden for the
  handoff target. The deployment ends up owned by an SMB's in-house tech owner;
  a self-hosted Vault would rot post-handoff.
- **Cross-cloud AWS Secrets Manager — rejected.** Forces a second cloud account
  onto a DigitalOcean client and gives a worse bootstrap story.
- **Doppler — chosen.** Low-ops, SOC 2-attested, does runtime injection, and holds
  *only* secrets (never PII), so the added-sub-processor surface is bounded.

The Doppler account is **client-owned**: the infrastructure lives in the client's own
account, never the consulting firm's. It is provisioned during the engagement and
handed off with the rest of the stack.

## How it is applied

- **Phase 1 — secrets manager abstraction.** The core library defines a secrets
  interface with a test fake and a Doppler-backed implementation. No code path ever
  reads a secret from a baked-in env var or a committed file.
- **Phase 6 — secrets backend provisioning.** The IaC baseline provisions the
  client-owned Doppler project and wires runtime injection, verified by a smoke
  check.

The Heavily-Regulated tier (AWS/GCP, customer-managed keys) stays agent-generated per
the reference architecture and may choose a different backend; this decision is
scoped to the Standard-Regulated baseline.
