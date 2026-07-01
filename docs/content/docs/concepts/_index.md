---
title: Concepts
weight: 3
---

The mental model behind Kura: the core enforcement library and the thin adapters over it, the `authn → authz → access → mask → audit` gate, Cedar policy, the audit log, PII detection and masking, and the schema manifest that drives every surface.

{{< cards >}}
  {{< card link="schema-manifest" title="Schema manifest" subtitle="The keystone — the per-client file that drives every data surface." >}}
  {{< card link="identity" title="Identity & principals" subtitle="The consultant authentication model and the Cedar principal schema." >}}
  {{< card link="pii" title="PII detection" subtitle="The self-hosted detector and the ingestion / access-time call sites." >}}
  {{< card link="ingestion" title="Record ingestion" subtitle="The unified, manifest-driven write path — validate, scan, encrypt, audit — and its CLI/HTTP surfaces." >}}
  {{< card link="audit" title="Audit log" subtitle="The append-only record of who did what — and why the data never lands in it." >}}
  {{< card link="database" title="Database layer" subtitle="The Postgres schema, migrations, extensions, per-component roles, RLS, and encryption at rest." >}}
  {{< card link="encryption" title="Field encryption & crypto-shredding" subtitle="Encrypt-by-default, the separate erasable key store, and erasure as destroying a key — never a row." >}}
  {{< card link="secrets" title="Secrets" subtitle="The runtime-injection model and the Doppler secrets-backend decision." >}}
  {{< card link="policy" title="Cedar policy" subtitle="The v1 deploy-time policy-apply posture." >}}
  {{< card link="iac" title="Infrastructure as code" subtitle="The Terraform-for-IaC decision for the Standard-Regulated baseline." >}}
  {{< card link="storage" title="Object storage" subtitle="The two buckets outside Postgres — distinct credentials, retention as policy, the deny-delete posture." >}}
  {{< card link="llm-gateway" title="LLM access gateway" subtitle="The thin gateway for LLM calls — DPA gate at startup, metadata-only logging, hashes never contents." >}}
  {{< card link="gate" title="The enforcement gate" subtitle="The single core entrypoint — authn → authz → access → mask → audit, welded shut by construction." >}}
  {{< card link="server" title="The HTTP API server" subtitle="`kura serve` — the only public surface, a JSON API over the core gate." >}}
  {{< card link="dashboard" title="The local dashboard" subtitle="`kura dashboard` — the loopback-bound, server-rendered admin app over the remote API." >}}
{{< /cards >}}

Other concept pages are filled in as the core enforcement library lands.
