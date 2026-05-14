---
title: Concepts
weight: 3
---

The mental model behind Kura: the core enforcement library and the thin adapters over it, the `authn → authz → access → mask → audit` gate, Cedar policy, the audit log, PII detection and masking, and the schema manifest that drives every surface.

{{< cards >}}
  {{< card link="identity" title="Identity & principals" subtitle="The consultant authentication model and the Cedar principal schema." >}}
  {{< card link="secrets" title="Secrets" subtitle="The runtime-injection model and the Doppler secrets-backend decision." >}}
  {{< card link="policy" title="Cedar policy" subtitle="The v1 deploy-time policy-apply posture." >}}
  {{< card link="iac" title="Infrastructure as code" subtitle="The Terraform-for-IaC decision for the Standard-Regulated baseline." >}}
{{< /cards >}}

Other concept pages are filled in as the core enforcement library lands.
