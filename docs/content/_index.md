---
title: Kura
layout: hextra-home
---

<div class="hx-mt-6 hx-mb-6">
{{< hextra/hero-headline >}}
  An auditable secure-data-store&nbsp;<br class="sm:hx-block hx-hidden" />you can stand up in an afternoon
{{< /hextra/hero-headline >}}
</div>

<div class="hx-mb-12">
{{< hextra/hero-subtitle >}}
  One open-source Go binary that provisions and operates a&nbsp;<br class="sm:hx-block hx-hidden" />secure, audited, PII-aware data store.
{{< /hextra/hero-subtitle >}}
</div>

<div class="hx-mb-6">
{{< hextra/hero-button text="Read the docs" link="docs" >}}
</div>

<div class="hx-mt-6"></div>

{{< hextra/feature-grid >}}
  {{< hextra/feature-card
    title="One core, four faces"
    subtitle="Cedar authorization, audit logging, and PII masking live in one core library. The CLI, HTTP API, dashboard, and MCP server are thin adapters over it."
  >}}
  {{< hextra/feature-card
    title="The core is the gate"
    subtitle="Every path — API, CLI, break-glass — runs authn → authz → access → mask → audit. Enforcement is impossible to skip by construction."
  >}}
  {{< hextra/feature-card
    title="Agent-native CLI"
    subtitle="Markdown by default, JSON opt-in, greppable errors, set-shaped operations. Built for a local agent operating a remote deployment."
  >}}
  {{< hextra/feature-card
    title="Auditable by design"
    subtitle="100% open source. A smaller audit and supply-chain surface is a security posture, not just aesthetics."
  >}}
{{< /hextra/feature-grid >}}
