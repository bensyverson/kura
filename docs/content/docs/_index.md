---
title: Documentation
weight: 1
---

Welcome to the Kura documentation. Kura is an open-source, auditable secure-data-store template: one Go binary that provisions and operates a secure, audited, PII-aware data store for consulting engagements.

This documentation is agent-first. If you're an agent reading this for orientation, **Concepts** is the shortest path to a complete mental model. If you want to stand up a deployment, start with **Getting started**. If you're integrating a program against Kura, see the **Machine interface**.

The canonical reference for how the CLI behaves — and *why* — is [`project/2026-05-14-cli-design-guidelines.md`](https://github.com/bensyverson/kura/blob/main/project/2026-05-14-cli-design-guidelines.md). The architecture rationale lives in [`project/2026-05-14-architecture.md`](https://github.com/bensyverson/kura/blob/main/project/2026-05-14-architecture.md).

{{< cards >}}
  {{< card link="getting-started" title="Getting started" subtitle="Install Kura and stand up a deployment." >}}
  {{< card link="concepts" title="Concepts" subtitle="The core enforcement library, the adapter model, Cedar policy, audit, and PII masking." >}}
  {{< card link="machine-interface" title="Machine interface" subtitle="The HTTP API, CLI JSON output, agent-context, and the MCP server." >}}
  {{< card link="recipes" title="Recipes" subtitle="Workflows that compose commands — provisioning, the quarterly access review, incident triage." >}}
{{< /cards >}}

> This documentation is a skeleton. Sections are filled in as their build-plan phases land.
