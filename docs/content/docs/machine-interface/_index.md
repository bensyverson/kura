---
title: Machine interface
weight: 4
---

How agents and other programs talk to Kura: the HTTP API exposed by `kura serve`, the CLI's `--json` output and `kura agent-context` introspection, and the `kura mcp` server. All surfaces project from one operations registry in the core, so they stay behaviorally consistent.

{{< cards >}}
  {{< card link="agent-context" title="agent-context & the operations registry" subtitle="How the CLI, MCP, and agent-context all project from one registry." >}}
{{< /cards >}}

Other machine-interface pages are filled in as the HTTP API, CLI, and MCP phases of the build plan land.
