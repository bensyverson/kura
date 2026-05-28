---
title: Machine interface
weight: 4
---

How agents and other programs talk to Kura: the HTTP API exposed by `kura serve`, the CLI's `--json` output and `kura agent-context` introspection, and the `kura mcp` server. All surfaces project from one operations registry in the core, so they stay behaviorally consistent.

{{< cards >}}
  {{< card link="agent-context" title="agent-context & the operations registry" subtitle="How the CLI, MCP, and agent-context all project from one registry." >}}
  {{< card link="cli-output" title="CLI output & errors" subtitle="Markdown-default output, greppable error prefixes, and the exit-code taxonomy." >}}
  {{< card link="cli-session" title="CLI session" subtitle="status, login, logout, whoami — the four verbs an agent uses to orient itself." >}}
  {{< card link="cli-profiles" title="CLI profiles" subtitle="--client multi-target, kura profile list/add/remove, and the no-credentials rule." >}}
  {{< card link="cli-users-roles" title="CLI users & roles" subtitle="kura user/role verbs over the gated admin API — variadic, atomic, idempotent." >}}
  {{< card link="cli-data" title="CLI data verbs" subtitle="kura query / kura show — bounded, masked, flat (no relationship traversal)." >}}
  {{< card link="cli-audit" title="CLI audit verbs" subtitle="kura log / kura tail — filterable audit query and live NDJSON streaming." >}}
  {{< card link="cli-jobs" title="CLI jobs verbs" subtitle="kura jobs list/get and --wait — the durable, idempotent async-ops ledger." >}}
  {{< card link="cli-backup-restore" title="CLI backup & restore" subtitle="kura backup / kura restore — async, encrypted, append-only, admin-gated." >}}
  {{< card link="cli-smoke" title="CLI smoke verb" subtitle="kura smoke — the end-to-end health gate for CI, staging, and provisioning." >}}
{{< /cards >}}

Other machine-interface pages are filled in as the HTTP API and MCP phases of the build plan land.
