---
title: agent-context & the operations registry
weight: 1
---

`kura agent-context` emits a versioned, machine-readable JSON description of every
operation Kura exposes — so an agent reads one document instead of scraping `--help`
across the command tree.

This page records **how** that document, the CLI command tree, and the MCP tool set
are kept consistent: they are all **projected from one operations registry**.

## The operations registry

The single source of truth is a Go-native **operations registry** in
`internal/ops` — a registry of `Operation` values, each carrying a name, a summary,
typed args, and a handler.

```go
type Operation struct {
    Name    string
    Summary string
    Args    []Arg   // typed: name, summary, type, required
    Handler func(args []string, out io.Writer) error
}
```

Three surfaces read that same registry:

- **The CLI** projects each `Operation` into a Cobra command.
- **The MCP server** projects each `Operation` into an MCP tool.
- **`kura agent-context`** projects the whole registry into its JSON document.

Because all three are projections of one slice, a divergence between what the CLI can
do and what MCP can do — or what `agent-context` advertises — is structurally
impossible. There is nothing to keep in sync.

## Why a registry, and not the alternatives

- **Not reflection over Go types.** Reflection is implicit and fragile; a rename or a
  signature change silently reshapes the agent-facing contract. The registry is
  explicit data — what an agent sees is exactly what is written down.
- **Not a separate schema file.** A schema file is a second source of truth, and two
  sources of truth drift. `job`'s hard-won lesson: keep the contract *in* the code
  that implements it. The registry does that — it is Go code, but it is plain data,
  not behavior-by-reflection.

The result: the build plan's "do the surfaces agree?" drift test is trivial — all
three surfaces read the same slice.

## Versioning

The `agent-context` document carries a `version` field (`ops.ContextVersion`,
currently `"0"` while Kura is pre-1.0). Parsers key off it; the schema is stable
within a version.

## Status

The mechanism is in place with a proof-of-concept seed: `agent-context` itself is the
first registered operation, so `kura agent-context` describes itself. Operations are
added to the registry as their build-plan phases land — each one becomes a CLI
command, an MCP tool, and an `agent-context` entry at once.
