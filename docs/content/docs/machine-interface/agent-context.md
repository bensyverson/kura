---
title: agent-context & the operations registry
weight: 1
---

`kura agent-context` emits a versioned, machine-readable JSON description of every
command Kura exposes — so an agent reads one document instead of scraping `--help`
across the command tree.

## The shape of the document

```json
{
  "version": "0",
  "global_flags": [
    { "name": "server", "type": "string", "summary": "..." },
    { "name": "as",     "type": "string", "summary": "..." }
  ],
  "commands": [
    {
      "name": "jobs",
      "summary": "Inspect and wait on async operations on the remote kura serve",
      "subcommands": [
        {
          "name": "get",
          "summary": "Read one job by id; with --wait, poll until it reaches a terminal status",
          "flags": [
            { "name": "wait",    "type": "bool",     "summary": "..." },
            { "name": "timeout", "type": "duration", "summary": "..." }
          ]
        }
      ]
    }
  ]
}
```

- `global_flags` carries the root's persistent flags — the state-carrying contract
  that every verb inherits (`--server`, `--client`, `--as`, `--json`, `--local`,
  `--confirm`).
- `commands` is the recursive tree of subcommands; each carries a `summary` and only
  its **own** flags (inherited globals are not duplicated). Cobra's built-in `help`
  and `completion` are excluded.

## How drift is prevented

The document is **generated from the live Cobra command tree** at execution time.
`emitAgentContext` walks `root.Commands()` recursively and calls
`pflag.FlagSet.VisitAll` for each command's local flags. There is no hand-maintained
list to keep in sync — a new verb added to `newRootCmd` shows up in `agent-context`
automatically.

The CLI test suite asserts the inverse: walking the Cobra tree and confirming every
command appears in the emitted JSON. A new verb that fails to surface — or a
regression that drops one — fails the build.

## The operations registry

Alongside the Cobra-tree walk, `internal/ops` holds a typed **operations registry**
— a `Registry` of `Operation` values, each carrying a name, a summary, typed args,
and a handler:

```go
type Operation struct {
    Name    string
    Summary string
    Args    []Arg   // typed: name, summary, type, required
    Handler func(args []string, out io.Writer) error
}
```

The registry is the typed seam shared with **MCP**: each `Operation` projects into a
Cobra command and (in future build-plan phases) an MCP tool. Operations are added to
the registry as their phases land. For now `agent-context` itself is registered there
so the CLI wiring is consistent, but its richer typed-args content is reserved for
the MCP path; `agent-context` itself reflects whatever the Cobra tree currently looks
like.

## Why a registry, and not the alternatives

- **Not reflection over Go types.** Reflection is implicit and fragile; a rename or
  a signature change silently reshapes the agent-facing contract. The registry is
  explicit data — what an agent sees is exactly what is written down.
- **Not a separate schema file.** A schema file is a second source of truth, and two
  sources of truth drift. `job`'s hard-won lesson: keep the contract *in* the code
  that implements it. The registry does that — it is Go code, but it is plain data,
  not behavior-by-reflection.

## Versioning

The `agent-context` document carries a `version` field (`ops.ContextVersion`,
currently `"0"` while Kura is pre-1.0). Parsers key off it; the schema is stable
within a version.
