// Package clio is Kura's shared CLI output and error layer.
//
// Three concerns belong here, and nowhere else, so that every kura
// command produces a uniform agent-facing contract:
//
//   - Output rendering. Dense Markdown is the default; --json is the
//     opt-in machine format. Both render the same field set, so output
//     format is a presentation choice — never a data-visibility one.
//     Masking happens upstream in internal/pii and internal/gate; by
//     the time a value reaches Render it is already masked, and the
//     renderer's job is to not unmask it. See TestRenderIsMaskingInvariant.
//
//   - Typed errors. Every CLI error is an *Error carrying a Kind from
//     the documented taxonomy and a stable `<verb>: <message>` first
//     line. Agents grep on that prefix and act on the Kind via the
//     exit-code taxonomy below.
//
//   - Exit codes. ExitCode(err) maps the Kind to a documented exit
//     code (0 success / 1 unclassified / 2 usage / 3 auth / 4
//     not-found / 5 conflict / 6 transient / 7 internal). The
//     taxonomy is pinned by tests and documented at
//     docs/content/docs/machine-interface/cli-output.md.
//
// The package is import-safe from any adapter (CLI today, MCP next)
// and depends only on the standard library. Per the adapter-over-core
// rule it carries no policy, no audit writes, and no masking rules —
// only the shapes the adapters agree on.
package clio
