---
title: CLI output & errors
weight: 2
---

How `kura` returns information to its caller — agent or human. Three concerns are pinned by tests so they cannot drift: the **output format** (Markdown by default, JSON opt-in, masking-invariant), the **error contract** (greppable first-line prefixes, classified by `Kind`), and the **exit-code taxonomy** (a closed set of integer codes the agent acts on without parsing prose).

All three live in [`internal/clio`](https://github.com/bensyverson/kura/tree/main/internal/clio) — the shared output and error layer that every kura command and every other CLI-shaped adapter (future MCP error surface) routes through.

## Output formats

`kura` produces **dense Markdown** by default. It is 2–3× more token-efficient than JSON, and humans and agents read it well — a measured finding from the `job` CLI, not a guess.

`--json` is the **opt-in** machine format, emitted as indented JSON for deterministic parsers. The schema is stable within a major version.

`stdout` is data; `stderr` is diagnostics. They are never interleaved. ANSI color is not emitted today; when it is added, it will be suppressed off-TTY automatically.

### Masking invariance

Output format is a **presentation choice**, never a data-visibility one. Masking lives in the core (`internal/pii` and the gate-layer access checks); by the time a value reaches the renderer it has already been masked. A `--json` view that exposes a field the Markdown view hides — or vice versa — is a security bug.

This invariant is pinned by [`TestRenderIsMaskingInvariant`](https://github.com/bensyverson/kura/blob/main/internal/clio/render_test.go) at the shared-layer level and by [`TestWhoamiOutputIsMaskingInvariant`](https://github.com/bensyverson/kura/blob/main/cmd/kura/errors_test.go) at the command-call level.

## Error contract

Every error a kura command returns is a `*clio.Error` carrying:

- a **`Verb`** — the command (`whoami`, `login`, `profiles`, …) producing the error;
- a **`Kind`** — one of the closed taxonomy (`KindUsage`, `KindAuth`, `KindNotFound`, `KindConflict`, `KindTransient`, `KindInternal`);
- a **message** that names both the problem *and* the fix in one line, before any side effect occurs;
- an optional wrapped **cause**.

The formatted string is always `<verb>: <message>`. That prefix is the agent-facing contract — pinned by [`TestCLIErrorPrefixesAreGreppable`](https://github.com/bensyverson/kura/blob/main/cmd/kura/errors_test.go) so a refactor that breaks it fails CI before it reaches a caller.

When rejecting input from an enumerated set, the error lists the valid options inline. The agent gets the fix without scraping `--help`.

## Exit-code taxonomy

The agent must distinguish — without parsing prose — between *the kinds of things that can go wrong*, because each one drives a different next action: retry, ask for credentials, escalate, or fix input.

| Code | Kind             | When                                                                  |
| ---- | ---------------- | --------------------------------------------------------------------- |
| `0`  | success          | The command completed.                                                |
| `1`  | (unclassified)   | A non-typed error escaped the CLI. Treat as a bug report.             |
| `2`  | `KindUsage`      | Bad flag, missing argument, value outside an enumerated set.          |
| `3`  | `KindAuth`       | Not authenticated, or not authorized for the requested action.        |
| `4`  | `KindNotFound`   | The requested resource does not exist.                                |
| `5`  | `KindConflict`   | Precondition / state conflict (already exists, ledger contention).    |
| `6`  | `KindTransient`  | May succeed on retry — network blip, server 5xx, lock contention.    |
| `7`  | `KindInternal`   | Unexpected condition inside Kura itself. Escalate, do not retry.      |

Mapping lives in [`clio.ExitCode`](https://github.com/bensyverson/kura/blob/main/internal/clio/errors.go); the taxonomy is pinned by [`TestExitCodeTaxonomy`](https://github.com/bensyverson/kura/blob/main/internal/clio/errors_test.go) and [`TestKindEnumerationIsComplete`](https://github.com/bensyverson/kura/blob/main/internal/clio/errors_test.go). Adding a kind without updating the docs *or* the exit code breaks the build.

Wrapped errors keep their `Kind` through `errors.As`, so an `%w`-wrapped `clio.AuthError` still exits `3`.

## Why these are split

The `job` CLI gets by with `0/1/2` because every error has one human reader. Kura's primary caller is an agent, and the agent has to **act** on the difference between "retry the request" (transient) and "the caller is not who they say" (auth) and "fix your input" (usage). Collapsing those into one bucket forces the agent into prose-scraping, which is brittle.

The doc-02 threat model is explicit: "the agent stops and surfaces the blocker." The taxonomy is how the agent recognizes a blocker without guessing.
