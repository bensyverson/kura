# Kura CLI — Design Guidelines

**Audience:** agents (and humans) evolving the `kura` CLI. Read this before adding or
changing a command. It is the *why* behind the CLI's shape, not just the *what*.

These guidelines synthesize three sources:

- **`job`** (`~/git/jobs`) — Ben Syverson's agent-native task CLI. The proven Go
  patterns and the hard-won lessons (Markdown-default output, set-shaped operations,
  acks that teach, greppable contracts, `status` as session opener) come from real
  Claude Opus sessions captured in its `project/` feedback docs.
- **"10 Principles for Agent-Native CLIs"** (trevinsays.com) — the
  table-stakes/compounding framing, three-layer introspection, async-awareness,
  profiles, two-way I/O.
- **Kura's own architecture** — the adapter-over-core model, the remote-first CLI,
  identity-with-teeth, and the security-product fencing of otherwise-general advice.

Where `job` and the blog post disagree, this doc takes a position and says why.

---

## Mental model

### The CLI is an adapter, not the product

The product is `internal/` — the **core enforcement library** that owns Cedar
evaluation, audit logging, PII masking, and data access. The CLI, the HTTP API
(`kura serve`), the local dashboard (`kura dashboard`), and the MCP server
(`kura mcp`) are all thin adapters over that core.

When you add or change a CLI command, the logic belongs in the core; the `cmd/` file
is wiring plus presentation. If you find yourself putting a policy decision, an audit
write, or a masking rule in a `cmd/` file, stop — it belongs in `internal/`. The core
is the gate; the API is its primary public expression; the CLI is one client of it.

### The CLI is not the only agent surface

MCP is the other one. They are **two surfaces for two contexts**:

- **CLI** — for agents driving a shell (e.g. Claude Code operating an engagement).
- **MCP** — for agents with a typed tool client (e.g. a client's own agents
  post-handoff).

Keep them behaviorally consistent: they project from the same core operations
definition. A divergence between what the CLI can do and what MCP can do is a bug,
not a feature.

### The primary user is a local agent talking to a *remote* server

`kura <verb>` is, by default, an **HTTP client of a remote `kura serve`**. The mental
image: Claude Code on a consultant's laptop operating a client's deployed Kura
instance. Design every command for that path first.

`--local` (direct core-library access, on-box) is the **break-glass exception**, not
the default — it exists for incident response when the server itself is down, and for
the narrow provisioning window before the API is up. Doc 03 already reserves direct
access "for the tech owner during incident response"; `--local` *is* that path, made
ergonomic and still audited.

Consequences of remote-first:

- State an agent needs across calls lives in **flags or profiles**, never in assumed
  shell/env persistence. Agent runtimes vary wildly in whether environment survives
  between invocations; flags are strictly more portable.
- Latency and partial failure are real. Every command must be safe to retry.

---

## Principles

### 1. Non-interactive, always

No prompts, ever. No `[y/N]`. No TTY assumptions. Confirmation for a destructive
action is an explicit flag (`--confirm`). A command invoked by an agent that blocks
on a prompt is a hang, and a hang is the worst failure mode there is. Detect
non-TTY and behave headlessly; suppress ANSI color when output is not a terminal.

### 2. Markdown by default, `--json` opt-in — and masking-invariant

Dense Markdown is the **default** output. It is 2–3× more token-efficient than JSON
and both humans and agents read it well — this is a measured finding from `job`, not
a guess. `--json` is opt-in, for deterministic parsers, with stable, versioned
schemas. stdout is data; stderr is diagnostics; never interleave the two.

**Kura-specific:** the PII masking layer renders **identically** into both formats.
Output format is a presentation choice and must *never* change which fields are
visible. Masking lives in the core, upstream of formatting. A `--json` flag that
leaks an unmasked field that the Markdown view masked is a security bug.

### 3. Identity has teeth — every action is an audited Cedar principal

`job` treats identity as a coordination primitive with no security weight ("weak
security primitive, rich coordination primitive"). **Kura is the opposite.**

`--as` (or the active session token) resolves to a real **Cedar principal**, and
every CLI invocation lands in the audit log with that actor — exactly like a human in
the dashboard or a call through the API. There is no "the CLI is trusted" backdoor.
Never guess identity; never silently default it in a way that obscures who acted.
`kura login` performs the OAuth flow and caches a **short-lived** token; the token is
the identity.

### 4. Errors teach and enumerate; exit codes are a taxonomy

An error message names the problem *and* the fix in one line, **before** any side
effect occurs. When rejecting input from an enumerated set, list the valid options in
the error itself — don't make the agent go parse `--help`.

Error output is **greppable**: stable, first-line, machine-matchable prefixes. Those
prefixes are pinned by tests — the agent-facing contract is a regression surface.
(See `job`'s `TestRunDone_StrictErrorPrefixIsGreppable` for the pattern.)

Exit codes are a **documented taxonomy**, not just 0/1. The provisioning agent must
distinguish — without scraping prose — between: success, validation error, auth
error, not-found, conflict, and transient/retryable. `job` only needed `0/1/2`; Kura
needs more, because the agent has to *act* on the distinction (doc 02: "the agent
stops and surfaces the blocker").

### 5. Operations are set- and tree-shaped

Agents think in sets and trees; a CLI that only exposes scalars forces them into
for-loops, and "every for-loop is a diagnostic of a missing primitive" (`job`
feedback). Mutating verbs are **variadic and atomic**: `kura user add a@x b@x c@x` is
one transaction, all-or-nothing. Read verbs return related entities as **trees**, not
as flat rows the caller must re-join (e.g. `kura show order <id>` includes the
customer).

### 6. Acks teach — every success answers "what's next?"

Every tool call costs the agent a round-trip. A bare "OK" wastes it. A success ack
states what happened *and* the most likely next action: after `kura user add`, hint
the role-assignment command; after a provisioning step, hint the next step. The next
action is always the caller's immediate next thought — answer it.

### 7. Three-layer introspection

- **`--help`** — human-readable, per command.
- **`kura agent-context`** — a versioned, machine-readable JSON description of the
  *entire* command tree, so an agent never has to scrape help text.
- **Recipe/skill manifests** — long-form documentation of how to *compose* commands
  into workflows (provisioning, the quarterly access review, incident triage).

The middle layer is the one most CLIs skip; it is the one agents need most.

### 8. Async-aware

Long-running operations (provisioning steps, backup verification, restore tests)
expose `--wait` with internal polling/backoff, so the agent never hand-rolls a
polling loop. A durable job ledger (`kura jobs list/get`) survives disconnects, so a
retry finds existing work instead of starting a duplicate.

### 9. Profiles — multi-client, zero credentials

A consultant's laptop addresses **N** client servers. `kura --client <name>` resolves
to an endpoint plus a non-secret config bundle. Profiles hold endpoints and output
preferences and **never** credentials — tokens stay short-lived and come from
`kura login`.

(`job` deliberately has *no* profile concept because it is single-DB-local. Kura's
multi-target reality brings profiles back — but the no-credentials-on-disk rule is
non-negotiable for a security product.)

### 10. Security-product adaptations

Some otherwise-standard agent-CLI conveniences are **data-egress or credential
surfaces** in Kura's context and must be fenced:

- **Artifact delivery to arbitrary URLs/webhooks** is a PII exfiltration path. stdout
  and local file paths are fine; arbitrary URL delivery must be Cedar-gated and
  audited, or omitted.
- **Anything that persists config** must pass the doc-03 threat model: no long-lived
  secrets on disk, no plaintext credentials in profiles, no env-baked keys.

When a convenience and the threat model conflict, the threat model wins — and you
write down why.

### 11. Consistency, mechanically enforced

Universal vocabulary: `get`, `list`, `add`, `remove`, `--json`, `--confirm` — never
bespoke synonyms. Because the CLI, MCP, and `agent-context` all project from one
operations definition in the core, consistency and the introspection surface should
be **generated**, not hand-maintained per command. A hand-written command that drifts
from the generated surface is a bug.

---

## Checklist: adding or changing a command

- [ ] Logic is in `internal/`; the `cmd/` file is wiring + presentation only.
- [ ] Works over HTTP (the primary path). If it needs `--local`, that is justified
      and documented.
- [ ] Non-interactive; any confirmation is a flag.
- [ ] Markdown + `--json`; masking is identical across both formats.
- [ ] Resolves a real Cedar principal; emits an audit event.
- [ ] Errors are greppable, enumerate valid options, and are pinned by a test.
- [ ] Exit codes follow the taxonomy.
- [ ] Mutations are variadic, atomic, and idempotent.
- [ ] Success ack includes a "what's next" hint.
- [ ] Reflected in `agent-context` (ideally generated, not hand-added).

---

## Open questions (resolve, then update this doc)

- **`agent-context` mechanism** — RESOLVED. CLI commands, MCP tools, and
  `agent-context` all project from a Go-native operations registry in `internal/` (a
  registry of `Operation` values: name, summary, typed args, handler) — not
  reflection, not a separate schema file. Source of truth stays in Go code; all three
  surfaces read the same registry, so there is nothing to drift. See the Phase 0
  "Record & apply: agent-context generation mechanism" task.
- **Exit-code taxonomy** — enumerate the final list and pin it in a test.
- **`kura login` flow** — device flow vs. loopback-callback OAuth; how the
  short-lived token is cached and refreshed.
