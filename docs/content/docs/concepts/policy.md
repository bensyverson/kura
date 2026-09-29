---
title: Cedar policy
weight: 3
---

Kura's authorization rules are **Cedar policy**. This page records the **v1
policy-apply ceremony** — how policy gets onto a running server, and what is
deliberately *not* built yet.

## The v1 posture: load at deploy time

The server loads its Cedar policy from the **deployment repo at startup / deploy
time**. Changing policy means changing the repo and redeploying. That is the whole
ceremony.

- **No `kura policy apply` command in v1.** No live apply path.
- **No watch-and-reload.** Policy is read once, at startup.
- **PR-gating comes for free.** Changing the repo *is* a pull request, so every
  policy change is already reviewed and history-tracked — no separate approval
  mechanism needed.
- **The API reads, never writes.** `GET /api/policy` renders the effective policy
  from the IR for review; there is no write method on the route. Reading policy is
  a server endpoint; authoring it is not.

## Why nothing more, yet

v1's Cedar UI is a **read-only structured viewer** (see the architecture doc). Nothing
on a running surface can change policy — so a live apply path would solve a problem
that does not yet exist. Building one now would be speculative.

The dedicated apply ceremony is **revisited when the structured Cedar *editor*
lands** (a future phase). At that point there is a real requirement — a surface that
edits policy — and the ceremony is designed against it, not ahead of it. Free-form
Cedar authoring stays a repo/PR activity regardless.

## The Cedar engine

Kura does **not** implement Cedar evaluation itself — re-implementing an authorization
engine is a security risk. It depends on
[`github.com/cedar-policy/cedar-go`](https://github.com/cedar-policy/cedar-go), the
official Go implementation in the Cedar Policy GitHub organization (originally
contributed by StrongDM, adopted by AWS into the official org).

**Maturity:** past 1.0 and actively maintained — v1.6.1 as of May 2026, with a
documented backward-compatibility policy. It supports parsing Cedar policy text,
evaluating requests against principal/action/resource/context, and both the
human-readable and JSON policy formats. It does not yet ship a stable schema
validator, partial evaluation, or policy templates — none of which v1 needs.

## The policy IR

Policy authoring in Kura happens through a structured **intermediate representation
(IR)**, not free-form Cedar. The IR is the constrained, safe subset — the same model
the dashboard's structured viewer renders and the future structured editor will edit.

The IR's axes come from the schema manifest: **roles × entities × PII-categories ×
actions**.

- **Roles** — named permission bundles. Principals are assigned roles; grants attach
  permissions to roles.
- **Entities** — the manifest's entities.
- **Actions** — `read`, `list`, `create`, `update`, `delete`.
- **PII categories** — for `read` and `list` grants, the [PII
  categories](../schema-manifest/#pii-categories) a role may see in plaintext. A
  category a grant does not list is masked.

The IR is **permit-only**: deny-by-default, no `forbid` rules. That is what keeps it
the safe subset. Free-form Cedar — including `forbid` — stays a repo/PR activity.

### The IR is the policy ceiling (decided 2026-05-19)

Cedar is far more expressive than what Kura enforces (`forbid`, `when`/`unless`
ABAC conditions, entity hierarchies, request context). **The IR is the hard ceiling
for Kura's enforced authorization policy; that extra expressiveness is a non-goal.**
The only evaluator path is `cedar.NewEvaluator(cedar.DefaultPolicy(m))` — there is no
loader for raw Cedar text, so free-form Cedar is neither enforced nor representable,
by design.

This is a deliberate trade of expressiveness for **auditability and completeness**.
Kura's audience is the 1–3 non-expert admins per client who must be able to read the
*whole* policy: because the IR is the ceiling, the dashboard's structured grid is the
**complete, authoritative picture** of what the deployment enforces — never a partial
view sitting above hidden free-form rules. Admitting free-form Cedar would break that
property, which is the policy viewer's reason for existing. If this is ever revisited,
the agreed rendering is recorded on job `60Ljz`: render the Cedar *scope* structurally
and show `when`/`unless` *conditions* verbatim (never an auto-generated paraphrase of a
security rule).

### Compilation and evaluation

The IR **compiles to Cedar policy text**, and the compiler guarantees validity by
round-tripping its own output through the Cedar engine's parser — a generator bug can
never ship as a malformed policy. Each grant becomes a `permit`; PII visibility
compiles to a separate `viewPII` action gated on the PII category.

The **evaluator** wraps the engine. A request carries the principal, its roles, the
action, the resource, and the **PII categories detected in that resource** — and the
evaluator decides visibility *per category*. It never sees, and never decides on, a
column or field name: access control keys on detected PII category, exactly as the
reference architecture requires.

### The default three-role model

`DefaultPolicy` builds a starting point a deployment then edits:

| Role | Actions | PII visibility |
|---|---|---|
| `admin` | all | every category |
| `user` | all | every category **except** high-sensitivity (those stay masked) |
| `auditor` | `read`, `list` only | none — all PII masked |

For an [append-only entity](schema-manifest#append-only-entities), `all` excludes
`update` and `delete`: even `admin` gets `create`, `read`, and `list` only.

## Append-only entities

When the manifest marks an entity [`append_only`](schema-manifest#append-only-entities),
the policy layer treats `update` and `delete` on it as structurally unavailable, not
merely ungranted:

- **Validation rejects them.** A policy that grants `update` or `delete` on an
  append-only entity fails validation with a matchable error
  (`append-only entity "X" cannot grant action "update"`). `create` stays the only
  write action.
- **The default policy never emits them.** `DefaultPolicy` skips `update`/`delete`
  grants for append-only entities entirely.
- **The viewer shows N/A.** The [policy viewer](dashboard) renders those cells as
  **N/A** rather than as empty grantable-but-ungranted cells, so a reviewer reads the
  immutability instead of mistaking it for a permission someone forgot to grant.

This is enforcement by validation, not type-level unrepresentability: which entities
are append-only is runtime manifest data, so any scheme bottoms out in a runtime lookup
anyway. The [database trigger](database#append-only-enforcement) is the mechanical
backstop beneath the policy.

### The snapshot-writer pattern

Append-only is absolute at the entity level, but a system that needs a *mutable
current view* over an immutable history models it as **two entities**: an append-only
event entity, and a separate non-append-only "snapshot" entity that exactly one service
role may `update`. That is pure configuration — grant `update` on the snapshot entity
to a single service principal in the policy; Kura needs no new code. The events stay
frozen; the snapshot is rebuilt from them.

The first time Kura grows a mutation path, two further controls land with it: an
application-layer check mirroring the trigger (defense in depth), and the
redaction-bypass distinction (a lawful-erasure path that is *not* an ordinary update).
Both are deferred until then — there is no mutation path today, so they would be
untestable dead code.
