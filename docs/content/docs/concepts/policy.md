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
