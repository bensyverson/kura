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

## Why nothing more, yet

v1's Cedar UI is a **read-only structured viewer** (see the architecture doc). Nothing
on a running surface can change policy — so a live apply path would solve a problem
that does not yet exist. Building one now would be speculative.

The dedicated apply ceremony is **revisited when the structured Cedar *editor*
lands** (a future phase). At that point there is a real requirement — a surface that
edits policy — and the ceremony is designed against it, not ahead of it. Free-form
Cedar authoring stays a repo/PR activity regardless.
