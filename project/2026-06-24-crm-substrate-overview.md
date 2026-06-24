# CRM-substrate work — overview & cross-cutting context

- **Date:** 2026-06-24
- **Author:** Ben Syverson (with Claude)
- **Status:** Index / connective tissue for three accepted-in-principle decision docs. Start here.
- **Purpose:** A fresh agent planning this work should read this first, then the three docs below. This file holds the cross-cutting context (sequencing, deferrals, what's settled vs. open) that doesn't belong in any single capability doc.

## The three docs (all peers, all domain-agnostic substrate capabilities)

1. **`2026-06-24-field-encryption-crypto-shredding.md`** — encrypt PII by default; erase via crypto-shredding (destroy keys, reaches immutable backups); searchable PII via blind indexes. Largest and most foundational; touches the ingest write path and the encryption layer.
2. **`2026-06-24-relationships.md`** — persist typed edges between records (`one`/`many`) in a dedicated `kura.record_edges` table. Most self-contained; **already has a TDD-ordered `job import` task tree baked in.**
3. **`2026-06-24-append-only-entities.md`** — make designated entities insert-only via a DB trigger; deterministic event ordering; Cedar policy restriction. The CRM's only real reach into storage.

All three are **accepted decisions with rationale**, not proposals to re-open. Re-verify the code cites (they're as-of 2026-06-24), but don't re-litigate the decisions themselves — the docs record *why* alternatives were rejected.

## These supersede the brief

`local/2026-06-23-kura-crm-substrate-brief.md` is the **origin** but is **superseded**. It was written from the docs without reading source, and verification corrected several load-bearing claims (no monotonic sequence exists; `kura_api` has UPDATE/DELETE but no app mutation path exists; relationships aren't persisted at all; an EAV relationship approach can't hold `many`). **Implement from the three docs, not the brief.** Read the brief only for historical motivation.

## Why this work exists (the driver, kept out of the code)

A CRM is being built *on top of* Kura. Its one storage-reaching opinion is event-sourcing: an append-only event stream is the source of truth; the current-state "Party" record is a projection. The CRM needs three things from the substrate — append-only events, an event→subject **relationship**, and GDPR/CCPA **erasure** that reaches backups — which is exactly the three docs. Everything else (Party concept, lifecycle, timelines, projection logic) stays in the CRM. **Kura must stay domain-agnostic: no diff should mention CRM, party, customer, subject, or lifecycle.** The snapshot-writer rule (only the projector role may write the snapshot entity) is already expressible as a Cedar grant — config, no code (see append-only doc).

## Cross-doc dependencies & sequencing (input for the planner — not a decree)

- **Relationships is the most independent and "ready"** (it has the task tree). Its only soft dependency is the append-only `bigint` sequence, used to *order* "edges for subject X." Relationships can land first and gain ordering once the sequence exists.
- **The append-only `bigint` sequence (Item F) is a cheap early win** — a small migration that unblocks both append-only event ordering *and* relationships' ordered queries. Good to do early.
- **The append-only trigger (Item B)** is self-contained but is the architectural keystone of that doc (mechanical trigger + manifest-derived `append_only_entities` table, startup-reconciled on an elevated credential). Independent of the other two.
- **Encryption/crypto-shredding is the largest** and carries the most unresolved open questions (below). It's mostly in the key/encryption layer but **touches `storedEncrypted` in ingest**, which also interacts with relationships' plaintext endpoint handling — coordinate those at the ingest seam. Its design open-questions should be resolved before coding the key hierarchy.
- Suggested rough order: **append-only sequence (F) → relationships → append-only trigger/Cedar (B/D) → encryption** (largest, gated on design decisions). The planner should weigh this against effort and the open items, not follow it blindly.

## The "no mutation path" deferral cluster (revisit together)

Kura currently has **no update or delete path anywhere** (`RecordStore` is read-only; the gate only creates). Multiple deferrals all hang off this single fact and should be revisited **together** when the first mutation/update path is built:

- **Append-only Item C** — the app-layer "belt" (typed errors + Fake parity refusing mutation). Deferred; the DB trigger (B) is complete protection until then.
- **Relationships post-creation edge mutation** — add/remove/replace edges after creation. Deferred; v1 supplies edges at creation only.
- **Mutable-entity relationship edits** — same update path.
- **Redaction bypass (GUC vs. role)** — the one narrow append-only mutation (incidental free-text span redaction); rides with the erasure subsystem.

When that path lands: build C, decide the redaction bypass (lean: separate role), and decide how editing edges interacts with append-only source records — as one coordinated piece.

## Settled vs. open

**Settled (rationale in the docs — do not re-litigate):** crypto-shredding as primary erasure; encrypt-PII-by-default with sensitivity decoupled from shreddability; per-field-value keys; blind-index search with a separate pepper; dedicated edges table (not EAV); `one`+`many` at creation; Cedar validation-rejection (not type-unrepresentability); `create`-only for append-only entities; append-only set auto-reconciled with block-silent-loosening + audit; `bigint` sequence on all records; defer Item C.

**Open — these are USER decisions, not agent discretion (ask, don't assume):**
- Encryption key granularity at volume (per-field-value key count — validate it's operationally viable).
- The erasable key-store mechanism (KMS / secrets manager / dedicated), and its own excluded-from-immutable-backups durability story.
- Counsel/DPO sign-off on the HMAC-tokens-in-immutable-backups residual.
- Whether the external OpenAI PII detector is acceptable for a PII-safe posture, or needs an in-tenant alternative.
- Redaction bypass: GUC vs. separate DB role.
- Encrypt-by-default vs. detection-driven encryption (sizing the queryability cost — measure how much of `query`/`list`/dashboard filters on `value_text` server-side).

**Open — implementation discretion (decide while building):** edge authorization model details; F-index `seq` denormalization onto edges; DB-level cardinality (`one` partial-unique) as optional suspenders; startup-ordering feasibility (verify the elevated connection + parsed manifest are available together at reconciliation time).

## Process reminders (per CLAUDE.md)

- Strict red/green TDD — failing tests first, verify they fail, then implement.
- Migrations are forward-only and numbered; never edit a committed migration.
- Every new interface gets a Fake enforcing the same contract; new verbs flow through `internal/ops` (agent-context drift test).
- Keep `docs/content/docs/` updated as features land.
- Ledger: the relationships task tree is baked into its doc but **not yet `job import`ed**; the other two docs have no task breakdown yet.
