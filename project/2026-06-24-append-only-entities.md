# Append-only entities — substrate enforcement, ordering, and policy

- **Date:** 2026-06-24
- **Author:** Ben Syverson (with Claude)
- **Status:** Draft — decisions captured and accepted in principle; pending implementation planning (no `job import` yet).
- **Pairs with:** `project/2026-06-24-field-encryption-crypto-shredding.md` (the erasure/encryption strand). Read together: this doc covers making designated entities insert-only; the companion covers how their PII is encrypted and erased.
- **Origin:** Reviewing `local/2026-06-23-kura-crm-substrate-brief.md` (the "Kura → CRM substrate" append-only brief) against the actual code. The brief was written from the docs, not the source, and asked that every claim be verified first. This doc records what verification found and the decisions that followed.

## Why this work exists

A CRM is being built *on top of* Kura. Almost all of its opinions (a "Party" record, lifecycle stages, timelines, context injection) live in the CRM layer and need nothing from Kura. The **one** exception is event-sourcing: the CRM's source of truth is an append-only event stream, and the current-state record is a *projection* derived from it. "Append-only source of truth" is a fundamentally different write contract than Kura's current mutable model, so it is the only CRM opinion that reaches down into storage.

**Scope is therefore narrow:** give Kura the ability to enforce, for *designated* entities, an insert-only contract — offered as a declarable capability (exactly as PII categories are declarable), which the CRM *chooses* to use. Nothing in the resulting diff should mention CRM, party, customer, or lifecycle. A reviewer who knew nothing about the CRM should read it as "Kura now supports append-only entities," full stop.

## Current state (verified against code, 2026-06-24)

- **No monotonic sequence on records.** `kura.records` is `id uuid PK, tenant_id, entity text, created_at timestamptz, updated_at timestamptz` (`internal/migrations/0001_app_schema.sql:16`). There is a `created_at` but **no sequence**, and a vestigial `updated_at` that is never written (a tell that no update path exists).
- **`kura_api` *can* mutate, but the app *cannot*.** `kura_api` holds `SELECT, INSERT, UPDATE, DELETE` on the `kura` schema (`internal/migrations/0003_component_roles.sql:32`), yet the application exposes **no update or delete path**: `RecordStore` is read-only (`internal/data/data.go:48`), the gate only `Ingest`s/creates (`internal/gate/ingest.go`), and there are no update/delete routes. `ActionUpdate`/`ActionDelete` exist in the Cedar IR but nothing invokes them. The real mutation exposure today is direct `kura_api` access, not an app path.
- **Forced RLS** on tenant-scoped tables keyed on the `kura.tenant_id` GUC (`internal/migrations/0002_row_level_security.sql`). Kura is **single-tenant per deployment** (`tenant_id` is the `KURA_DB_TENANT_ID` constant); the manifest is one file loaded into memory at startup (`KURA_MANIFEST_PATH`).
- **No manifest→DB projection exists.** Entity metadata is not stored anywhere; `entity` is a free-text discriminator on each row. The Cedar policy is derived from the manifest *in memory* at startup and never persisted.
- **Cedar IR** is a flat `[]Grant` of `(role, entity, action)` tuples (+ visible-PII for reads); actions are string constants `read/list/create/update/delete` (`internal/cedar/ir.go:27`); permit-only, deny-by-default; compiles to Cedar text and round-trips through the parser for validity.
- **Relationships are not persisted.** `manifest.Relationship` (`name`, `kind` one/many, `target`) is **declarative metadata only** (`internal/manifest/manifest.go:42`). Ingest rejects any field not declared in `e.Fields`, so a relationship value can't even be written; there is no edges table and no join key (the dashboard "follows" a relationship by linking to the target entity's list, not by querying — `internal/dashboard/data.go:54`). **This is a substrate gap the CRM depends on (see F).**

## Decisions

### A — Manifest `append_only` entity property + validation

Add an optional boolean `append_only` on an entity, following the existing optional-field convention (`omitempty`; the manifest already uses `omitempty`/pointers for optional properties — there are no existing boolean entity props to copy, so match the optional-scalar style). When true, records of that entity are insert-only.

Validation rules (§5 of the brief):
- Append-only entities may have relationships and may be the `target` of others' relationships (events are referenced).
- The validator **rejects** any policy that grants `update`/`delete` on an append-only entity, with a matchable message (e.g. `append-only entity "X" cannot grant action "update"`) — see D.
- Messages matchable and specific, consistent with existing manifest validation.

### B — DB-layer enforcement (the keystone)

A **mechanical** guard: Postgres itself rejects UPDATE/DELETE on append-only rows, regardless of who issues it or through what path. This is the "suspenders" (the app-layer "belt" is C, deferred). It defends the realistic threat — direct `kura_api` access, a buggy/compromised path, or a future mutation handler added without thought.

The mechanism splits into **mechanical enforcement + manifest-derived configuration**, and the work is in protecting the configuration:

- **Trigger, not RLS policy.** A `BEFORE UPDATE OR DELETE` trigger on `kura.records` and `kura.record_field_values` raises a clear, matchable error when the row's entity is append-only. Chosen over a second RLS policy because it gives a loud, specific failure and composes cleanly with the existing forced tenant-isolation RLS rather than stacking conflicting `USING` clauses.
- **A dedicated `kura.append_only_entities` table** (tenant-scoped, forced RLS) holds the set the trigger consults. *Not* a speculative general entity-metadata table — build the narrow thing. This is Kura's first manifest→DB projection.
- **Populated by startup reconciliation, on a credential separate from `kura_api`.** A static migration can't hold the set (migrations are static SQL; the append-only set is runtime manifest data), and the app can't hand it to the trigger per-transaction (the app is `kura_api`, the very role being constrained — it could declare an empty set and bypass). So the set is reconciled from the manifest at startup, written by the **elevated/migrator credential**, with the trigger as `SECURITY DEFINER` so `kura_api` needs **no access** to the table. This mirrors Kura's object-storage pattern: immutability "administered from a credential domain separate from the runtime writer."
- **Auto-reconcile, tighten silently, block silent loosening.** The manifest is the single source of truth and the set re-derives every boot ("derive, don't duplicate"). *Adding* append-only protection applies automatically. *Removing* append-only from an entity **that already has stored rows** is refused unless an explicit operator override is passed — so a security boundary can't be weakened as a silent side effect of a config edit. (An append-only entity with no rows yet can be loosened freely.) **Every change to the set is audited.**
  - *Implementation consequence:* reconciliation must check "does this entity have rows?" before allowing a removal — so the startup path touches `kura.records`, not just the set table.

### C — App-layer belt: **deferred**

The belt (gate/store refuses UPDATE/DELETE on append-only entities before the DB, with typed errors + Fake parity) is **deferred until an update/delete path exists.** Rationale:

- There is no app mutation path today (see current state). Building the belt now means a guard and a typed error **nothing can call** — dead code — and you can't write a red/green TDD test for refusing an operation that can't be invoked.
- It is **not costly to defer:** when the first mutation handler is built, adding the append-only refusal is a natural part of that work (you're already in the write path), and the failing test becomes writable then. The "cheap-now/annoying-later" argument doesn't apply.
- Until then, **B (the DB trigger) is complete protection.**

*Definition-of-done reframed:* the brief's "enforce at both layers" assumed update/delete already exist. They don't, so the app half is currently vacuous. **B now; C ships with the first mutation handler.** Leave a one-line note in the append-only docs so the belt isn't forgotten.

### D — Cedar IR: validation-rejection (not type-level unrepresentability)

For an append-only entity, no policy may grant `update`/`delete`. Achieved by **the validator rejecting** any such grant (matchable error) and `DefaultPolicy` never emitting one — *not* by making the grant unrepresentable in the Go type system.

- **True compile-time unrepresentability is effectively impossible here**, for a precise reason: which entities are append-only is *runtime* data (the manifest). Kura is compiled once and deployed against many manifests, so at compile time "entity X is append-only" isn't known. Any type-level scheme bottoms out in a runtime lookup against the manifest — which *is* validation-rejection. The only way to get a true type wall would be hardcoding entity names into Go, which detonates Kura's domain-agnosticism.
- **Same practical guarantee.** The viewer only shows loaded, valid policies; if no valid policy can contain the grant, the viewer can never show a phantom (unenforceable) grant. "The structured view is the complete authoritative picture" is preserved. This is also consistent with how the IR *already* guarantees validity (round-trip through the parser; manifest validation rejects bad config) — it's not a weakening, and it's automatic/fail-closed, so it satisfies "structural over disciplinary."
- **Belt-and-suspenders already holds** without a type wall: the validator refuses the grant *and* the DB trigger (B) physically rejects the mutation. A type wall would be a redundant third guard bought by complicating the deliberately-simple flat-list IR (which must stay readable by 1–3 non-expert admins).
- **`create` stays the only write action** for append-only entities (read/list/create available; update/delete forbidden).
- **Viewer presentation:** render update/delete as *structurally unavailable (N/A)* for append-only entities, not as an empty grantable-but-ungranted cell, so the immutability is legible.

### E — Erasure: reshaped, mostly moved to the companion doc

Crypto-shredding (companion doc) is the primary erasure path and **destroys external keys without mutating records** — so it needs no append-only exception, simplifying the brief's Item E considerably. What survives here:

- **Redaction-in-place is retained only for the entangled tail** — an incidental PII *span* inside another subject's append-only free-text field (a field is one ciphertext, so key-shredding can't target a sub-field span; redaction can). This is the *only* operation that mutates an append-only record.
- It therefore needs the trigger's controlled **bypass** — and that decision (GUC vs. separate DB role) is **deferred to the redaction work**, by the same YAGNI logic as C (no redaction operation exists yet). The trigger built now blocks all mutations; a forward-only migration adds bypass recognition when redaction lands.
- *Lean (for the record, not decided):* a **separate DB role**, not a GUC — a GUC lets `kura_api` self-bypass (guards only accidental mutation), and for an erasure-grade operation true credential separation fits the "do the correct/harder thing" posture. It will likely be near-free because redaction is part of the privileged erasure subsystem that already runs outside `kura_api`.

### F — Deterministic event ordering

- **Add a `bigint` monotonic sequence to all records** (one shared Postgres sequence; ~8 bytes/row). *All* records, not just append-only — ordering is a generally useful, cheap property, and gating it on a domain flag adds conditional complexity for no real saving. `created_at` is kept for wall-clock meaning but is **not** the order key (it ties within a transaction — `now()` is transaction-start time — and is subject to clock skew).
- **The sequence orders events *within* a subject; it is not a safe global progress cursor.** A sequence value is assigned at INSERT but only visible at COMMIT, and transactions can commit out of order — so a reader using `seq > N` to track progress across the whole stream can skip an event that committed late. Documenting this is an obligation.
- **Supported projection model: replay-from-scratch per subject.** "All events for subject X, `ORDER BY seq`" is correct and gap-immune once events are committed. For a CRM, per-subject event counts are small, so rebuilding a subject's snapshot on change is cheap and is the recommended approach — driven by "which subject changed," *not* by a global seq cursor. **Incremental cross-stream projection (and its gap-handling) is CRM-layer work; Kura builds none of it.** No commit-timestamp machinery in the substrate.
- **Prerequisite — relationship persistence (RESOLVED in its own doc).** The "events for subject X, ordered" index presupposes the event stores a reference to subject X. **It can't today** — relationships aren't persisted (see current state). This is a generic substrate gap, now decided in `project/2026-06-24-relationships.md`: a **dedicated `kura.record_edges` table** (FK-backed, both `one`/`many`), chosen over EAV field-values (which can't represent `many` and gives no referential integrity). The F index builds on that table.
- **Index:** query edges by `target_record_id` and order by the source record's `seq` (this sequence) via a join to `kura.records`. The endpoint id stays plaintext/indexable (excluded from encryption per the companion doc). Denormalize `seq` onto the edge only if profiling shows the join is hot.

## The snapshot-writer invariant (no new code)

The event-sourcing integrity contract is two rules: (1) events are immutable — items A–F; and (2) the Party *snapshot* entity is written only by the projection service. Rule (2) is already expressible in the existing Cedar IR — grant `update` on the snapshot entity to exactly one service role and to no one else (per-role-per-entity-per-action grants exist). So rule (2) is a CRM *configuration* of Kura, needing no Kura code. Document the pattern.

## Open items / prerequisites

1. **Relationship persistence** — *resolved* in `project/2026-06-24-relationships.md` (dedicated `kura.record_edges` table). It gated F's index; no longer open here.
2. **F index** — query edges by target, order by the record `seq` via join; pinned by the relationships doc.
3. **Startup-ordering feasibility** — confirm the startup sequence can run reconciliation with the elevated connection *and* the parsed manifest in hand (verification, not a decision).
4. **Redaction bypass** (GUC vs. role) — deferred to the redaction work (companion doc's erasure subsystem).
5. Companion doc's open items (key granularity, erasable key store, etc.) apply where erasure touches append-only entities.

## Relationship to the encryption doc

Crypto-shredding **decouples erasure from append-only**: the shred path destroys external keys and never mutates `kura.records`, so the append-only trigger needs no erasure exception for it. The controlled bypass survives only for the narrow incidental-span redaction case (E).

## Definition of done

- A manifest can declare an entity `append_only`; validation enforces the rules in A/§5.
- Records of an append-only entity can be inserted but cannot be updated or deleted by `kura_api`, enforced at the **DB layer** (B) with tests proving both that mutation raises and that non-append-only entities are unaffected. (App-layer belt C deferred to the first mutation handler.)
- The Cedar IR cannot grant `update`/`delete` on an append-only entity (validator rejects; `DefaultPolicy` never emits; viewer shows N/A); the structured view stays authoritative.
- Append-only entities have a deterministic per-subject replay order (the `bigint` sequence) and — once relationship persistence lands — an index supporting "events for subject X, ordered."
- Kura remains domain-agnostic: nothing in the diff mentions CRM, party, customer, or lifecycle.
- New interfaces have Fakes enforcing the same contract; new verbs flow through `internal/ops` and are covered by the agent-context drift test.
