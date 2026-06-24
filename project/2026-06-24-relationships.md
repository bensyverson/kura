# Relationship persistence — typed edges between records

- **Date:** 2026-06-24
- **Author:** Ben Syverson (with Claude)
- **Status:** Draft — decisions accepted in principle; implementation plan (for `job import`) at the end. No import run yet.
- **Pairs with:** `project/2026-06-24-append-only-entities.md` and `project/2026-06-24-field-encryption-crypto-shredding.md`. The three are peer substrate capabilities surfaced by the CRM-substrate brief.
- **Origin:** Surfaced while resolving Item F of the append-only work. The CRM's "event points at its subject" model assumes a stored reference between records — and verification showed **Kura doesn't persist relationships at all today.** That gap is a generic substrate primitive (any consumer needs edges), not append-only-specific, so it's captured here on its own.

## Why this is its own capability

Relationships are a core data-modeling primitive of *any* store: a person has many addresses, an order has many line items, an event has one subject. The CRM's event→subject edge is just the immediate driver. Nothing here is CRM-specific — Kura should end this work able to persist typed edges for any manifest, `one` or `many`.

The manifest **already declares** `Relationship{Name, Kind (one/many), Target}` as a first-class concept (`internal/manifest/manifest.go:41`), and validation **already** checks that a relationship's target entity exists (`internal/manifest/validate.go:68`). So the schema advertises relationships; storage just doesn't honor them yet. This closes that gap.

## Current state (verified 2026-06-24)

- **Relationships are declarative metadata only — never persisted.** Ingest rejects any field not declared in `e.Fields` (`internal/gate/ingest.go:131`), so a relationship value can't even be written. There is no edges table and no join key.
- The dashboard "follows" a relationship by linking to the target entity's *entire list* (`internal/dashboard/data.go:277`), not by querying actual edges.
- Manifest-level validation is done (target entity must exist); **instance**-level validation (does the target *record* exist? cardinality?) does not exist because nothing writes edges.
- Records are keyed by `uuid` PK; FK pattern in use is `REFERENCES kura.records(id) ON DELETE CASCADE` (`0001_app_schema.sql:28`). Latest migration is `0006`.

## Decisions

### R1 — A dedicated edges table, not EAV field-values

Persist edges in a new `kura.record_edges` table (tenant-scoped, forced RLS), **not** as rows in `record_field_values`. Three reasons, the first decisive:

- **EAV literally can't hold `many`.** `record_field_values` has `PRIMARY KEY (record_id, field_name)` — at most one value per field per record. A `many` relationship needs multiple targets; it cannot be represented without changing that PK. The manifest declares `many`, so storage must support it.
- **Referential integrity.** An edges table carries real FKs (`source_record_id` / `target_record_id REFERENCES kura.records(id)`), so an edge can't dangle. `value_text` is a generic shared column and can carry no FK — relationships there would be unverified strings, sharply against Kura's "structural over disciplinary" character.
- **It mirrors the manifest**, which already separates `Fields` from `Relationships`, and keeps the model generic (relationship name as *data*, like entity/field names elsewhere).

Shape (final SQL settles at implementation): `id, tenant_id, source_record_id (FK), target_record_id (FK), relationship text, created_at`. Indexes: `(tenant_id, target_record_id, relationship)` for "edges pointing at X" and `(tenant_id, source_record_id)` for "edges from X."

### R2 — Cardinality enforced at the gate, from the manifest

The gate validates cardinality against the manifest's declared `kind`: `one` → at most one target per `(source, relationship)`; `many` → multiple allowed. **No `cardinality` column on the edge** (it's a manifest property; storing it duplicates the source of truth and can drift). A DB-level partial-unique index for `one` is possible later as suspenders, but is not needed for v1.

### R3 — Both kinds, supplied at record creation; post-creation mutation deferred

Build **both `one` and `many`** now (we're in build mode, and a substrate that can't model `many` is crippled). The capability is delivered by accepting relationships **at record creation** (ingest): validated, authorized as part of `ActionCreate` on the source entity, persisted with FK integrity, and queryable by target/source.

**Deferred:** standalone *post-creation* add/remove/replace of edges. Rationale — that's a *mutation*, and Kura has **no update path anywhere** (the same finding that deferred append-only Item C). Post-creation edge mutation rides with that future update work, where it also has to answer how editing edges interacts with append-only source records. This keeps the v1 write surface minimal (the guardrail against over-building) without holding back the `many` *capability* — many edges can be supplied at creation. It is a scope line on *when* edges can be written, not on *which kinds*.

### R4 — Target ids plaintext and indexable; ordering via the record sequence

Edge endpoint ids are non-content structural keys: **plaintext, never encrypted** (consistent with the encryption doc, which excludes relationship references from encryption), so they're indexable. "All events for subject X, ordered" is served by querying edges by `target_record_id` and ordering by the source record's `seq` (the append-only doc's `bigint` sequence) via a join to `kura.records`. Denormalize `seq` onto the edge only if profiling shows the join is hot — not pre-emptively.

## Open questions (implementation-time)

1. **Edge authorization model.** Creation-time edges are covered by `ActionCreate` on the source entity (they're part of creating the record). Post-creation mutation (deferred) would need `ActionUpdate` on the source entity — confirm when the update path lands. Do *not* mint a new Cedar action speculatively (the IR is the ceiling).
2. **Append-only × edge mutation.** When post-creation edge mutation is built, decide whether an append-only source record's edges are fixed at creation (likely yes — the event's references shouldn't change).
3. **DB-level cardinality** — whether to add the `one` partial-unique index as suspenders.

## Relationship to the other docs

- **Append-only:** Item F's "events for subject X, ordered" index builds directly on this edges table (R4). This doc resolves that doc's open-item #1.
- **Encryption:** relationship endpoint ids live here as plaintext `uuid` columns (not as plaintext `record_field_values`); the principle (relationship keys never encrypted, stay indexable) is unchanged — only the location moves. The companion doc's D2 line is updated accordingly.

## Implementation plan (`job import`)

> **Import source note:** This block is reproduced (renumbered — edges migration `0007` → `0008`, `rel-pg` now blocked on the record sequence) in `project/2026-06-24-substrate-implementation-plan.md`, which is the authoritative `job import` source for the combined `Phase 9` substrate tree. Do **not** import this file directly, or the relationships subtree will be created twice. The block below is kept as the canonical rationale for the relationships breakdown.

Forward-only, TDD-ordered. Each leaf lands with failing tests first, then implementation. Fakes enforce the same contract as the real store.

```yaml
tasks:
  - title: "Relationship persistence: typed edges between records"
    ref: rel-root
    labels: [relationships, substrate]
    desc: >-
      Persist manifest-declared relationships as typed edges between records, supporting both `one`
      and `many` cardinality, with FK referential integrity, cardinality validation at the gate, and
      indexes for "edges pointing at target X" and "edges from source X". Relationships are supplied at
      record creation; standalone post-creation edge mutation is deferred with the (not-yet-existent)
      update path. See project/2026-06-24-relationships.md for the full rationale. Kura stays
      domain-agnostic — nothing here mentions CRM, party, or subject.
    children:
      - title: "Migration: kura.record_edges table"
        ref: rel-migration
        desc: >-
          New forward-only migration 0007_record_edges.sql creating kura.record_edges with
          source_record_id and target_record_id both REFERENCES kura.records(id), a relationship text
          column, tenant_id, created_at. Forced RLS keyed on the kura.tenant_id GUC, kura_api DML grant,
          and indexes (tenant_id, target_record_id, relationship) and (tenant_id, source_record_id).
          Mirror the patterns in 0001_app_schema.sql and 0002_row_level_security.sql. No cardinality
          column — cardinality is a manifest property enforced at the gate. Do not edit existing
          migrations.
        criteria:
          - "kura.record_edges exists with FKs from source_record_id and target_record_id to kura.records(id)"
          - "Forced RLS isolates rows by the kura.tenant_id GUC"
          - "Indexes on (tenant_id, target_record_id, relationship) and (tenant_id, source_record_id) exist"
          - "kura_api holds SELECT/INSERT on the table; migration applies cleanly on startup and is recorded in schema_migrations"
      - title: "Edge types and data-layer interface"
        ref: rel-iface
        desc: >-
          Define EdgeInput and Edge types and extend the data layer: RecordInput (internal/data/write.go:38)
          gains a relationships slice, the writer gains InsertEdges (edges written in the same tenant tx as
          their record), and add a reader EdgesByTarget / EdgesBySource. Document the contract that edges are
          created atomically with the source record.
        criteria:
          - "Edge/EdgeInput types defined and the writer/reader interface compiles"
          - "Contract documented: edges are written in the same tenant transaction as the record"
      - title: "MemStore edge implementation with contract tests"
        ref: rel-mem
        blockedBy: [rel-iface]
        desc: >-
          Implement edges in MemStore (internal/data/data.go) with by-target and by-source lookup. Strict
          TDD: write failing tests first for insert, query-by-target, query-by-source, and the one-cardinality
          contract, verify they fail, then implement. The Fake must enforce the identical contract the
          Postgres store will.
        criteria:
          - "Failing tests written and confirmed red before implementation"
          - "MemStore stores edges and EdgesByTarget/EdgesBySource return them"
          - "Fake enforces the same edge contract as the production store; tests pass"
      - title: "PostgresStore edge implementation with integration tests"
        ref: rel-pg
        blockedBy: [rel-iface, rel-migration]
        desc: >-
          Implement InsertEdges and EdgesByTarget/EdgesBySource on PostgresStore (internal/data/postgres.go)
          using the existing withTenantTx pattern. FK violations (target record absent) surface as typed
          errors. Integration tests run against the shared test Postgres container. Ordering for
          "events for subject X" is by the source record's seq via a join to kura.records.
        criteria:
          - "Edges insert inside a tenant-scoped transaction; RLS isolates by tenant"
          - "An edge to a non-existent record is rejected via the FK as a typed error"
          - "EdgesByTarget returns the target's edges, orderable by the source record sequence"
          - "Integration tests pass against the test Postgres container"
      - title: "Gate: accept and validate relationships at ingest"
        ref: rel-gate
        blockedBy: [rel-mem, rel-pg]
        desc: >-
          Extend IngestRequest (internal/gate/ingest.go:21) to carry relationship values, and validate each at
          ingest: the relationship is declared on the entity, the target record exists and is of the declared
          target entity, and cardinality holds (one → at most one target; many → multiple). Authorize as part of
          ActionCreate on the source entity; persist edges in the same path as the record; audit. Manifest-level
          target-entity validation already exists (validate.go:68) — this is instance-level. Strict TDD.
        criteria:
          - "Failing tests written and confirmed red before implementation"
          - "An undeclared relationship is rejected with a matchable error"
          - "A target that does not exist, or is of the wrong entity, is rejected with a matchable error"
          - "A second target on a `one` relationship is rejected; a `many` relationship accepts multiple"
          - "Edges are persisted with the record and the create action is authorized; tests pass"
      - title: "CLI/MCP surface: relationships on create + list-edges"
        ref: rel-cli
        blockedBy: [rel-gate]
        desc: >-
          Accept relationships in the create/ingest CLI input, and add a read verb to list a record's edges.
          Register both through internal/ops (cmd/kura/registry.go) so they appear in agent-context and MCP and
          satisfy the agent-context drift test; mirror the existing show verb (cmd/kura/data.go:70). Standalone
          post-creation add/remove/replace edge verbs are DEFERRED with the update path (no mutation path exists
          yet — see append-only Item C).
        criteria:
          - "Relationships can be supplied on record creation via the CLI"
          - "A list-edges verb returns a record's edges"
          - "New operations appear in agent-context JSON and the drift test passes"
      - title: "Docs: relationship persistence"
        ref: rel-docs
        blockedBy: [rel-cli]
        desc: >-
          Update docs/content/docs/concepts/schema-manifest and concepts/database to describe edge persistence:
          the record_edges table, cardinality validation, that relationships are supplied at record creation
          (post-creation mutation deferred), and that endpoint ids are plaintext/indexable. Include both a `one`
          and a `many` example.
        criteria:
          - "schema-manifest and database concept docs describe edge persistence and cardinality validation"
          - "Examples include both a one and a many relationship"
```

## Definition of done

- A manifest's `one` and `many` relationships can be **written at record creation** and are persisted as FK-backed edges in `kura.record_edges`, tenant-isolated by forced RLS.
- Ingest validates relationships instance-level: declared on the entity, target record exists and is of the declared entity, cardinality enforced — all with matchable errors.
- Edges are queryable by target and by source; "events for subject X, ordered" works via the record sequence.
- Endpoint ids are plaintext and indexed; nothing here is encrypted.
- New verbs flow through `internal/ops` and pass the agent-context drift test; Fakes enforce the store contract.
- Post-creation edge mutation is explicitly deferred (rides with the update path); Kura remains domain-agnostic.
