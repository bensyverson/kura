# Substrate capabilities — implementation plan (ledger import source)

- **Date:** 2026-06-24
- **Author:** Ben Syverson (with Claude)
- **Status:** Implementation plan. This is the authoritative `job import` source for the substrate work. Covers **record ordering (Item F)**, **relationships**, and **append-only entities**. The **encryption / crypto-shredding** subtree is intentionally *not* here yet — it is gated on a key-store/granularity decision (see below) and will be appended after that decision pass.
- **Read first:** `project/2026-06-24-crm-substrate-overview.md` (connective tissue), then the three peer decision docs. This doc turns those accepted decisions into a TDD-ordered task tree; it does not re-open them.

## Context — why this doc exists

Three peer substrate capabilities were accepted in principle (relationships, append-only entities, field-encryption/crypto-shredding) to let a CRM be built *on top of* Kura without Kura learning any CRM concepts. The decision docs record *what* and *why*; this doc records *how and in what order*, as the breakdown to import into the `job` ledger under one root. Kura stays domain-agnostic — nothing in the resulting diffs should mention CRM, party, customer, subject, or lifecycle.

This pass drafts the two fully-resolved capabilities (relationships, append-only) plus the small ordering primitive (Item F, extracted to run first). Encryption follows once its one genuine blocker is decided.

## Decisions resolved for this plan (2026-06-24)

These were settled in the planning session that produced this doc, on top of the decision docs:

1. **Item F (the `bigint` record sequence) is extracted as the first task.** Relationships' "events for subject X, ordered by `seq`" depends on it, and it is a cheap early win. It therefore takes migration **`0007`**, pushing relationships' edges migration to **`0008`** and append-only's to **`0009`**.
2. **All three capabilities live under one root**, framed domain-agnostically (`Phase 9 — Substrate capabilities`), matching the existing `Phase N` ledger convention. The ledger tracks the work; the code stays CRM-free.
3. **Encrypt-PII-by-default carries ~zero queryability cost today.** Verification found *no* server-side filtering/sorting/matching on `value_text` anywhere — the only read is decrypt-at-display projection (`internal/data/postgres.go:145`); value filtering is an unshipped future feature. The plaintext opt-out need only cover non-content structural types (`boolean`/`integer`/`timestamp`/`seq`). (Informs the deferred encryption subtree.)
4. **The PII detector is already in-tenant behind a swappable interface.** It is a self-hosted open-weight model reached via `KURA_PII_DETECTOR_URL` through the `Detector` interface (`internal/pii/detect.go:25`), not OpenAI-cloud. Acceptable for v1; an in-process detector is a tracked follow-up, not a blocker.
5. **The secrets infrastructure already exists but is unwired.** `internal/secrets` has a `Manager` + Doppler backend and the constants `FIELD_ENCRYPTION_KEY`/`BACKUP_ENCRYPTION_KEY`, but `serve.go` still reads keys straight from env. The KEK has a natural home (Doppler); per-field-value DEKs at volume do not — that is the encryption blocker below.
6. **The encryption key-store + per-field-value granularity question (#1/#2) is the one unresolved blocker** and is heavy enough to be its own decision pass (a volume-sizing analysis, then a store choice). Relationships + append-only are drafted now; encryption is drafted right after that decision. So all three still get planned; encryption's draft waits only on its real blocker.
7. **Append-only enforcement needs a migrator/owner DB role, which does not exist today.** Migrations currently run as `kura_api` (`internal/db/migrate.go`, `deploy/terraform/database.tf:34`); there is no elevated credential. Item B's enforcement depends on `kura_api` being unable to write the append-only set or own the trigger (else it could declare an empty set and self-bypass). So the append-only subtree provisions a new migrator/owner role — added scope the decision doc did not anticipate.

## Sequencing notes (guidance, not hard edges)

- Hard dependencies are encoded as `blockedBy` in the tree below. The only cross-subtree edge is **relationships' Postgres edge work → the record sequence** (the ordered-by-`seq` query joins `kura.records.seq`).
- Append-only (A/B/D) has no real dependency on relationships or the sequence, so it can proceed in parallel; the overview's suggested order (sequence → relationships → append-only → encryption) is a recommendation, not enforced.
- **The append-only doc's "F index" (events for subject X, ordered) is delivered by the relationships `rel-pg` leaf once the sequence exists** — there is no separate F-index task.
- **Deferred (kept out of the tree on purpose):** append-only Item C (app-layer belt) and Item E's redaction bypass (GUC vs. role). There is no mutation path in Kura today, so a guard would be untestable dead code. They ride with the first update/delete/redaction path; documented in prose, not as perpetually-blocked tasks.

## Import

This file's `tasks:` block is the import source. Validate, then import:

```
job import project/2026-06-24-substrate-implementation-plan.md --dry-run
job import project/2026-06-24-substrate-implementation-plan.md
```

**Imported 2026-06-24.** The `Phase 9` root is `pxV0E`. The encryption subtree will be imported under it later (after the key-store decision) with `job import <enc-doc> --parent pxV0E`.

## Task tree (`job schema` format)

```yaml
tasks:
  - title: "Phase 9 — Substrate capabilities: edges, append-only, ordering"
    ref: phase9-root
    labels: [phase-9, substrate]
    desc: >-
      Domain-agnostic substrate work surfaced by building a CRM on top of Kura: a monotonic record
      sequence for deterministic ordering, persisted typed relationships (edges) between records, and
      append-only entity enforcement. Field-level encryption / crypto-shredding is a fourth capability,
      planned separately and appended to this root after its key-store/granularity decision. Nothing in
      any resulting diff may mention CRM, party, customer, subject, or lifecycle — a reviewer should read
      every change as a generic store capability. See project/2026-06-24-crm-substrate-overview.md and the
      three peer decision docs for rationale; project/2026-06-24-substrate-implementation-plan.md for this
      breakdown.
    children:

      - title: "Record sequence: monotonic bigint ordering on all records"
        ref: seq-root
        labels: [substrate, ordering]
        desc: >-
          Append-only doc Item F, extracted to run first because relationships' ordered queries depend on
          it and it is a cheap, broadly useful primitive. Add one shared Postgres bigint sequence assigned
          to every record at INSERT (all entities, not just append-only — ~8 bytes/row). created_at is kept
          for wall-clock meaning but is not the order key (it ties within a transaction and is clock-skew
          prone). The sequence orders events within a subject; it is NOT a safe global progress cursor (a
          value is assigned at INSERT but only visible at COMMIT, and transactions can commit out of order).
          Supported projection model is replay-from-scratch per subject; no commit-timestamp machinery.
        children:
          - title: "Migration: add monotonic seq to kura.records"
            ref: seq-migration
            desc: >-
              Forward-only migration 0007_record_sequence.sql adding a non-null bigint seq column to
              kura.records, backed by one shared Postgres sequence (DEFAULT nextval), assigned on INSERT.
              Keep created_at. No dedicated index is required for per-subject ordering (that query is served
              by the edges index plus a join), but confirm during implementation. Mirror the patterns in
              0001_app_schema.sql; do not edit existing migrations.
            criteria:
              - "0007 adds a non-null bigint seq to kura.records backed by a shared sequence, assigned on INSERT"
              - "created_at is retained; migration applies cleanly on startup and is recorded in schema_migrations"
          - title: "Expose record seq in the data layer (MemStore, Postgres, Fake parity)"
            ref: seq-data
            blockedBy: [seq-migration]
            desc: >-
              Surface seq on record reads in the RecordStore interface; MemStore assigns a monotonic seq
              matching the Postgres contract, and the Fake enforces the same. Strict TDD: write failing
              tests first for monotonic assignment and ordering, verify they fail, then implement across
              MemStore and PostgresStore with integration tests against the shared test container.
            criteria:
              - "Failing tests written and confirmed red before implementation"
              - "Records carry a monotonic seq; MemStore and PostgresStore assign it consistently"
              - "The Fake enforces the same seq contract as the production store; tests pass"
          - title: "Docs: record sequence semantics"
            ref: seq-docs
            blockedBy: [seq-data]
            desc: >-
              Document the sequence in concepts/database: per-subject replay ordering, that created_at is
              not the order key, and the obligation that seq is NOT a safe global progress cursor (assigned
              at INSERT, visible at COMMIT; commits can reorder). State the recommended replay-per-subject
              projection model.
            criteria:
              - "The database concept doc explains seq ordering and the 'not a global progress cursor' caveat"

      - title: "Relationship persistence: typed edges between records"
        ref: rel-root
        labels: [relationships, substrate]
        desc: >-
          Persist manifest-declared relationships as typed edges between records, supporting both one and
          many cardinality, with FK referential integrity, cardinality validation at the gate, and indexes
          for "edges pointing at target X" and "edges from source X". Relationships are supplied at record
          creation; standalone post-creation edge mutation is deferred with the (not-yet-existent) update
          path. Reproduced from project/2026-06-24-relationships.md (the canonical rationale), with the
          edges migration renumbered to 0008 because the record sequence took 0007, and the Postgres edge
          work now blocked by the sequence so ordered queries can join kura.records.seq. Kura stays
          domain-agnostic — nothing here mentions CRM, party, or subject.
        children:
          - title: "Migration: kura.record_edges table"
            ref: rel-migration
            desc: >-
              New forward-only migration 0008_record_edges.sql creating kura.record_edges with
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
              Define EdgeInput and Edge types and extend the data layer: RecordInput (internal/data/write.go)
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
            blockedBy: [rel-iface, rel-migration, seq-data]
            desc: >-
              Implement InsertEdges and EdgesByTarget/EdgesBySource on PostgresStore (internal/data/postgres.go)
              using the existing withTenantTx pattern. FK violations (target record absent) surface as typed
              errors. Integration tests run against the shared test Postgres container. Ordering for
              "events for subject X" is by the source record's seq via a join to kura.records — this leaf also
              delivers the append-only doc's "F index", which is why it is blocked by the record sequence.
            criteria:
              - "Edges insert inside a tenant-scoped transaction; RLS isolates by tenant"
              - "An edge to a non-existent record is rejected via the FK as a typed error"
              - "EdgesByTarget returns the target's edges, ordered by the source record sequence via a join to kura.records"
              - "Integration tests pass against the test Postgres container"
          - title: "Gate: accept and validate relationships at ingest"
            ref: rel-gate
            blockedBy: [rel-mem, rel-pg]
            desc: >-
              Extend IngestRequest (internal/gate/ingest.go) to carry relationship values, and validate each at
              ingest: the relationship is declared on the entity, the target record exists and is of the declared
              target entity, and cardinality holds (one → at most one target; many → multiple). Authorize as part of
              ActionCreate on the source entity; persist edges in the same path as the record; audit. Manifest-level
              target-entity validation already exists (internal/manifest/validate.go) — this is instance-level.
              Strict TDD.
            criteria:
              - "Failing tests written and confirmed red before implementation"
              - "An undeclared relationship is rejected with a matchable error"
              - "A target that does not exist, or is of the wrong entity, is rejected with a matchable error"
              - "A second target on a one relationship is rejected; a many relationship accepts multiple"
              - "Edges are persisted with the record and the create action is authorized; tests pass"
          - title: "CLI/MCP surface: relationships on create + list-edges"
            ref: rel-cli
            blockedBy: [rel-gate]
            desc: >-
              Accept relationships in the create/ingest CLI input, and add a read verb to list a record's edges.
              Register both through internal/ops (cmd/kura/registry.go) so they appear in agent-context and MCP and
              satisfy the agent-context drift test; mirror the existing show verb (cmd/kura/data.go). Standalone
              post-creation add/remove/replace edge verbs are DEFERRED with the update path (no mutation path exists
              yet — see the append-only deferral cluster).
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
              (post-creation mutation deferred), and that endpoint ids are plaintext/indexable. Include both a one
              and a many example.
            criteria:
              - "schema-manifest and database concept docs describe edge persistence and cardinality validation"
              - "Examples include both a one and a many relationship"

      - title: "Append-only entities: insert-only enforcement and policy"
        ref: ao-root
        labels: [append-only, substrate]
        desc: >-
          Append-only doc decisions A, B, and D: let a manifest designate an entity insert-only, enforced
          mechanically at the DB layer and reflected in the Cedar policy. Deterministic ordering (Item F) is
          the record-sequence subtree above. The app-layer belt (Item C) and the redaction bypass (Item E,
          GUC vs. separate role) are DEFERRED — Kura has no mutation path today, so they would be untestable
          dead code; they ride with the first update/delete/redaction path and are documented in prose, not
          tracked as tasks here. Kura stays domain-agnostic — a reviewer should read this as "Kura now
          supports append-only entities", full stop.
        children:
          - title: "Manifest: append_only entity property + parsing"
            ref: ao-manifest
            desc: >-
              Add an optional boolean append_only on the manifest Entity (internal/manifest/manifest.go),
              following the existing optional-scalar convention (omitempty). When true, records of that entity
              are insert-only. Append-only entities may declare relationships and may be the target of others'
              relationships (events are referenced). Strict TDD: failing parse/round-trip tests first.
            criteria:
              - "Failing tests written and confirmed red before implementation"
              - "An entity can declare append_only and it round-trips through manifest load"
              - "Append-only entities may declare relationships and may be the target of others' relationships"
          - title: "Validation + Cedar IR: forbid update/delete grants on append-only entities"
            ref: ao-validate
            blockedBy: [ao-manifest]
            desc: >-
              The validator rejects any policy granting update or delete on an append-only entity with a
              matchable message (e.g. append-only entity "X" cannot grant action "update"); DefaultPolicy never
              emits update/delete for such entities; create stays the only write action. This is
              validation-rejection, not type-level unrepresentability — which entities are append-only is
              runtime manifest data, so any type scheme bottoms out in a runtime lookup anyway. Touches
              internal/manifest/validate.go and internal/cedar (ir.go / DefaultPolicy). Strict TDD.
            criteria:
              - "Failing tests written and confirmed red before implementation"
              - "A policy granting update/delete on an append-only entity is rejected with a matchable error"
              - "DefaultPolicy never emits update/delete grants for an append-only entity; create remains available"
          - title: "Policy viewer: render update/delete as N/A for append-only entities"
            ref: ao-viewer
            blockedBy: [ao-validate]
            desc: >-
              The policy/grant viewer presents update and delete as structurally unavailable (N/A) for
              append-only entities, not as empty grantable-but-ungranted cells, so the immutability is legible.
              Mirror the existing grant presentation so the structured view stays the authoritative picture.
            criteria:
              - "The viewer shows update/delete as N/A (structurally unavailable) for append-only entities"
          - title: "Provision a migrator/owner DB role separate from kura_api"
            ref: ao-migrator-role
            desc: >-
              No elevated credential exists today — migrations run as kura_api (internal/db/migrate.go,
              deploy/terraform/database.tf). Provision a migrator/owner role (terraform + a startup connection)
              that owns DDL and the append-only objects, so kura_api cannot write the append-only set or own the
              trigger. This credential separation is what Item B's enforcement depends on: kura_api must not be
              able to declare an empty set and self-bypass. Mirror the object-storage credential-domain-separation
              pattern (immutability administered from a credential domain separate from the runtime writer).
              Cover with the static IaC policy tests and a connection test.
            criteria:
              - "A migrator/owner DB role distinct from kura_api is provisioned in terraform and covered by IaC policy tests"
              - "The app can open an elevated connection for startup reconciliation/DDL, separate from the kura_api runtime connection"
              - "kura_api retains only its existing privileges and cannot own or write the append-only set table"
          - title: "Migration: append_only_entities table + insert-only trigger"
            ref: ao-migration
            blockedBy: [ao-migrator-role]
            desc: >-
              Forward-only migration 0009 creating kura.append_only_entities (tenant-scoped, forced RLS) and a
              BEFORE UPDATE OR DELETE trigger on kura.records and kura.record_field_values that raises a clear,
              matchable error when the row's entity is in the set. The trigger is SECURITY DEFINER owned by the
              migrator/owner role so kura_api needs no access to the set table; kura_api is granted no privileges
              on append_only_entities. Chosen over a second RLS policy for a loud, specific failure that composes
              with the existing forced tenant-isolation RLS. Mirror 0001/0002 patterns; do not edit existing
              migrations.
            criteria:
              - "kura.append_only_entities exists, tenant-scoped with forced RLS; kura_api has no access to it"
              - "A BEFORE UPDATE OR DELETE trigger on kura.records and kura.record_field_values raises a matchable error for append-only rows"
              - "The trigger is SECURITY DEFINER owned by the migrator/owner role; migration applies cleanly and is recorded in schema_migrations"
          - title: "Startup reconciliation of the append-only set from the manifest"
            ref: ao-reconcile
            blockedBy: [ao-migration, ao-manifest]
            desc: >-
              At startup, on the elevated/migrator credential with the parsed manifest in hand, derive the
              append-only entity set and reconcile kura.append_only_entities. Adding protection applies
              automatically (tighten silently). Removing append_only from an entity that already has stored rows
              is refused unless an explicit operator override is passed — so a security boundary can't be weakened
              as a silent side effect of a config edit; an append-only entity with no rows can be loosened freely
              (so reconciliation must check kura.records for existing rows). Every change to the set is audited.
              Strict TDD plus integration tests.
            criteria:
              - "Failing tests written and confirmed red before implementation"
              - "Append-only protection is added automatically from the manifest at startup"
              - "Removing append_only for an entity with existing rows is refused without an explicit override; loosening an empty entity succeeds"
              - "Every change to the append-only set is audited"
          - title: "Integration tests: append-only mutation rejected; others unaffected"
            ref: ao-enforcement-tests
            blockedBy: [ao-migration, ao-reconcile]
            desc: >-
              Integration tests against the shared test Postgres container proving UPDATE/DELETE on append-only
              rows (both kura.records and kura.record_field_values) raise the matchable trigger error even via
              direct kura_api access, and that non-append-only entities remain fully mutable. This confirms the DB
              trigger (Item B) is complete protection while the app-layer belt (Item C) is deferred.
            criteria:
              - "UPDATE/DELETE on an append-only row raises the trigger error, including via direct kura_api access"
              - "Non-append-only entities are unaffected by the trigger"
              - "Tests pass against the test Postgres container"
          - title: "Docs: append-only entities"
            ref: ao-docs
            blockedBy: [ao-viewer, ao-enforcement-tests]
            desc: >-
              Document append-only entities in the concept docs (schema-manifest, database, authorization): the
              append_only property; the trigger plus manifest-derived set and migrator/owner credential
              separation; startup reconciliation with block-silent-loosening; that Cedar forbids update/delete and
              the viewer shows N/A; the snapshot-writer Cedar pattern (grant update on a snapshot entity to exactly
              one service role — configuration, no Kura code); and a one-line note that the app-layer belt (C) and
              the redaction bypass (E) are deferred to the first mutation path.
            criteria:
              - "Docs describe the append_only property, the DB trigger + migrator/owner credential separation, and startup reconciliation"
              - "Docs note Cedar forbids update/delete (viewer N/A), the snapshot-writer Cedar pattern, and the deferred belt/redaction-bypass"
```

## Definition of done (this pass)

- One ledger root (`Phase 9 — Substrate capabilities`) holds the record-sequence, relationships, and append-only subtrees, imported from this doc.
- A monotonic `bigint` `seq` orders all records; its "not a global progress cursor" caveat is documented.
- Manifest `one`/`many` relationships are written at record creation as FK-backed edges, tenant-isolated, instance-validated, queryable by target/source, and orderable by `seq`.
- Designated entities are insert-only, enforced by a DB trigger backed by a manifest-derived set written by a migrator/owner role `kura_api` cannot impersonate; Cedar forbids update/delete (viewer N/A).
- App-layer belt (C) and redaction bypass (E) remain explicitly deferred to the first mutation path.
- The encryption / crypto-shredding subtree is appended and imported under the same root after its key-store/granularity decision.
