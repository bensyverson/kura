---
title: Database layer
weight: 7
---

Kura stores structured records and their metadata in **Postgres**. Large blobs go to
object storage; the database holds records, field values, and PII-span metadata. This
page records the shape of that layer and the security posture baked into it.

## A manifest-agnostic schema

The per-client [schema manifest](../schema-manifest/) is dynamic — every engagement
declares different entities — but Kura's migrations are static, forward-only SQL
files. The two are reconciled by storing records **generically**: the static schema
never changes when a client's manifest does.

| Table | Holds |
|---|---|
| `kura.records` | One row per record. `entity` is a free-text discriminator; `seq` is the record's order key (see [Record ordering](#record-ordering-a-shared-sequence)). |
| `kura.record_field_values` | One row per (record, field). A value is either a plain scalar or pgcrypto ciphertext — never both. |
| `kura.pii_spans` | Detected-PII metadata (category, byte offset, length, confidence) produced at ingestion. The source text never lives here. |
| `kura.record_edges` | One row per relationship edge between two records. Both endpoints are foreign keys into `kura.records` (see [Relationships](#relationships-typed-edges)). |
| `kura.users` | The authorized-user list — one row per email allowed to hold a principal in this deployment. |
| `kura.role_assignments` | Which roles each authorized user holds. A user with no rows here is on the list but has no access. |

Roles are stored as free text, matching the [Cedar policy IR's](../policy/)
role names — the same manifest-agnostic discipline: the static schema
never changes when a deployment edits its entities or its role set.

Migrations live in `internal/migrations/` as numbered `NNNN_name.sql` files, embedded
into the binary. An automatic runner (`internal/db.Migrate`) applies pending
migrations on server startup, each in its own transaction, and records the applied
version in `public.schema_migrations`. Migrations are never run by hand, and a
committed migration is never edited — a schema change is always a new migration.

## Record ordering: a shared sequence

Every row in `kura.records` carries a `seq` — a `bigint` drawn from one shared
Postgres sequence at insert (migration `0007`). It is the record **order key**:
deterministic and immune to clock skew, where `created_at` is not. `created_at` is
`now()`, which is transaction-start time, so it ties for rows written in the same
transaction and drifts with the system clock; `seq` does neither. The sequence spans
**all** records regardless of `entity` — ordering is a cheap (~8 bytes/row), generally
useful property, so it is not gated on any per-entity flag. The `RecordStore` surfaces
it as `Record.Seq`, populated identically by `MemStore` and `PostgresStore`.

`seq` orders events **within a subject**: "all of subject X's records, `ORDER BY seq`"
is correct and gap-free once those rows have committed. It is **not a safe global
progress cursor.** A `seq` value is assigned at `INSERT` but only becomes visible at
`COMMIT`, and transactions can commit out of order — so a reader that tracks the whole
stream with `seq > N` can step past an event that committed late and never see it
again. The supported projection model is therefore **replay-from-scratch per subject**
(rebuild a subject's view when it changes), not an incremental global cursor; any
cross-stream, gap-handling progress tracking is a consumer concern Kura builds none of.

## Relationships: typed edges

A manifest's declared relationships are persisted as **edges** in
`kura.record_edges` (migration `0008`) — one row per (source record,
relationship, target record). Both endpoints are real foreign keys into
`kura.records` (`ON DELETE CASCADE`), so an edge can **never dangle**: this is
the structural referential integrity the generic EAV field-values cannot
provide, and the reason edges live in their own table rather than as fields.

Edges are written in the **same tenant transaction** as the record that
declares them, so a record and its edges commit together or not at all — a
reference can never outlive a failed write. Relationships are supplied only at
**record creation**; standalone post-creation add/remove of an edge is a
mutation, and Kura has no update path yet, so it is deferred to that future
work.

A few deliberate choices:

- **No cardinality column.** Whether a relationship is `one` or `many` is a
  manifest property, validated at the gate on ingest (a `one` relationship
  rejects a second target). Storing it on the row would duplicate the source
  of truth and could drift from it.
- **Endpoint ids are plaintext, indexable uuids** — relationship references
  are never encrypted. Two indexes serve the two traversal directions:
  `(tenant_id, target_record_id, relationship)` for "edges pointing at X" and
  `(tenant_id, source_record_id)` for "edges from X".
- **Incoming edges order by `seq`.** "All edges pointing at subject X, in
  order" is served by querying `target_record_id` and ordering by the *source*
  record's [`seq`](#record-ordering-a-shared-sequence) via a join to
  `kura.records` — the deterministic, clock-skew-immune order. This is read
  through the gate's `Edges` method and the `GET /api/{entity}/{id}/edges`
  route; the `kura edges` verb requires an explicit `--direction out|in`.

Like every other application table, `kura.record_edges` is tenant-scoped and
RLS **enabled and forced** from creation, keyed on the `kura.tenant_id` GUC.

## Required extensions

Two Postgres extensions are required, and `internal/db.VerifyExtensions` reports the
state of both:

- **pgcrypto** — supplies the field-level encryption primitives (`pgp_sym_encrypt` /
  `pgp_sym_decrypt`). Migration `0001` creates it; it is verified available and
  installed.
- **pgaudit** — forensic query logging. pgaudit is intentionally **not** created by a
  migration: it only functions when it is present in the server's
  `shared_preload_libraries`, which is a deployment-time setting no migration can
  force. `VerifyExtensions` checks that it is *available*; if a target server cannot
  provide it, that is surfaced as a blocker rather than passing silently.

On the targeted DigitalOcean Managed Postgres major version both extensions are
available; pgaudit's activation is wired in the Phase 6 IaC baseline. Kura's own
integration tests run against a containerized Postgres (never DO's) that bundles
pgaudit and a TLS certificate — see `scripts/test-db.sh`.

## TLS is required

Every database connection uses TLS. `internal/db` refuses any DSN that would permit a
non-TLS connection — `sslmode=disable`, `allow`, and `prefer` all leave a plaintext
path open and are rejected; only `require`, `verify-ca`, and `verify-full` are
accepted. A misconfigured DSN fails at parse time, before a connection is opened.

## Per-component roles, minimum privilege

Migration `0003` creates three roles, one per component, each with the smallest
privilege set that lets it do its job:

| Role | For | Privileges |
|---|---|---|
| `kura_api` | The running API server | `SELECT/INSERT/UPDATE/DELETE` on the `kura` schema. No DDL, no role management, no other schema. |
| `kura_admin` | Schema provisioning | Full rights *within* the `kura` schema, including DDL. Not a superuser; still RLS-bound. |
| `kura_audit` | The tech owner's break-glass audit access | `SELECT` only. Can read, can change nothing. |

The roles are created `NOLOGIN` and **without passwords** — a password in a committed
migration would be a baked-in secret. The IaC layer runs `ALTER ROLE … LOGIN
PASSWORD` with a value from the secrets manager when it provisions a deployment. The
initial extension/role bootstrap is run by the platform's provisioning superuser
(for example, DigitalOcean's `doadmin`); `kura_admin` owns ongoing schema migrations.
No component role is a superuser and none has `BYPASSRLS`.

### Two connections, two credentials

The server uses **two** database credentials, never one. The runtime request path
connects as `kura_api` through `KURA_DATABASE_URL`. Schema migrations and append-only
reconciliation run at startup on a separate elevated connection, `kura_admin`, through
`KURA_ADMIN_DATABASE_URL` — both are required when a database is configured. This is a
deliberate credential-domain separation, mirroring the object-storage posture (admin
keys administer the backups bucket; runtime keys only append): `kura_admin` *owns*
schema evolution and the append-only objects — the `BEFORE UPDATE OR DELETE` trigger
and the `kura.append_only_entities` set — while `kura_api` has no access to that set
at all. So a compromised runtime credential cannot clear the append-only set and
unfreeze an entity the manifest marked insert-only; only the migrator/owner credential
can change what is protected. In production the two DSNs name two database users
(`…-api` and `…-migrator`); in local development, where the database has a single
superuser, both DSNs point at it.

## Row-level security

Every tenant-scoped table — all three — has row-level security **enabled and forced**.
Kura ships single-tenant, but RLS is far harder to retrofit than to start with, so it
is on from day one.

Each policy keys on the `kura.tenant_id` session GUC. `current_setting('kura.tenant_id',
true)` yields `NULL` when the GUC is unset, and `tenant_id = NULL` is never true — so a
connection that never sets the GUC sees **nothing**. The policies fail closed by
construction. `FORCE ROW LEVEL SECURITY` makes them bind the table owner too, so a
provisioning path that queries as the owner is not silently exempt.

## Encryption at rest

Field values are stored in `record_field_values` as either a plain scalar
(`value_text`) or pgcrypto ciphertext (`value_encrypted`) — a `CHECK` constraint
enforces exactly one. Two kinds of value are always encrypted:

- **High-sensitivity categories** — account numbers, government IDs, medical record
  numbers, biometrics, secrets — get field-level encryption.
- **Free-text columns** are encrypted at the column level by default, since free text
  is assumed to contain PII.

Encryption uses `internal/db.EncryptValue` / `DecryptValue`, wrapping pgcrypto under
an **app-managed key** supplied by the secrets manager. The key is never written to
the database, and a wrong key fails loudly rather than returning garbage.

## Reading records: the RecordStore

The Go layer that turns those generic EAV rows back into records is the `RecordStore`
interface in `internal/data`. It is the seam beneath the [gate](../gate/): the gate's
`Fetcher` and `ListFetcher` callbacks read through a `RecordStore`, which is
deliberately **enforcement-blind** — it returns raw field values and knows nothing
about authorization or masking. Those belong to the gate; a store that did them would
be a second, divergent enforcement point.

Two implementations satisfy the interface:

- **`MemStore`** — in-memory, for tests and adapters that have no database yet.
- **`PostgresStore`** — the production store over `kura.records` /
  `record_field_values`. It owns the two storage-layer concerns the schema demands:

  - **Tenant isolation.** Every read runs inside a transaction that sets the
    `kura.tenant_id` GUC (transaction-local, so it cannot leak across a pooled
    connection), so the row-level-security policies bind. A store scoped to one tenant
    cannot see another's rows.
  - **Field decryption.** A field stored as `value_encrypted` is decrypted with the
    app-managed key as part of the read query. The store hands back plaintext; the
    bytes at rest stay ciphertext.

  `PostgresStore` connects as the RLS-bound `kura_api` role — never a superuser — so
  the tenant-isolation guarantee is real and not an accident of which role ran the
  query.

The authorized-user list has the same shape of seam: `UserStore`, also in
`internal/data`, with an in-memory `MemUserStore` and a Postgres-backed
`PostgresUserStore` over `kura.users` / `kura.role_assignments`. It runs every
operation in a tenant-scoped transaction just as `PostgresStore` does — reads
read-only, the variadic role mutations as one read-write transaction, which is what
makes them atomic. `UserStore` also *is* the [gate's](../gate/) role resolver: the
same store both manages access and answers "what roles does this principal hold" when
the gate enforces it, so management and enforcement can never drift onto separate
copies.
