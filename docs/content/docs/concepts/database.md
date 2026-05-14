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
| `kura.records` | One row per record. `entity` is a free-text discriminator. |
| `kura.record_field_values` | One row per (record, field). A value is either a plain scalar or pgcrypto ciphertext — never both. |
| `kura.pii_spans` | Detected-PII metadata (category, byte offset, length, confidence) produced at ingestion. The source text never lives here. |

Migrations live in `internal/migrations/` as numbered `NNNN_name.sql` files, embedded
into the binary. An automatic runner (`internal/db.Migrate`) applies pending
migrations on server startup, each in its own transaction, and records the applied
version in `public.schema_migrations`. Migrations are never run by hand, and a
committed migration is never edited — a schema change is always a new migration.

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
