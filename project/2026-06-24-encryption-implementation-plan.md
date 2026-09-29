# Field-level encryption & crypto-shredding — implementation plan

- **Status:** Ready to import
- **Date:** 2026-06-24
- **Decision:** `docs/decisions/0002-erasable-key-store-for-field-encryption.md`
- **Design:** `project/2026-06-24-field-encryption-crypto-shredding.md`
- **Parent task:** `pxV0E` (Phase 9 — Substrate capabilities)

This is the fourth Phase-9 substrate capability. ADR 0002 resolved the three blockers that gated it: per-field-value DEKs (validated viable at target volume by `scripts/dek_sizing.py`), a dedicated separate-instance erasable key store, and KEK-only rotation. With those settled the implementation has a clean spine, captured as the task tree below.

## The load-bearing shift: in-DB crypto → app-layer envelope

Today encryption happens *inside* Postgres. `internal/data/postgres.go` inlines `pgp_sym_encrypt($value, $key)` on write (line ~128) and `pgp_sym_decrypt(value_encrypted, $key)` on read (line ~204), with a single global key passed as a SQL parameter (`KURA_RECORD_ENCRYPTION_KEY`, `internal/db/crypto.go`). That model cannot survive per-field-value DEKs held in a *separate* instance: the main DB query has no access to the DEK. So the core of this work is moving crypto to the **application layer** — Go `crypto/aes` + GCM, with the DEK fetched from the key store, unwrapped with the KEK, and the value encrypted/decrypted in process. Ciphertext still lands in `record_field_values.value_encrypted` (bytea, unchanged); only the producer of those bytes moves from Postgres to Go.

## Scope and deferrals

**In scope:** envelope primitives, the erasable key store (schema, interface, Postgres impl, Fake, runtime wiring, DEK cache), encrypt-PII-by-default on write, app-layer decrypt on read, the crypto-shred erasure operation through `internal/ops`, KEK rotation, the key-store's own erasable backup infrastructure, and docs.

**Deferred (documented in prose, not tasked here):**
- **Blind-index search (D5/D6).** The mechanism is settled but the per-category normalization rules (D6 — email casing, phone formatting, name folding) are still an open decision needing their own ADR. Encrypt-by-default is independently shippable because there is no server-side filtering on `value_text` today, so blind indexes are not on this critical path. They ride with the D6 decision.
- **The app-layer encryption belt and redaction-of-incidental-spans** remain deferred with the substrate plan's reasoning: Kura has no update/redaction path today, so they would be untestable dead code.

**Domain-agnostic constraint:** nothing in any resulting diff or task may mention CRM, party, customer, subject, or lifecycle. Erasure is expressed over Kura primitives — "shred the field-value keys for a given set of records" — never "erase a subject." A reviewer should read every change as a generic store capability.

## Import

```
job import project/2026-06-24-encryption-implementation-plan.md --dry-run --parent pxV0E
job import project/2026-06-24-encryption-implementation-plan.md --parent pxV0E
```

## Task tree (`job schema` format)

```yaml
tasks:
  - title: "Field-level encryption and crypto-shredding"
    ref: enc-root
    labels: [encryption, substrate, phase-9]
    desc: >-
      The fourth Phase-9 substrate capability: encrypt PII field content by default and make erasure a crypto-shred — destroy a key, never mutate a row — so it reaches the deny-delete immutable backup and stays compatible with append-only entities. Architecture is fixed by docs/decisions/0002-erasable-key-store-for-field-encryption.md: per-field-value DEKs wrapped by a KEK in the secrets manager, the wrapped DEKs held in a physically separate, erasable Postgres instance excluded from the immutable backup regime, and KEK-only rotation. See project/2026-06-24-field-encryption-crypto-shredding.md for the full design (D1–D7).

      The load-bearing change is moving crypto from in-database (pgcrypto pgp_sym_encrypt/decrypt inlined in internal/data/postgres.go) to the application layer (Go AES-256-GCM), because a DEK living in a separate instance is unreachable from a main-DB SQL expression. Ciphertext still lands in kura.record_field_values.value_encrypted unchanged.

      Blind-index search (D5/D6) and the redaction/update path are deferred — see the plan doc. Strict red/green TDD throughout: failing tests first, confirmed red, then implement. New interfaces get Fakes; the new erase verb flows through internal/ops. Kura stays domain-agnostic — no diff or task may mention CRM, party, customer, subject, or lifecycle; erasure operates over records and field-values, not subjects.
    children:

      # ---- A. Envelope crypto primitives (app-layer) ----
      - title: "App-layer envelope crypto: DEK generation, AES-256-GCM, KEK wrap/unwrap"
        ref: env-crypto
        labels: [encryption]
        desc: >-
          Build the pure crypto layer that replaces pgcrypto. Provide: generate a random 256-bit DEK; encrypt/decrypt a value with a DEK via AES-256-GCM (random nonce, nonce prepended to ciphertext); wrap/unwrap a DEK under a KEK (AES key-wrap or AES-GCM over the raw DEK). These are pure functions taking key material as arguments — no database handle, no environment access — so they are exhaustively unit-testable and auditable. This supersedes internal/db/crypto.go's EncryptValue/DecryptValue, which run pgp_sym_* through *sql.DB; that in-DB path is removed once the write/read paths below adopt these functions.

          Why app-layer: ADR 0002 puts DEKs in a separate instance, so decryption cannot be a SQL expression in the main DB. Crypto must run in Go with the DEK in hand.
        criteria:
          - "Failing tests written and confirmed red before implementation"
          - "GenerateDEK returns a 256-bit key from crypto/rand; round-trip encrypt→decrypt recovers the plaintext"
          - "Wrap→unwrap recovers the exact DEK bytes; a wrong KEK fails authentication rather than returning garbage"
          - "GCM authentication failure (tampered ciphertext or nonce) surfaces as an error, never silent corruption"
          - "No function in this layer takes a *sql.DB or reads the environment"

      - title: "Source the KEK from the secrets manager"
        ref: env-kek
        blockedBy: [env-crypto]
        labels: [encryption]
        desc: >-
          Wire the master KEK to the existing secrets manager rather than a bare env var. internal/secrets/secrets.go already exposes Manager.EncryptionKey(ctx, actor) returning the FIELD_ENCRYPTION_KEY secret (and Manager.Get for any named secret). Use that as the KEK source for wrap/unwrap, replacing the direct os.Getenv("KURA_RECORD_ENCRYPTION_KEY") read in cmd/kura/serve.go. Keep KEK material out of the data layer's constructor signature where practical — pass a wrap/unwrap capability, not the raw key, so the KEK's blast radius stays small.
        criteria:
          - "The KEK is fetched via the secrets Manager, not read directly from the environment in the data layer"
          - "KURA_RECORD_ENCRYPTION_KEY's former direct read in serve.go is removed or routed through secrets"
          - "Tests cover a missing/garbage KEK producing a clear startup error"

      # ---- B. Erasable key store ----
      - title: "Key-store schema and its own migration lineage"
        ref: ks-schema
        labels: [encryption, keystore, migration]
        desc: >-
          Define the wrapped-DEK table for the separate key-store instance: keyed by (tenant_id, record_id, field_name) — mirroring kura.record_field_values' identity — holding wrapped_dek bytea and kek_version int. The key store is a DIFFERENT Postgres instance, and the current migrator (internal/migrations + internal/db/migrate.go) is single-DSN with a contiguous 1-based embedded set (highest is 0009). So the key store needs its OWN migration lineage: a separate embedded directory (e.g. internal/migrations/keystore/0001_keystore_schema.sql) and a second Migrate invocation targeting the key-store DSN. This task adds the embedded set, the schema migration, and the migrator plumbing to run a named lineage against a given DSN.

          Note: the main DB needs no schema change for the core crypto-shredding path — value_encrypted (bytea) already exists and the ciphertext format change is app-layer. The 0010+ main-DB numbering reserved by the brief applies only when a main-DB change (e.g. a future blind-index column) lands.
        criteria:
          - "A keystore migration lineage exists, separate from the main 0001–0009 set, applied against the key-store DSN"
          - "The wrapped-DEK table is keyed by (tenant_id, record_id, field_name) with wrapped_dek bytea and kek_version"
          - "Forced RLS or equivalent tenant scoping is applied consistent with the main schema's tenant isolation"
          - "The migrator records applied key-store migrations in that instance's schema_migrations"

      - title: "KeyStore interface and Fake"
        ref: ks-iface
        labels: [encryption, keystore]
        desc: >-
          Define the KeyStore interface the data layer depends on: store a wrapped DEK for (record_id, field_name); fetch+return the wrapped DEK for a value; shred (delete) all wrapped DEKs for a given set of record ids. Provide an in-memory Fake implementing the identical contract, used by unit tests across the write/read/erase paths. The interface is the seam that keeps the data layer ignorant of whether keys live in Postgres, a cache, or a test double — per the adapter-over-core architecture, the policy (what gets shredded) lives in internal, the storage is swappable.
        criteria:
          - "KeyStore interface defines store, fetch, and shred-by-records operations with explicit tenant scoping"
          - "A Fake implements the full contract and is the basis for unit tests of dependent paths"
          - "The shred operation is expressed over a set of record ids (domain-agnostic), not over any subject concept"

      - title: "Postgres KeyStore implementation with integration tests"
        ref: ks-postgres
        blockedBy: [ks-schema, ks-iface]
        labels: [encryption, keystore]
        desc: >-
          Implement KeyStore against the key-store Postgres instance. Strict TDD: write failing integration tests first for store, fetch, fetch-miss (a shredded/absent key), and shred-by-records, then implement. The integration harness mirrors internal/data/testdb_test.go's newDataTestEnv (fresh per-test database from KURA_TEST_DATABASE_URL); for the key store, provision a second fresh database on the same test cluster — physical separation is a production/terraform property, not a test property, so a second database in the test cluster is the correct test analogue. Verify tenant isolation: one tenant cannot fetch or shred another's DEKs.
        criteria:
          - "Failing integration tests written and confirmed red before implementation"
          - "Store→fetch round-trips the wrapped DEK; fetch after shred reports a clean miss, not an error"
          - "Shred-by-records deletes exactly the targeted records' DEKs and no others"
          - "Cross-tenant fetch and shred are denied by the store's tenant scoping"

      - title: "DEK cache (LRU) in front of the key store"
        ref: dek-cache
        blockedBy: [ks-iface]
        labels: [encryption, keystore, performance]
        desc: >-
          Add an in-process LRU cache of unwrapped DEKs so hot reads avoid both a key-store round-trip and an unwrap. The cache wraps any KeyStore (decorator over the interface). Critically, the cache must honor shredding: a shred invalidates the cached DEK for the affected records, so an erased value cannot be decrypted from a stale cache entry — this is a correctness requirement, not just performance. Bound the cache by entry count; on miss, fetch+unwrap and populate.
        criteria:
          - "Failing tests written and confirmed red before implementation"
          - "A cache hit returns the unwrapped DEK without a key-store call"
          - "Shredding a record's keys invalidates any cached DEKs for those records; a subsequent decrypt cannot succeed"
          - "The cache is bounded and evicts least-recently-used entries"

      - title: "Runtime wiring: second DB connection and key-store config"
        ref: ks-wiring
        blockedBy: [ks-postgres]
        labels: [encryption, keystore, config]
        desc: >-
          Wire the key store into the server. Add the key-store DSN configuration (e.g. KURA_KEYSTORE_DATABASE_URL for the runtime role and a KURA_KEYSTORE_ADMIN_DATABASE_URL for its migrations), open the second connection pool in cmd/kura/serve.go, run the key-store migration lineage at startup, and construct the cached Postgres KeyStore. NewPostgresStore's signature changes here: the encryptionKey string parameter is replaced by the KeyStore (cached) plus the KEK wrap/unwrap capability from env-kek. Update all constructor call sites.
        criteria:
          - "The server opens a separate key-store pool from its own DSN and runs the key-store migrations at startup"
          - "NewPostgresStore takes a KeyStore + KEK capability instead of a global encryption key; all call sites updated"
          - "Missing key-store configuration fails fast at startup with a clear message"

      # ---- C. Encrypt-by-default write path ----
      - title: "Envelope write path: per-value DEK, key-store-first persistence"
        ref: wp-replace
        blockedBy: [env-crypto, ks-iface]
        labels: [encryption, data]
        desc: >-
          Replace the in-DB write encryption with the envelope flow. Today PostgresStore.Insert (internal/data/write.go) sets value_encrypted via pgp_sym_encrypt($value,$key) in SQL. Change it to: for each encrypted field, generate a DEK, encrypt the value in Go (env-crypto), wrap the DEK, persist the wrapped DEK to the key store, then write the ciphertext bytea to record_field_values. Ordering matters and is a deliberate design choice: persist the wrapped DEK to the key store FIRST, then the ciphertext. The key store is a separate instance, so there is no cross-instance transaction; key-store-first means a mid-failure leaves at worst an orphan DEK (harmless, unused key material reclaimable by a later sweep), never undecryptable ciphertext. Strict TDD using the Fake KeyStore; integration coverage arrives via ks-postgres.
        criteria:
          - "Failing tests written and confirmed red before implementation"
          - "Insert generates a per-value DEK, encrypts in Go, and stores the wrapped DEK before writing ciphertext"
          - "No pgp_sym_encrypt remains on the write path; value_encrypted holds app-layer AES-GCM ciphertext"
          - "A key-store write failure aborts the field write without leaving undecryptable ciphertext in the main DB"

      - title: "Encrypt PII content by default; plaintext only for structural types"
        ref: wp-default
        blockedBy: [wp-replace]
        labels: [encryption, data, policy]
        desc: >-
          Implement D2: PII content is encrypted by default, with plaintext reserved for non-content structural types only (boolean, integer, timestamp, seq). Today FieldInput.Encrypted (internal/data/write.go) is set by the caller; locate where the gate/ingestion path decides it and flip the default so content fields encrypt unless their type is structural. This is safe to do now precisely because there is no server-side filtering or sorting on value_text anywhere (verified during planning), so encrypt-by-default costs nothing on the read path today. Document the opt-out list as the structural types, not as a sensitivity judgment — shreddability is decoupled from visibility/sensitivity (D2).
        criteria:
          - "Failing tests written and confirmed red before implementation"
          - "Content fields encrypt by default; boolean/integer/timestamp/seq remain plaintext in value_text"
          - "The plaintext opt-out is driven by structural type, not by a sensitivity/visibility classification"

      # ---- D. Decrypt-at-read path ----
      - title: "Envelope read path: fetch+unwrap DEK, decrypt in Go"
        ref: rp-replace
        blockedBy: [env-crypto, dek-cache, wp-replace]
        labels: [encryption, data]
        desc: >-
          Replace the in-DB decrypt projection. Today fieldsOf (internal/data/postgres.go ~line 204) decrypts via CASE WHEN ... pgp_sym_decrypt(value_encrypted,$key). Change the read to select value_encrypted as raw bytea and decrypt in Go: fetch the DEK via the cached KeyStore, unwrap with the KEK, AES-GCM decrypt. Batch the DEK fetches for a record's fields to avoid N round-trips. Plaintext (structural) fields continue to come straight from value_text.
        criteria:
          - "Failing tests written and confirmed red before implementation"
          - "Reads return decrypted content via app-layer crypto; no pgp_sym_decrypt remains on the read path"
          - "DEK fetches for a record's fields are batched rather than issued one-per-field"

      - title: "Erased-value semantics on read (shredded DEK)"
        ref: rp-tombstone
        blockedBy: [rp-replace]
        labels: [encryption, data]
        desc: >-
          Define what a read returns when the DEK has been shredded (the erasure happy path) or is otherwise absent. A shredded DEK means the ciphertext is permanently undecryptable BY DESIGN — that is the feature, not an error. Reads of such values must return a well-defined erased sentinel/tombstone (e.g. a typed "erased" marker the API renders consistently), so that listing or fetching a record containing erased fields stays a normal, non-failing operation. Distinguish this from a genuine decrypt failure (tampering / wrong KEK), which must still surface as an error.
        criteria:
          - "Failing tests written and confirmed red before implementation"
          - "A read of a value whose DEK was shredded returns an erased sentinel, not an error, and never the ciphertext"
          - "A genuine GCM authentication failure remains a hard error, distinct from the erased sentinel"

      # ---- Cleanup: retire pgcrypto ----
      - title: "Drop the pgcrypto extension"
        ref: drop-pgcrypto
        blockedBy: [wp-replace, rp-replace]
        labels: [encryption, migration, cleanup]
        desc: >-
          Once the write and read paths use app-layer AES-GCM, nothing uses pgcrypto: its only consumers were pgp_sym_encrypt/pgp_sym_decrypt (now removed) and gen_random_uuid(), which has been a core Postgres built-in since PG13 — Kura runs PG18 (postgres:18 in tests; var.postgres_version in terraform), so the UUID PK defaults in migrations 0001/0004/0008 bind to the core function and do not need the extension. Add a forward-only migration 0010_drop_pgcrypto.sql running DROP EXTENSION IF EXISTS pgcrypto. This is the first main-DB migration in the encryption work (the key store keeps its own lineage). Migrations are forward-only, so do not edit 0001; instead correct the now-stale "pgcrypto supplies field-level encryption" framing in the docs and in the new migration's header comment. Verify the drop succeeds with no dependency error and that gen_random_uuid() still works afterward.
        criteria:
          - "0010_drop_pgcrypto.sql drops the extension and applies cleanly on startup, recorded in schema_migrations"
          - "No object depends on pgcrypto at drop time; the migration does not error on dependencies"
          - "gen_random_uuid() still resolves (to the core built-in) and inserts succeed after the drop"
          - "Docs no longer describe pgcrypto as the field-encryption provider"

      # ---- E. Crypto-shred erasure ----
      - title: "Erase verb in internal/ops (shred field-value keys for a set of records)"
        ref: erase-op
        blockedBy: [ks-iface]
        labels: [encryption, ops, erasure]
        desc: >-
          Add the erasure operation to the ops registry so it is a first-class, agent-visible verb. internal/ops/ops.go holds the Registry/Operation model; cmd/kura/registry.go's buildRegistry registers operations; internal/ops/ops_test.go's TestContextProjectsRegisteredOperations enforces that every registered op projects faithfully into agent-context. Declare the erase operation here (name, summary, args — a set of record ids and the tenant) and ensure it satisfies the drift test. The verb is domain-agnostic: it shreds the field-value keys for the given records. It does NOT know about subjects, parties, or any domain entity — the caller maps its own concept of "who" to a record set.
        criteria:
          - "An erase operation is registered in the ops registry with explicit args (record ids, tenant)"
          - "TestContextProjectsRegisteredOperations passes with the new verb projected"
          - "The operation's name, summary, and args contain no domain language (no subject/party/customer/lifecycle)"

      - title: "Erasure implementation: shred keys, prove record and append-only untouched"
        ref: erase-impl
        blockedBy: [erase-op, ks-postgres, rp-tombstone]
        labels: [encryption, erasure]
        desc: >-
          Implement the erase handler as a KeyStore shred over the target records, plus cache invalidation. The defining property to prove by integration test: after erasure, reads of the affected fields can no longer be decrypted (they return the erased sentinel), while kura.records and kura.record_field_values rows are byte-for-byte untouched and the append-only trigger (migration 0009) fires no violation — because erasure never mutates the main DB. This is the concrete demonstration that crypto-shredding decouples erasure from append-only. Confirm the same holds for a value that was hot in the DEK cache before erasure.
        criteria:
          - "Failing integration tests written and confirmed red before implementation"
          - "After erase, the targeted fields read as the erased sentinel and cannot be decrypted"
          - "kura.records and record_field_values rows are unchanged by erasure; no append-only trigger violation occurs"
          - "A DEK cached before erasure does not allow post-erase decryption"

      - title: "Audit-log erasure events"
        ref: erase-audit
        blockedBy: [erase-impl]
        labels: [encryption, erasure, audit]
        desc: >-
          Erasure is a consequential, irreversible action and must be audited like other privileged operations. Record an audit event for each erase: the acting principal, the tenant, the set of records (and field count) shredded, and the timestamp — via the existing audit recorder used elsewhere (internal/audit, the same Recorder wired into secrets.Manager). The audit log itself records that an erasure happened; it must not capture the destroyed key material or the now-erased plaintext.
        criteria:
          - "Each erase emits an audit event with principal, tenant, and the records affected"
          - "The audit event contains no key material and no erased plaintext"
          - "A failed/partial erase is distinguishable in the audit trail from a completed one"

      # ---- F. KEK rotation ----
      - title: "KEK rotation: re-wrap DEKs in place"
        ref: kek-rotate
        blockedBy: [ks-postgres, env-kek, ks-wiring]
        labels: [encryption, keystore, rotation]
        desc: >-
          Implement KEK-only rotation (ADR 0002): unwrap each wrapped DEK with the old KEK, re-wrap with the new KEK, bump kek_version, and persist — leaving the DEK value, and therefore all ciphertext in both the live DB and immutable backups, fully decryptable. Rotation stays entirely in the mutable key-store layer and never touches ciphertext. The job must be resumable and batched (kek_version distinguishes done from pending rows), because at hundreds of millions of DEKs it is bound by key-store write throughput (~1.4h at 100M per the sizing analysis). Per-value DEK rotation is explicitly out of scope and must not be implemented — it would break the decryptability of immutable backups.
        criteria:
          - "Failing tests written and confirmed red before implementation"
          - "After rotation, every value still decrypts; ciphertext bytes are unchanged"
          - "Rotation is resumable: interrupting and re-running completes without double-wrapping or skipping rows"
          - "kek_version reflects the active KEK for rotated rows"

      # ---- G. Key-store infrastructure (erasable backup) ----
      - title: "Terraform: separate Postgres instance for the key store"
        ref: tf-instance
        labels: [encryption, infra, terraform]
        desc: >-
          Provision the key store as a physically separate managed Postgres instance in deploy/terraform, alongside the existing digitalocean_database_cluster "kura" (database.tf). Separate instance, separate database, separate runtime/migrator roles, and the firewall/VPC rules to match. The whole point of physical separation (ADR 0002) is that the immutable backup pipeline structurally cannot capture the keys — so this instance must NOT be a target of the main cluster's pg_dump→immutable-Spaces job.
        criteria:
          - "A separate managed Postgres cluster + database for the key store is defined in terraform"
          - "It has its own runtime and migrator roles and appropriate VPC/firewall scoping"
          - "It is not referenced by the immutable-backup job"

      - title: "Erasable backup for the key store"
        ref: tf-backup
        blockedBy: [tf-instance]
        labels: [encryption, infra, terraform, backup]
        desc: >-
          Give the key store its own durable-but-erasable backup, the counterpart to the main DB's immutable one. Add a Spaces bucket WITHOUT the deny-delete policy that storage.tf applies to the immutable backups bucket — versioned, but with a bounded lifecycle/retention so that a shredded DEK genuinely disappears from backups once retention passes (otherwise a shredded key resurrects from its own backup and erasure is incomplete). Use credentials that CAN delete, distinct from the append-only KURA_DO_SPACES keys. Add the key-store dump/restore job and verify the end-to-end property: a shredded DEK is unrecoverable after the retention window.
        criteria:
          - "A versioned, non-deny-delete backup target with bounded retention exists for the key store"
          - "Backup credentials permit deletion and are distinct from the immutable-backup append-only credentials"
          - "A test/verification shows a shredded DEK does not resurrect from the key-store backup after retention"

      # ---- H. Docs ----
      - title: "Document encryption and crypto-shredding"
        ref: enc-docs
        blockedBy: [erase-impl, kek-rotate]
        labels: [encryption, docs]
        desc: >-
          Update docs/content/docs to explain the capability for operators and integrators: the envelope model (KEK wraps per-field-value DEKs); the separate erasable key store and WHY it is excluded from the immutable backup regime; encrypt-PII-by-default and the structural-type plaintext opt-out; the erase operation's semantics (shred keys for a set of records; reads return an erased sentinel; the main DB and append-only invariant are untouched); KEK-only rotation and why per-value DEK rotation is deliberately excluded; and the configuration (key-store DSNs, KEK secret). Note the deferred blind-index search and its dependence on the D6 normalization decision. Keep it domain-agnostic.
        criteria:
          - "A concept doc covers the envelope model, the erasable key store, erase semantics, and KEK rotation"
          - "Operator configuration (key-store DSNs, KEK secret, erasable backup) is documented"
          - "Deferred blind-index search and the open D6 decision are noted; no domain language appears"
```
