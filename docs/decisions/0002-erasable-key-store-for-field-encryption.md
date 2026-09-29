# ADR 0002 — Erasable key store and key granularity for field encryption

- **Status:** Accepted
- **Date:** 2026-06-24
- **Approved by:** Ben Syverson

## Context

Kura's field-encryption design
(`project/2026-06-24-field-encryption-crypto-shredding.md`) settles
crypto-shredding as the primary erasure primitive (D1): erasure destroys
a key, not a row, leaving the ciphertext untouched. That is the only
erasure model that reaches the deny-delete immutable database backup
(`deploy/terraform/storage.tf`) and the only one compatible with
append-only entities. The design also settles envelope encryption (D3):
a master KEK wraps many fine-grained data keys (DEKs).

Two questions were left open and gated the whole encryption subtree:

1. **Key granularity at volume (D4).** Per-field-value DEKs are the lean
   choice — domain-agnostic (records and fields are Kura concepts;
   "subject" is not) and a 1:1 map onto Kura's existing per-value
   encryption unit, `kura.record_field_values`
   (`internal/migrations/0001_app_schema.sql`). They also avoid
   over-erasure: shred only the PII field-values, preserving a record's
   id, timestamps, and non-PII structure. The open risk was operational:
   a per-value key implies a very large key count, with corresponding
   store size, unwrap cost, and rotation overhead.

2. **The erasable key-store mechanism.** Crypto-shredding requires
   destroying key material that the immutable backup never captured. The
   standard envelope pattern stores the wrapped DEK next to the
   ciphertext — i.e. in Postgres — which the immutable `pg_dump` captures,
   making destruction impossible. The shreddable key material must
   therefore live in a separate **mutable, erasable** store, outside the
   immutable backup regime, with its own durable-but-erasable backup.

The current crypto is a single global key via pgcrypto
(`internal/db/crypto.go`), read from the environment at
`cmd/kura/serve.go`; there is no key hierarchy. The secrets manager
(`internal/secrets/secrets.go`, Doppler backend) is the natural KEK home
but cannot hold millions of DEKs.

## Decision

### 1. Granularity: per-field-value DEKs

One DEK per `kura.record_field_values` row, keyed by the row's existing
`(record_id, field_name)` identity. This is **validated**, not merely
asserted: `scripts/dek_sizing.py` models the key store from first
principles (Postgres heap tuple + PK btree, AES-KW..GCM wrap, ×1.35
bloat). At the target volume of tens to hundreds of millions of
encrypted field-values the store is **2–24 GB**, trivial for one modest
managed Postgres instance; even a 500M stress case is ~118 GB on a
single instance. Per-read overhead is ~2 µs unwrap plus one indexed
point-lookup, collapsing to a map hit under an in-process LRU DEK cache.
No coarser fallback is needed.

### 2. Key store: a dedicated, separate Postgres instance

The wrapped DEKs live in a **physically separate** Postgres instance
from `kura.records` et al. The KEK stays in the secrets manager
(Doppler) and wraps the DEKs; the separate instance holds the wrapped
DEKs and nothing immutable. Crypto-shredding is a `DELETE` of the
wrapped-DEK row. The instance is excluded from the immutable backup
regime **structurally** — it is not in the cluster the immutable
`pg_dump` targets — and carries its own **erasable** backup: versioned
object storage *without* the deny-delete role, on a bounded retention,
so a shredded DEK genuinely disappears everywhere once retention passes.
The read path fronts the store with an LRU DEK cache.

### 3. Rotation: KEK-only

KEK rotation re-wraps the DEKs in place — unwrap with the old KEK,
re-wrap with the new — leaving the DEK value, and therefore every
ciphertext in the live database *and* in immutable backups, decryptable.
Rotation stays entirely within the mutable layer. Periodic **DEK**
rotation is deliberately excluded (see Alternatives).

## Alternatives considered

### Coarser key granularity (per-record or per-subject DEKs)

Fewer keys, smaller store. Rejected: per-record over-erases (shredding
one PII field destroys the whole record's values, including non-PII
structure the event-sourcing model must keep), and per-subject entangles
Kura with a domain concept it does not own — "subject" is not a Kura
primitive. The sizing analysis removes the only motivation for trading
these away: per-value is already cheap at target volume.

### Key store in the same Postgres instance (separate schema)

Keep the DEK table in the existing cluster, in its own schema, and
exclude it from the immutable backup with `pg_dump --exclude-schema`.
Cheaper — no second instance. Rejected: the exclusion boundary becomes a
**policy flag** on every backup, forever. One forgotten flag, or one
ad-hoc full `pg_dump` by an operator, immortalizes the wrapped DEKs in
the deny-delete bucket, and shredding silently stops reaching backups —
the row vanishes from the live DB while its backup copy survives. For a
primitive whose entire purpose is to be destroyable, the boundary must
be structural, not remembered.

### DEKs held directly in the secrets manager (Doppler)

Doppler is the natural KEK home and already wired
(`internal/secrets/secrets.go`). Rejected as the DEK store: a secrets
manager is built for a bounded set of high-value secrets, not tens of
millions of per-value keys — it has neither the storage model nor the
bulk-delete semantics shredding needs.

### Cloud KMS holding the DEKs (KMS-per-DEK)

Let a managed KMS store and unwrap every DEK. Rejected: per-DEK KMS
operations are rate-limited and priced for KEK-scale use, not
millions-of-keys-scale, and add a cloud dependency outside the current
DigitalOcean footprint. Using a KMS for the **KEK only** (HSM-grade KEK
protection and rotation, DEKs still in the dedicated store) remains a
clean future option and is not foreclosed by this decision.

### Storing the wrapped DEK next to the ciphertext

The textbook envelope layout. Rejected because it *is* the original
problem: the wrapped DEK lands in Postgres, the immutable `pg_dump`
captures it, and shredding cannot reach the backup copy.

### Periodic DEK rotation

Re-encrypt each value under a fresh DEK and discard the old one.
Rejected: it collides with the immutable-backup invariant. A backup
froze the ciphertext under DEK-v1; rotating to DEK-v2 and destroying
DEK-v1 leaves the live value decryptable but the backup's copy
permanently unreadable. Avoiding that forces retaining every historical
DEK forever, which defeats the clean shredding story and bloats the
store. DEK destruction and crypto-shredding are the same operation
pointed at opposite intents — shredding *wants* the backup ciphertext
gone; rotation does not — so per-value DEK rotation is unsafe by
construction, and KEK-only rotation is the principled choice rather than
merely the cheap one.

## Consequences

**Positive**

- Per-field-value shredding with no over-erasure, validated viable at
  target volume by a reusable tool (`scripts/dek_sizing.py`) rather than
  by assertion.
- The shreddability boundary is structural: the immutable backup regime
  *cannot* capture the keys, independent of operator discipline.
- Rotation never touches ciphertext, so it never threatens the
  decryptability of live data or immutable backups.
- Reuses the existing per-value encryption unit and the existing secrets
  manager as the KEK home; no domain concepts enter the design.

**Negative**

- One additional managed Postgres instance to operate, with its own
  (erasable) backup pipeline and retention policy — a new operational
  surface and a second connection in the runtime's configuration.
- The read path gains a dependency on the key store (mitigated by the
  LRU DEK cache and batch unwrap), and a cold read pays one extra
  point-lookup.
- KEK rotation re-wraps every DEK; at 100M keys that is a ~1.4-hour
  online batched job bound by key-store write throughput. Infrequent,
  but real, and must be implemented as a resumable background job.

## Residual — external sign-off (does not block code)

The blind-index search path (D5) leaves keyed-HMAC tokens in the
immutable backup; those are not reachable by crypto-shredding and rely
on the irreversibility of the HMAC for erasure adequacy. This needs
DPO/counsel sign-off. It is tracked as an external decision and does
**not** gate the encryption implementation.

## Scope of this ADR

This decision covers key granularity, the erasable key-store mechanism,
and rotation policy for field-level encryption. It does not specify the
wire format of wrapped DEKs, the migration sequence (encryption
migrations are forward-only, numbered 0010+), the blind-index
normalization rules (D6, still open), or the detector posture (already
resolved in-tenant). Those are settled in the implementation plan and
its task tree, not here.
