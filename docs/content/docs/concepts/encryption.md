---
title: Field encryption & crypto-shredding
weight: 8
---

Kura encrypts field content **by default** and makes erasure a **crypto-shred** —
destroy a key, never a row. This is what lets a "forget these records" request reach
the [deny-delete immutable backup](../storage/) and stay compatible with append-only
entities: the row is never mutated, so there is nothing for the append-only trigger to
refuse, and no plaintext copy survives in a sealed backup once its key is gone.

The design is fixed by
[ADR 0002](https://github.com/bensyverson/kura/blob/main/docs/decisions/0002-erasable-key-store-for-field-encryption.md).
The load-bearing move is that crypto runs in the **application layer** (Go
AES-256-GCM), not in the database (the old pgcrypto path, dropped in migration
`0010`). A data key that lives in a physically separate instance is unreachable from a
SQL expression in the main database — so the encryption has to happen in Go, with the
key in hand.

## The envelope model

Two layers of the same primitive — **AES-256-GCM** — applied at different scopes
([`internal/crypto`](https://github.com/bensyverson/kura/tree/main/internal/crypto)):

- A **per-field-value data key (DEK)** seals one value. Every encrypted field value
  gets its own freshly generated 32-byte DEK; the DEK is never reused and the nonce is
  random, so identical plaintexts produce different ciphertext.
- The **master KEK** wraps the DEK. The wrapped DEK — not the DEK itself — is what
  Kura persists.

The ciphertext lands in `kura.record_field_values.value_encrypted` exactly as before;
the wrapped DEK lands in a **separate key store**, keyed 1:1 to the value it protects
by `(tenant_id, record_id, field_name)`. The KEK is a base64-encoded 32-byte key
(`openssl rand -base64 32`) sourced from the [secrets manager](../secrets/) under the
name `FIELD_ENCRYPTION_KEY` — it never appears in the data path and never in an image.

GCM is *authenticated* encryption, so a wrong key — a wrong DEK on a value or a wrong
KEK on a wrapped DEK — fails authentication (`ErrAuthentication`) rather than returning
plausible garbage. That property is what lets an *erased* read (the key is simply gone)
be told apart from a *tampered* read (the key is present but the bytes do not
authenticate); see [Erase semantics](#erase-semantics-the-crypto-shred).

The write path seals key-store-first: generate the DEK, encrypt the value, wrap the
DEK, **store the wrapped DEK, then** write the ciphertext — so an interrupted write can
never strand undecryptable ciphertext with no key. On read, `PostgresStore` fetches and
unwraps the value's DEK through an in-process LRU cache (default 4096 unwrapped DEKs)
and decrypts in Go; the bytes at rest stay ciphertext.

## Encrypt by default; the structural-type opt-out

Content is encrypted by default. A field's value is stored as plaintext `value_text`
**only** when its manifest type is *structural* — `integer`, `boolean`, or `timestamp`
— types that hold non-content values carrying no PII and that a deployment may want to
query, sort, or index on. Everything else — `string`, `text` — is encrypted.

The opt-out is purely the **type**, never a sensitivity or visibility judgment.
Shreddability is deliberately decoupled from sensitivity: a plain string and a
high-sensitivity string alike encrypt, because the question encryption answers is *"can
we erase this?"*, not *"who may read it?"* (that stays a [policy](../policy/) and
[masking](../pii/) concern). Defaulting to encrypt also **fails closed** — a field type
added to the manifest schema later encrypts until it is deliberately classified
structural.

This is a structural guarantee rather than a disciplinary one. Erasability no longer
depends on an author remembering to tag a field, or on a probabilistic
[detector](../pii/) catching every PII span: it is a property of how content is stored.
(The record ordering sequence `seq` is a system column, not a field value, so it is
plaintext by construction; [relationship edges](../database/#relationships-typed-edges)
are not field values either — they live as indexable `uuid` columns and are never
encrypted.)

## The erasable key store — and why it is separate

The wrapped DEKs live in a **physically separate Postgres instance** from
`kura.records`
([`internal/keystore`](https://github.com/bensyverson/kura/tree/main/internal/keystore)),
with a single table, `kura.wrapped_deks`, whose primary key `(tenant_id, record_id,
field_name)` mirrors the identity of the value each key protects. It carries the same
[tenant-isolation RLS](../database/) as the main schema — every access binds the
`kura.tenant_id` GUC, fail-closed when unset.

The separation is the whole point. Crypto-shredding has to destroy key material that
the immutable backup never captured. The textbook envelope layout stores the wrapped
DEK next to the ciphertext — i.e. in the main database — which the immutable `pg_dump`
captures, making destruction impossible. So the shreddable keys must live **outside the
immutable backup regime**, and the boundary must be **structural, not remembered**: the
key store is simply not in the cluster the immutable backup targets. A schema-exclusion
flag on every backup would be a boundary an operator has to get right forever — one
forgotten flag immortalizes the keys and shredding silently stops reaching backups. A
separate instance cannot be captured by accident.

Because the key store is mutable and excluded from the immutable regime, it needs its
own **erasable backup**: versioned object storage *without* the deny-delete role, on a
bounded retention, so a shredded DEK genuinely disappears everywhere once retention
passes. That instance and its backup are provisioned by the [deployment
baseline](../iac/); the runtime only needs the two DSNs below.

## Erase semantics: the crypto-shred

Erasure destroys the DEKs for a **set of records** and returns how many wrapped DEKs it
shredded. It is the only Kura erasure primitive, and it is domain-agnostic: it names
records by id — a caller maps its own notion of *what* a record set represents to those
ids; Kura knows only records and field values.

- **Records are named by id.** [`kura erase <record-id>
  [record-id...]`](../../machine-interface/cli-erase/) (or `POST /api/erase` with
  `{"record_ids": [...]}`) shreds every wrapped DEK for those records within the tenant.
  It is **`AdminErase`** — admin-only — and is destructive and irreversible, so the CLI
  requires `--confirm`. The response is the count of DEKs destroyed (`{"shredded": N}`).
- **The main database is untouched.** No `kura.records` or `record_field_values` row is
  mutated or deleted; only the external keys are destroyed (and any cached copies
  evicted). Because nothing is mutated, erasure engages **no append-only trigger** — it
  is compatible with append-only entities by construction.
- **Reads stay non-failing.** A record whose DEK was shredded is a normal read. The
  field is **absent from `fields`** and named in an **`erased`** list on the record; the
  CLI and dashboard render it with an `[erased]` sentinel. The rest of the record — its
  id, timestamps, non-PII structure, and any still-keyed fields — reads back normally.
  There is no over-erasure: shredding one field's key leaves every other field intact.
- **Erased is not the same as tampered.** A missing DEK is the *expected* state after a
  shred, returned as a clean miss and surfaced as erased. A DEK that is *present* but
  cannot open its value (`ErrAuthentication` — tampering or a wrong KEK) is a **hard
  error**, never a silent erased. The two can never be confused.
- **It is idempotent.** Erasing a record with no encrypted fields, or one already
  erased, shreds nothing and is harmless.
- **Every shred is audited per record.** The gate records the authorization decision and
  then one `erase` access event **per named record**, so the [audit trail](../audit/)
  names exactly which records were forgotten, by whom, and when — not merely that an
  erasure ran.

## KEK-only rotation

Rotation re-wraps the DEKs in place: unwrap each wrapped DEK with the retiring KEK,
re-wrap it with the new one, and advance the row's stamped `kek_version`. The **DEK
value never changes**, so every ciphertext — in the live database *and* in immutable
backups — stays decryptable across a rotation. Rotation stays entirely within the
mutable key store; it never touches ciphertext.

Every wrapped DEK is stamped with the KEK generation that wrapped it. During a rotation
the running server holds a **key ring** of both generations: the write path seals under
the active KEK and stamps its version; the read path opens each row under whichever
generation wrapped it. Outside a rotation the ring holds one generation and behaves like
a single KEK.

[`kura rotate-kek`](../../machine-interface/cli-rotate-kek/) drives a **resumable,
batched** re-wrap directly against the key store (`--batch` sizes each durable step).
Selecting strictly on the retiring version makes it idempotent: an interrupted run
re-selects only the not-yet-advanced rows and never double-wraps one already rotated.

**Per-value DEK rotation is deliberately excluded.** Re-encrypting a value under a fresh
DEK and destroying the old one collides with the immutable-backup invariant: a backup
froze the ciphertext under the old DEK, so destroying that DEK would leave the live value
readable but the backup's copy permanently unreadable. DEK destruction and
crypto-shredding are the same operation pointed at opposite intents — shredding *wants*
the backup ciphertext gone; rotation does not — so KEK-only rotation is the principled
choice, not merely the cheaper one.

## Configuration

The record store and the key store are configured on `kura serve`. All secrets come from
the [secrets manager](../secrets/) (Doppler in production, the process environment on the
dev/bare path); nothing is baked in.

| Setting | What it configures |
| --- | --- |
| `FIELD_ENCRYPTION_KEY` | The master KEK — a base64-encoded 32-byte AES-256 key. Sourced from the secrets manager under this canonical name; required once `KURA_DATABASE_URL` is set. |
| `KURA_KEK_VERSION` | The active KEK generation stamped on new writes (defaults to `1`). |
| `KURA_KEYSTORE_DATABASE_URL` | Runtime DSN (TLS) of the **separate, erasable** key-store instance that holds the wrapped DEKs. Required once `KURA_DATABASE_URL` is set. |
| `KURA_KEYSTORE_ADMIN_DATABASE_URL` | Elevated migrator DSN for the key-store instance; its schema is applied here at startup. |

Two more secrets are set **only while a rotation is in flight**, alongside the new
`FIELD_ENCRYPTION_KEY` / `KURA_KEK_VERSION`, then removed once `kura rotate-kek` reports
every row advanced:

| Setting | What it configures |
| --- | --- |
| `FIELD_ENCRYPTION_KEY_RETIRING` | The outgoing KEK, so the read path and the rotation can unwrap rows still stamped with the old generation. |
| `KURA_KEK_RETIRING_VERSION` | The outgoing generation, the version the rotation advances *from*. |

The **erasable backup** of the key store is not a runtime setting — it is a property of
how the separate instance is provisioned: versioned object storage without the
deny-delete role, on a bounded retention, distinct from the main database's immutable
[BACKUPS bucket](../storage/) and from the separate `BACKUP_ENCRYPTION_KEY` that seals
those dumps. It lands with the [deployment baseline](../iac/).

## Deferred: searchable PII (blind indexes)

ADR 0002 settles a **blind-index** design for looking up records by an encrypted value
without decrypting the table — store `HMAC(search_key, normalize(value))` in an indexed
column under a separate shared search key, and turn a normalized query term into an
indexed equality hit. It is **not implemented.** Encrypt-by-default ships independently
because Kura does no server-side filtering on field content today, so blind indexes are
not on its critical path.

The mechanism is settled but the **per-category normalization rules** it depends on — the
open **D6 decision**: email casing, phone formatting, name folding, and which
partial-match transforms to ship — still need their own ADR before implementation.
Category-level presence search ("which records contain a phone number") is already
available for free through the [`pii_spans`](../pii/) inventory, with no new index and no
decryption. Substring, fuzzy, range, and sort over encrypted content stay further out —
that is heavier encrypted-search territory and will be built only when something
concretely needs it.
