# Field-level encryption, crypto-shredding erasure, and searchable PII

- **Date:** 2026-06-24
- **Author:** Ben Syverson (with Claude)
- **Status:** Draft — decisions captured and accepted in principle; pending implementation planning (no `job import` yet).
- **Origin:** Surfaced while reviewing `local/2026-06-23-kura-crm-substrate-brief.md` (the "Kura → CRM substrate" append-only brief). The brief put per-subject crypto-shredding *out of scope* and assumed redaction-in-place was sufficient. Reviewing it against the actual code revealed that erasure-from-immutable-backups is a real, unmet requirement, and that the current encryption rule leaves erasure-critical PII in plaintext. That strand is large enough, and independent enough of append-only, to stand on its own — hence this doc. Other findings from the brief (append-only enforcement, the migration-vs-runtime projection question, Cedar IR validation, deterministic ordering) are tracked separately.

## Why this is its own decision

The CRM motivates it, but **none of what follows is CRM-specific.** It is a change to how Kura stores and erases PII generally. Kura should end this work still able to back any PII-bearing application with equal indifference. Every primitive here is domain-agnostic; the CRM (or any consumer) supplies the identity semantics on top.

The forcing question was GDPR Art. 17 / CCPA §1798.105 erasure ("right to be forgotten"). Three facts collided:

1. **Kura backs up to deny-delete immutable object storage** (`deploy/terraform/storage.tf`). You cannot reach into those backups to delete or rewrite a record.
2. **Erasure must nonetheless render a subject's PII unrecoverable** — including in backups. Regulators accept "put beyond use + gone by next retention cycle" rather than surgical backup edits, but the data must become genuinely unrecoverable.
3. **Redaction-in-place (null the field) cannot reach immutable backups.** So redaction alone leaves a recoverable copy of erased PII in backups forever — a real compliance hole the brief glossed over.

Crypto-shredding is the only erasure model that closes this: destroy a key held *outside* the immutable store, and every copy — live DB, replicas, WAL, sealed backups — becomes permanently opaque at once, without touching the immutable artifacts.

## Current state (verified against code, 2026-06-24)

These are the gaps the decisions below address. All verified in source:

- **Single global key.** Field encryption uses one app-managed `FIELD_ENCRYPTION_KEY` via pgcrypto. There is no key hierarchy and no per-subject/per-field key, so there is nothing to shred per subject. (`internal/db` `EncryptValue`/`DecryptValue`.)
- **Encryption is high-sensitivity-only.** `storedEncrypted` (`internal/gate/ingest.go:182`) encrypts a value only if the field is `type: text`, its *declared* category is high-sensitivity, or a *detected* span is high-sensitivity. "High-sensitivity" is just two categories — `AccountNumber`, `Secret` (`internal/pii/category.go:57`). **Everything else is stored as plaintext `value_text`.**
- **Erasure-critical PII is the unprotected set.** `Person`, `Email`, `Phone`, `Address` are all *low*-sensitivity, hence plaintext today. Those are exactly the substance of a "forget me" request. The current rule protects account numbers and secrets while leaving names and emails in the clear — backwards for erasure purposes.
- **Kura is not blind, though.** The detector scans **every** field at ingest, not only declared-PII fields (`internal/pii/scan.go:23`, fed all fields by `internal/gate/ingest.go:105`), and records every span in `kura.pii_spans` regardless of declaration. The signal exists; the encryption decision just ignores it for low-sensitivity hits.
- **Encryption is randomized.** `pgp_sym_encrypt` includes a random IV, so identical plaintexts produce different ciphertext — you cannot match or look up by ciphertext. (`internal/data/write.go`.)
- **Encryption is per-value, not per-column.** `kura.record_field_values` carries both `value_text` and `value_encrypted` with a per-row XOR check (`exactly_one_value`, `internal/migrations/0001_app_schema.sql`). Encryption can therefore vary row-by-row for the same field — which the design below exploits.
- **PII detection currently runs through an external OpenAI privacy filter.** Noted as a related risk (see Residuals); not resolved here.

## The three goals in tension

1. **Confidentiality** — PII encrypted at rest.
2. **Erasability** — a subject's PII can be made unrecoverable, *including in immutable backups*.
3. **Searchability** — users can look up by PII value (e.g. an email) across a very large table without decrypting it row-by-row.

A single ciphertext cannot serve all three, because erasability wants a *fine-grained* key (destroy one subject's data in isolation) while searchability wants a *shared* key (identical plaintexts must produce identical, indexable tokens). The resolution is to stop asking one ciphertext to do every job.

## Decisions

### D1 — Crypto-shredding is the primary erasure primitive

Erasure destroys a key, not a row. The encrypted value is left untouched (which is also what makes it compatible with append-only entities — erasure no longer mutates the record). This is the only model that reaches immutable backups.

**Rationale:** see "Why this is its own decision." Redaction-in-place cannot reach backups; crypto-shredding can.

### D2 — Encrypt PII content by default; decouple sensitivity from shreddability

Two concepts Kura currently conflates get separated:

- **Sensitivity → masking / visibility** (who may read it). Unchanged; remains a policy concern.
- **PII-ness → encryption / shreddability** (can we erase it). Becomes a binary: *any* PII (declared category of any sensitivity, **or** any detected span) ⇒ encrypted under a shreddable key.

Beyond that, **content-bearing fields are encrypted by default.** Plaintext is a deliberate, validator-enforced **opt-out** restricted to non-content structural types meant to be query/sort/index keys (`boolean`, `integer`, `timestamp`, the ordering sequence). The validator must forbid opting a `text` or PII-declared field into plaintext. (Relationship references are *not* field-values at all — they live in the dedicated `kura.record_edges` table as plaintext, indexable `uuid` columns; see `project/2026-06-24-relationships.md`. The principle is unchanged: relationship keys are never encrypted.)

**Rationale:** A shreddability guarantee that depends on an author remembering to tag a field, or on a probabilistic detector catching every email, is *disciplinary*, not structural — contrary to Kura's "structural over disciplinary / fail closed" ethos. Making encryption the default for content makes erasability a property of storage, not of classification accuracy. Per-value encryption (the existing XOR) means a `string` field stays plaintext and queryable for rows with no PII and flips to encrypted only for rows that actually carry it — so the cost is bounded.

### D3 — Key hierarchy with an erasable key store

Move from one global key to envelope encryption: a master KEK in the secrets manager wrapping many fine-grained data keys (DEKs). DEKs live in a **mutable, authoritatively-erasable key store that is deliberately excluded from the immutable backup regime** (otherwise shredding can't reach the key copy in backups — the original problem one layer down). The key store still needs its own durable, erasable backup.

### D4 — Key granularity: per-field-value DEKs **(open — validate cost)**

Lean: **per-field-value** DEKs. This is domain-agnostic (records/fields are Kura concepts; "subject" is not) and maps 1:1 onto Kura's existing per-value encryption unit. It also avoids over-erasure: shred only the PII field-values, preserving a record's non-PII structure, id, and timestamps — exactly the event-sourcing requirement.

**Open question / risk:** per-field-value keys imply a very large key count for high-volume streams, with corresponding key-store size, wrapping/unwrapping cost, and rotation overhead. This is the single biggest thing to validate before committing the implementation. Alternative granularities (per-record, per-subject) were considered and rejected: per-record over-erases retained/non-PII fields; per-subject drags CRM identity into the substrate and breaks on free-text entanglement (see D7).

### D5 — Searchable PII via blind indexes

For fields declared searchable, store two things per value:

1. `value_encrypted` — under the fine-grained **shreddable** DEK (confidentiality + erasure).
2. `value_blind_index` — `HMAC(search_key, normalize(value))` in an **indexed** column, under a **separate, shared search key** ("pepper") from the secrets manager.

Lookup = normalize the query term, HMAC it, indexed equality hit. O(log n), no decryption, only matching rows decrypted. Derive a per-field-name (or per-category) subkey so the same value in different fields does not cross-correlate. Trivial to implement in-house (keyed hash + normalization + btree index) — **no dependency.**

- **Supported:** exact match (email, phone, account number, normalized name). Domain/prefix/partial via additional transformation indexes (`HMAC(domain)`, trigram HMACs) at chosen cost/leakage.
- **Deferred:** substring / fuzzy / range / sort over encrypted PII — that is heavier encrypted-search territory (order-revealing / queryable encryption, a real dependency). Build only when something concretely needs it.
- **Free already:** category-level search ("which records contain a phone number") via `kura.pii_spans` — no new index, no decryption.

### D6 — Manifest surface: declare `searchable`, derive the index

Searchability is a declared field property; Kura derives the blind index from it. This follows Kura's "declare a property, derive the mechanism" pattern, and bounds equality-leakage to exactly the fields deliberately made searchable. (Pairs with the encryption default in D2: PII-ness is declared/detected, searchability is declared.)

### D7 — Erasure flow and the role split

On "forget subject X":

1. Destroy X's DEK(s) → `value_encrypted` permanently opaque, including in backups.
2. Delete X's blind-index entries → no longer findable in the live store. The blind index is mutable side-metadata (like `pii_spans`), so this is allowed **even for append-only entities** — it is not part of the immutable record.
3. (Consumer) re-project any derived snapshots so they don't retain the erased PII.

**Redaction-in-place is retained only for the entangled tail:** incidental PII *spans* inside another subject's free-text field (e.g. "called Bob" inside Alice's note). A field is one ciphertext, so key-shredding can't target a sub-field span; redaction can. This is the only erasure path that mutates a record, and thus the only one needing the append-only trigger's controlled bypass.

**Domain-agnosticism (the layer line):** Kura exposes primitives — *shred these field-values' keys*, *redact these spans* — plus the `pii_spans` inventory of *where* PII is. The consumer owns *whose* it is (identity resolution, subject→records mapping). Kura never learns what a "subject" is.

## Regulatory grounding (engineering-informed, not legal advice; confirm with DPO/counsel)

- **Standard is reasonableness + proportionality + by-design findability**, not perfection. "Our data is an unsearchable swamp" is itself an accountability/Art. 25 failure; being *able* to locate a subject's data is the obligation. `pii_spans` already provides most of the "findability" half (where PII is); identity linkage (whose) is the consumer's job.
- **Free-text mentions are personal data** and in scope — handled by the redaction tail (D7), as a reasonable detection-assisted effort, not a zero-residue guarantee.
- **Retention exceptions exist** (GDPR Art. 17(3); CCPA §1798.105(d)) — some events lawfully survive an erasure request (legal obligation, defense of claims). Per-field shredding (D4) lets you erase the PII fields while retaining the lawful-basis structure.
- **Backups: "beyond use" doctrine.** Crypto-shredding is a gold-standard answer — destroying the key puts every backup copy beyond use instantly.

## Accepted residuals and risks

- **Blind-index leakage.** HMAC tokens leak *equality and frequency* (two records share a value; how often a value recurs) — never the plaintext. Tunable by truncating the hash (false positives vs. equality certainty). Far weaker than plaintext; accepted.
- **HMAC tokens in immutable backups.** The blind index can be deleted live, but copies may persist in immutable backups and cannot be deleted there. They are irreversible one-way keyed hashes (cannot reconstruct the value). Likely adequate erasure, but **flag for counsel.**
- **Detector recall + external egress.** Encrypt-by-default for content (D2) is what makes erasure robust *despite* imperfect detection; detection is a safety net, not the guarantee. Separately, PII currently flows to an external OpenAI privacy filter for detection — a recall dependency *and* a PII-egress concern for a "PII-safe" store. Out of scope here; recorded for follow-up.
- **Key-management complexity is the heavy new surface** — KEK→DEK hierarchy, the erasable key store's own durability/erasable backup, unwrap-per-read performance (DEK caching), and rotation. This, plus D4's key count, is where the implementation risk concentrates.
- **Performance / storage.** Encrypt/decrypt per PII value; ciphertext larger than short plaintexts; unwrap per read. Mitigated by per-value encryption (non-PII rows stay plaintext) and DEK caching.

## Relationship to the append-only brief

Crypto-shredding **decouples erasure from append-only.** Because the shred path destroys external keys and never mutates `kura.records`, the append-only trigger needs *no* erasure exception for it — simplifying the brief's Item E considerably. The controlled bypass survives only for the narrow redaction-of-incidental-spans case (D7).

## Open questions to resolve before implementation

1. **D4 key count** — validate that per-field-value DEKs are operationally viable at target volume, or settle a coarser granularity that still avoids over-erasure and stays domain-agnostic.
2. **Erasable key store** — choose the mechanism (KMS, secrets manager, dedicated store) and its own erasable-backup story; confirm it can be excluded from the immutable backup regime.
3. **Query-path impact** — measure how much of `query`/`list`/dashboard filters on `value_text` server-side today, to size the D2 plaintext opt-out list precisely.
4. **Blind-index normalization rules** — per category (email casing, phone formatting, name folding) and the partial-match transformation indexes to ship in v1.
5. **Backup residual** — DPO/counsel sign-off on the irreversible-HMAC-in-backups position.
6. **Detector** — decide whether the external PII detector is acceptable for a PII-safe posture, or needs an in-house/in-tenant alternative (separate work).

## Definition of done (for the eventual implementation)

- PII content is encrypted by default under shreddable keys; plaintext is a validator-enforced opt-out limited to non-content structural fields.
- Erasure destroys keys (and deletes blind-index entries), rendering a subject's PII unrecoverable including in immutable backups, without mutating append-only records.
- Searchable PII fields support indexed lookup by value with no full-table decryption; searchability is manifest-declared.
- Kura remains domain-agnostic: it exposes shred/redact/inventory primitives; no notion of "subject" or any CRM concept appears in the diff.
- Accepted residuals are documented; counsel has signed off on the backup-residual position.
