Take on the DEK / key-store decision for Kura's field-encryption work — the one
unresolved blocker (#1/#2) gating the encryption subtree. This is a diverge-then-converge
DECISION pass, not implementation. Do NOT use plan mode.

READ FIRST (use an Explore agent for the docs; don't sweep the whole codebase):
- project/2026-06-24-crm-substrate-overview.md            (connective tissue; "open USER decisions")
- project/2026-06-24-field-encryption-crypto-shredding.md (D1–D7 + the 6 open questions)
- project/2026-06-24-substrate-implementation-plan.md     (what's already planned + decisions resolved)

THE QUESTION TO RESOLVE:
1. Key granularity at volume — is per-field-value DEKs operationally viable at target
   volume, or do we settle a coarser granularity that still avoids over-erasure and stays
   domain-agnostic? Do a key-count sizing analysis (script it into scripts/ per CLAUDE.md).
2. The erasable key-store mechanism — choose it (KMS / secrets manager / dedicated store)
   and define its own erasable-backup/durability story, and confirm it can be excluded
   from the immutable backup regime.

THE CRUX (why this is hard): crypto-shredding requires destroying key material that is NOT
in the immutable backup. The standard envelope pattern stores the wrapped DEK next to the
ciphertext — i.e. in Postgres — which is captured by the deny-delete immutable DB backup,
so destroying it there is impossible. The shreddable key material must therefore live in a
SEPARATE mutable store outside the immutable backup regime, with its own erasable durability.
Per-field-value granularity implies potentially millions of DEKs → validate key-store size,
unwrap-per-read perf (DEK caching), and rotation.

VERIFIED FACTS (as of 2026-06-24 — re-confirm before relying, but these are current):
- Current crypto: single global key via pgcrypto pgp_sym_encrypt (randomized IV) —
  internal/db/crypto.go (EncryptValue/DecryptValue); key read from env KURA_RECORD_ENCRYPTION_KEY
  at cmd/kura/serve.go:331. No key hierarchy.
- Per-VALUE encryption already exists: kura.record_field_values has value_text + value_encrypted
  with XOR check exactly_one_value (internal/migrations/0001_app_schema.sql). So encryption can
  vary row-by-row for the same field — the granularity the design exploits.
- Secrets infra EXISTS but is UNWIRED: internal/secrets/secrets.go (Manager + EncryptionKey()),
  doppler.go backend, constants FIELD_ENCRYPTION_KEY / BACKUP_ENCRYPTION_KEY. Doppler is the
  natural KEK home; it CANNOT hold millions of DEKs. serve.go still reads keys from env directly.
- Immutable backups: deploy/terraform/storage.tf — deny-delete versioned DO Spaces; backups are
  pgdump → AES-256-GCM (KURA_BACKUP_ENCRYPTION_KEY, DeriveKey=SHA-256) → append-only Spaces role.
- Encrypt-by-default is ~free today: NO server-side filtering/sorting on value_text anywhere; only
  decrypt-at-display projection (internal/data/postgres.go:145). Filtering is unshipped.
- Detector is in-tenant already: self-hosted model via KURA_PII_DETECTOR_URL behind the swappable
  Detector interface (internal/pii/detect.go:25). Not OpenAI-cloud.
- PII categories: internal/pii/category.go (high-sensitivity = account_number, secret).

ALREADY SETTLED — do NOT re-open (rationale in the encryption doc): crypto-shredding is primary
erasure; encrypt-PII-by-default with sensitivity decoupled from shreddability; blind-index search
with a SEPARATE pepper; searchable is manifest-declared; relationship endpoint ids stay plaintext.
Per-field-value DEKs is the LEAN choice but is exactly what you're validating in #1.

NEEDS THE USER (ask early): target volume/scale assumption; infra appetite (dedicated erasable
key DB vs. a KMS pattern); rotation expectations; counsel/DPO sign-off on the
HMAC-tokens-in-immutable-backups residual (external — track, don't block code).

DELIVERABLE (this project's shape):
- A dated decision doc project/2026-06-24-...-key-store.md (or similar) resolving #1/#2 with
  rationale and rejected alternatives, matching the style of the three peer decision docs.
- An embedded `tasks:` YAML block (job schema format; do NOT hard-wrap desc fields) for the
  encryption subtree, to `job import` under the existing "Phase 9 — Substrate capabilities" root.
  Encryption migrations are forward-only, numbered 0010+ (0007 seq, 0008 edges, 0009 append-only).

CONSTRAINTS: Kura stays domain-agnostic — no diff or task mentions CRM/party/customer/subject/
lifecycle. Strict red/green TDD. Migrations forward-only & numbered. New interfaces get Fakes;
new verbs flow through internal/ops (agent-context drift test). Keep docs/content/docs/ updated.
