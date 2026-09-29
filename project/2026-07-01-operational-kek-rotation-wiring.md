# Operational KEK rotation wiring (KujMe)

- **Date:** 2026-07-01
- **Task:** `KujMe` — Operational KEK rotation wiring (child of `7bjgb` Field-level
  encryption and crypto-shredding; blocks `OdXWD` encryption docs)
- **Builds on:** `VPQAT` (KEK rotation primitive: `keystore.RotateBatch` /
  `keystore.Rotate`, already shipped) and ADR 0002 (erasable key store,
  KEK-only rotation).

## Why this is safe (KEK vs. DEK rotation)

Rotation here is **KEK-only**: unwrap each per-value DEK with the old master
key, re-wrap with the new one. The DEK value — and therefore the ciphertext in
the live DB *and* the immutable backups — is unchanged, so nothing rotation
does can break a backup. **DEK** rotation (re-encrypting values under fresh
DEKs) *would* break backups and collide with crypto-shredding; ADR 0002
forbids it. Rotation only touches the mutable key store, never the immutable
backup cluster, and it cannot resurrect a shredded value (its wrapped-DEK row
is already gone, so there is nothing to re-wrap).

## Chosen approach: label each row (version-indexed keys)

A rotation re-wraps rows in batches, so for the duration (~1.4h at 100M keys)
the key store holds a **mix** of old-KEK and new-KEK rows. A live server must
open both. Each row already carries a `kek_version` tag; the server holds a
**versioned set of KEKs** and opens each row with the key its tag names.
Rejected alternatives: try-both-keys (fuzzier tamper vs. wrong-key signal) and
maintenance-window (walks back online-rotation criterion J2O and ADR 0002).

## Operator flow

1. Provision a new master key in the secrets store, beside the old one.
2. Set active = v2, retiring = v1 in config; restart. New writes lock under v2;
   the server can open both v1 and v2 rows.
3. Run `kura rotate-kek` — batched, resumable re-lock of every v1 row under v2.
4. When drained, remove the old key from config.

## Config shape (minimal; no-rotation case unchanged)

- `FIELD_ENCRYPTION_KEY` — active key (unchanged), `KURA_KEK_VERSION` = its
  number (default `1`).
- During a rotation only: `FIELD_ENCRYPTION_KEY_RETIRING` +
  `KURA_KEK_RETIRING_VERSION` for the outgoing key.

Version numbers are non-sensitive config (env); key material comes from the
secrets backend — matching the existing split.

## Build steps (each red/green TDD)

1. `wgKBY` — **Key ring**: versioned KEK set. `WrapActive` wraps under the
   active KEK and reports the active version; `Unwrap(wrapped, version)`
   selects by version; unknown version → clear error (not a GCM auth failure).
2. `Nsufp` — **Write path stamps the active version** (`keystore.Store` +
   `data.sealField`); fixes the mislabel-as-v1 bug. Criterion `7tj`.
3. `c64xO` — **Read path selects the KEK by row version** (`keystore.Fetch`
   returns version; `Cache` unwraps via the key ring). Criterion `J2O`.
4. `LsANp` — **Runtime wiring**: build the key ring from the secrets backend;
   document the new env vars in `concepts/server.md`. Criterion `qaT`.
5. `9WdAh` — **`kura rotate-kek`** drives the resumable rotation from the same
   dual-KEK config. Criterion `JL1`.

Full operator rotation runbook remains task `OdXWD` (unblocked by this work).
