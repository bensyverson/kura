---
title: CLI KEK rotation — kura rotate-kek
weight: 11
---

`kura rotate-kek` re-wraps every wrapped data key in the [key
store](../../concepts/encryption/#the-erasable-key-store--and-why-it-is-separate) from a
retiring master KEK to a new active one. It is **KEK-only rotation** (ADR 0002): it
unwraps each per-value DEK with the retiring KEK and re-wraps it with the active one, then
stamps the row's new generation. The **DEK value never changes**, so every ciphertext — in
the live database and in the deny-delete immutable backups — stays decryptable across the
rotation. Per-value DEK rotation is deliberately *not* done: it would strand the backups'
ciphertext under a destroyed key.

Unlike the other verbs, this is an **operational maintenance command**, not a remote API
client. It connects **directly to the key store** and drives a resumable, batched re-wrap
to completion:

```sh
kura rotate-kek [--batch 1000]
```

## Before running: provision the new KEK

Rotation runs against a server already configured with **both** generations. Provision the
new KEK in the [secrets manager](../../concepts/secrets/) and set the incoming and retiring
keys and their versions:

| Setting | Value |
| --- | --- |
| `FIELD_ENCRYPTION_KEY` | the new (active) KEK |
| `KURA_KEK_VERSION` | its generation — one above the old one |
| `FIELD_ENCRYPTION_KEY_RETIRING` | the old (retiring) KEK |
| `KURA_KEK_RETIRING_VERSION` | its generation, the version to rotate away from |
| `KURA_KEYSTORE_DATABASE_URL` | the key store the command re-wraps |
| `KURA_DB_TENANT_ID` | the tenant whose keys are rotated |

The running `kura serve`, holding both keys as a key ring, keeps reading correctly the
whole time: the write path seals under the active KEK while the read path opens each row
under whichever generation wrapped it. `rotate-kek` never handles a raw KEK — it takes both
wrappers from the ring built out of the secrets backend.

## Rotating

`rotate-kek` re-wraps the store in **committed batches** (`--batch`, default `1000` — the
unit of durable progress), reporting a running total and a final count:

```text
Rotating wrapped DEKs from KEK v1 to v2 (batch 1000)…
  … 1000 rotated
  … 2000 rotated
Done: 2413 wrapped DEK(s) now at KEK v2.
```

It is **safe to interrupt.** Each batch commits its generation advance durably, and the
re-wrap selects strictly on the retiring version — so re-running resumes from where it
stopped and never double-wraps a row already advanced. `Done: 0` means the store was
already fully rotated.

## After: retire the old KEK

Once the command reports every row rotated, remove the retiring KEK from the configuration
(`FIELD_ENCRYPTION_KEY_RETIRING` / `KURA_KEK_RETIRING_VERSION`). The key ring then holds a
single generation again and behaves like one KEK until the next rotation.
