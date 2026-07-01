---
title: CLI erase — kura erase
weight: 10
---

`kura erase` crypto-shreds a set of records: it destroys the per-value keys that
decrypt their encrypted field values, so the ciphertext becomes permanently
undecryptable in every copy — the live database, its replicas, and the deny-delete
immutable backup alike — **without deleting or mutating any row**. It is the erasure
primitive from [Field encryption & crypto-shredding](../../concepts/encryption/), and a
[thin presenter](../agent-context/): the shred runs server-side through the core
[gate](../../concepts/gate/).

```sh
kura erase <record-id> [record-id...] --confirm
```

Erasing is an **`erase`** admin operation — admin only — and every erasure is
[audited](../../concepts/audit/), one event per named record, so the trail names exactly
which records were forgotten, by whom, and when.

## Records are named by id

`kura erase` takes one or more record ids and shreds every wrapped key for those records
within the tenant. The verb is **domain-agnostic**: it knows only records. A caller maps
its own notion of *what* a record set represents to the ids it passes; Kura never learns
anything more.

Because erasure destroys external keys and never touches `kura.records`, it engages **no
append-only trigger** — it is compatible with append-only entities by construction. The
record itself stays put; only its encrypted values become unreadable.

## It is destructive and requires `--confirm`

Erasure is irreversible — a shredded key cannot be recovered — so the verb refuses to run
without `--confirm`. That flag is the only confirmation; there is no interactive prompt.

```sh
kura erase 8f3c1d2a-... 1b9e77f0-... --confirm
```

Erasing a record with no encrypted fields, or one already erased, shreds nothing and is
harmless — the operation is idempotent.

## Output

Without `--json`, `kura erase` prints a dense Markdown summary naming the records asked to
erase and how many wrapped keys were actually destroyed:

```markdown
# kura erase

Requested erasure of 2 record(s): 8f3c1d2a-..., 1b9e77f0-...
Destroyed 3 wrapped key(s); the erased field values can no longer be decrypted.
```

With `--json` it emits the machine shape — the count of keys shredded:

```json
{"shredded": 3}
```

A shredded record still **reads back normally** afterward: its erased fields are absent
from the record's `fields` and named in an `erased` list, which `kura show` / `kura query`
render with an `[erased]` sentinel (see [CLI data verbs](../cli-data/)). The rest of the
record — id, timestamps, and any still-keyed fields — is unaffected.

## Identity is server-stamped

`kura erase` sends no actor. The server stamps the **authenticated principal** (from the
cached bearer token) into the operation, so the per-record `erase` audit events name the
real caller — a client cannot attribute an erasure to someone else.

## `--local` is a deployment-baseline stub

The global `--local` flag (break-glass on-box execution) needs the on-box key store, which
lands with the [deployment baseline](../../concepts/iac/). Until then, `kura erase --local`
fails with a clear message; run against a remote `kura serve`.
