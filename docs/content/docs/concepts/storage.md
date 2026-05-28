---
title: Object storage
weight: 8
---

Two things Kura keeps live **outside Postgres**: encrypted backup dumps and the
append-only audit trail. Both go to object storage — and each gets its own
bucket, its own credentials, and its own retention.

## Two buckets, two credential domains

| Bucket | Holds | Written by | Retention |
| --- | --- | --- | --- |
| **BACKUPS** | Encrypted logical-backup dumps, in their own region | Primary infrastructure, via the append-only role | 30–35 days |
| **AUDIT-LOG** | The append-only audit trail | The API, via the append-only role | 1–2 years |

The buckets sit in **distinct credential domains**. A writer compromised in one
domain holds no key material for the other — the backup job cannot touch the
audit log, and the API cannot touch the backups. Both buckets are private
always and encrypted always; neither is a configurable option.

## Immutability: the deny-delete posture

DO Spaces has no Object Lock / WORM. The achievable — and targeted — posture is
**versioning enabled plus a deny-delete bucket policy** (denying object and
version deletion, and denying versioning-disable), administered from a
credential domain *separate from the runtime writer*. The runtime writer can
append but effectively cannot destroy. True WORM is the Heavily-Regulated
(AWS/GCP) tier; this is the proportionate posture for the Standard-Regulated
baseline and Kura's threat model.

The storage interface models this directly. A `Store` carries a **role**:

- **`AppendOnly`** — the runtime writer's posture. Putting a key that already
  exists is refused (`ErrOverwriteDenied`); any delete is refused
  (`ErrDeleteDenied`). New objects write normally.
- **`ReadWrite`** — held only by the separate administrative credential domain
  that owns the bucket's lifecycle. Reads, writes, overwrites, and deletes are
  all permitted.

The in-memory `Fake` used by tests enforces the same role contract as the real
DO Spaces implementation, so a test exercising the runtime writer cannot
accidentally destroy data the real bucket policy would protect.

## Backup encryption: a key of its own

The logical-backup tier is what earns the security improvement over bare managed
Postgres. DO's built-in managed backups are kept on for fast operational
recovery, but they share the primary database's credential domain. The
independent tier adds the compromise-resilient copy: it dumps the database
(`pg_dump`, custom format), encrypts the dump with **AES-256-GCM**, and writes
the ciphertext to the BACKUPS bucket through the append-only role. Restore
reverses the path — read, decrypt, `pg_restore` into a target.

The backup-encryption key is sourced from the secrets manager under
`BACKUP_ENCRYPTION_KEY`, and it is **distinct from the runtime
`FIELD_ENCRYPTION_KEY`** that protects fields inside Postgres. Distinct keys are
the point: a leak of the runtime key exposes neither the backups nor a path to
forge them, and the backup copy lives in a separate region under a separate
credential. Both operations are audited (`backup.created`, `backup.restored`)
and run through the jobs ledger, so they are idempotent and retryable like any
other async operation.

The orchestration lives in
[`internal/backup`](https://github.com/bensyverson/kura/tree/main/internal/backup);
the `pg_dump`/`pg_restore` mechanism sits behind a `Dumper` interface so the
logic is testable without a database. Operators drive it with
[`kura backup` and `kura restore`](../../machine-interface/cli-backup-restore/).

The bucket's concrete client is the S3-compatible `Spaces` `Store` in
[`internal/storage`](https://github.com/bensyverson/kura/tree/main/internal/storage),
which works against DO Spaces in production and any S3 endpoint (a local MinIO)
under test. It enforces the `AppendOnly`/`ReadWrite` contract in Go — the belt —
to match the deny-delete bucket policy that is the suspenders. The *scheduled*
invocation of `kura backup` is provisioned in the deployment-baseline phase.

## Retention is policy, not action

Retention lives on the bucket spec as declared lifecycle bounds (`MinDays` /
`MaxDays`); the storage platform enforces it. The `Store` interface has **no
expire or purge primitive** — nothing the runtime can invoke deletes data on a
schedule. Lifecycle is something the bucket *has*, not something the
application *does*.
