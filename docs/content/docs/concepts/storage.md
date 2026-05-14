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

## Retention is policy, not action

Retention lives on the bucket spec as declared lifecycle bounds (`MinDays` /
`MaxDays`); the storage platform enforces it. The `Store` interface has **no
expire or purge primitive** — nothing the runtime can invoke deletes data on a
schedule. Lifecycle is something the bucket *has*, not something the
application *does*.
