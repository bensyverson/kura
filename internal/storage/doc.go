// Package storage is Kura's object-storage abstraction: the two buckets
// that sit outside Postgres, each with its own credentials and its own
// retention.
//
//   - The BACKUPS bucket holds encrypted logical-backup dumps. It lives
//     in its own region, is written only by primary infrastructure
//     through the append-only role, and retains objects 30-35 days.
//   - The AUDIT-LOG bucket holds the append-only audit trail. It is
//     written only by the API through the append-only role and retains
//     objects 1-2 years.
//
// The two buckets are placed in distinct credential domains: a
// compromised writer in one cannot reach the other.
//
// Immutability posture. DO Spaces has no Object Lock / WORM. The
// achievable — and targeted — posture is versioning enabled plus a
// deny-delete bucket policy (denying object/version deletion and
// versioning-disable), administered from a credential domain separate
// from the runtime writer. The runtime writer can append but effectively
// cannot destroy. True WORM is the Heavily-Regulated (AWS/GCP) tier; this
// is the proportionate Standard-Regulated posture for Kura's threat
// model. The Store interface models this directly: a Role of AppendOnly
// refuses overwrite and delete, ReadWrite permits them, and the Fake and
// the real DO Spaces implementation agree on that contract.
//
// Retention is policy, not action. Retention lives on BucketSpec as
// declared lifecycle bounds; the storage platform enforces it. The Store
// interface has no expire or purge primitive — nothing the runtime can
// invoke deletes data on a schedule.
package storage
