package storage

// CredentialDomain identifies an isolated set of credentials. Two buckets
// in different domains share no key material, so a compromised writer in
// one domain cannot reach the other. The backups bucket (written by
// primary infrastructure) and the audit-log bucket (written by the API)
// are deliberately placed in distinct domains.
type CredentialDomain string

// Retention is a bucket's lifecycle policy, expressed declaratively in
// days. It is enforced by the storage platform's lifecycle rules — never
// by the application issuing deletes. The Store interface has no
// expire/purge primitive on purpose: retention is policy, not an action
// any runtime credential can take.
type Retention struct {
	// MinDays is the floor an object must be retained before the
	// lifecycle policy may expire it.
	MinDays int
	// MaxDays is the ceiling at which the lifecycle policy expires an
	// object.
	MaxDays int
}

// BucketSpec is the immutable description of a bucket: its name, the
// credential domain that owns it, and its retention policy. Buckets are
// always private and always encrypted; those are not fields because they
// are not options.
type BucketSpec struct {
	// Name is the logical bucket name. The IaC phase maps it to a
	// concrete, per-deployment DO Spaces bucket name.
	Name string
	// CredentialDomain is the isolated credential set that owns the
	// bucket.
	CredentialDomain CredentialDomain
	// Retention is the declared lifecycle policy for the bucket.
	Retention Retention
}

// BackupsSpec is the canonical spec for the BACKUPS bucket: encrypted,
// held in its own region, written only by primary infrastructure via the
// append-only role, with a 30-35 day retention window.
func BackupsSpec() BucketSpec {
	return BucketSpec{
		Name:             "backups",
		CredentialDomain: "backups-infra",
		Retention:        Retention{MinDays: 30, MaxDays: 35},
	}
}

// AuditLogSpec is the canonical spec for the AUDIT-LOG bucket: encrypted,
// append-only, written only by the API via the append-only role, with a
// 1-2 year retention window.
func AuditLogSpec() BucketSpec {
	return BucketSpec{
		Name:             "audit-log",
		CredentialDomain: "audit-log-api",
		Retention:        Retention{MinDays: 365, MaxDays: 730},
	}
}
