package identity

import "context"

// AccountStatus is the state of an account in the identity provider.
// It is what makes an IdP mismatch detectable: an account that is
// suspended or absent upstream while still holding Kura roles is access
// the deployment no longer intends to grant.
type AccountStatus string

const (
	// AccountActive: the account exists and is enabled upstream.
	AccountActive AccountStatus = "active"
	// AccountSuspended: the account exists upstream but is suspended.
	AccountSuspended AccountStatus = "suspended"
	// AccountAbsent: the identity provider has no such account at all.
	AccountAbsent AccountStatus = "absent"
)

// Directory reports the status of accounts in the identity provider.
// It is the narrow seam IdP-mismatch detection reads through: real
// implementations wrap a vendor directory API (Google Admin SDK,
// Microsoft Graph) and FakeDirectory backs unit tests so the core's
// tests need no live IdP.
type Directory interface {
	// AccountStatus reports the upstream status of email. An account the
	// directory has no record of is AccountAbsent, not an error.
	AccountStatus(ctx context.Context, email string) (AccountStatus, error)
}

// FakeDirectory is an in-memory Directory for tests: it reports exactly
// the statuses registered with Set, and AccountAbsent for any email it
// was not told about.
type FakeDirectory struct {
	status map[string]AccountStatus
}

var _ Directory = (*FakeDirectory)(nil)

// NewFakeDirectory returns a FakeDirectory that knows no accounts.
func NewFakeDirectory() *FakeDirectory {
	return &FakeDirectory{status: make(map[string]AccountStatus)}
}

// Set registers email's upstream status. It returns the directory so
// registrations can be chained.
func (f *FakeDirectory) Set(email string, status AccountStatus) *FakeDirectory {
	f.status[email] = status
	return f
}

// AccountStatus reports the registered status of email, or AccountAbsent
// if it was never registered.
func (f *FakeDirectory) AccountStatus(_ context.Context, email string) (AccountStatus, error) {
	if s, ok := f.status[email]; ok {
		return s, nil
	}
	return AccountAbsent, nil
}
