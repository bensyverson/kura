package identity

import (
	"context"
	"testing"
)

func TestFakeIdPDirectoryReportsSetStatus(t *testing.T) {
	dir := NewFakeIdPDirectory().
		Set("active@client.com", AccountActive).
		Set("suspended@client.com", AccountSuspended)

	cases := map[string]AccountStatus{
		"active@client.com":    AccountActive,
		"suspended@client.com": AccountSuspended,
	}
	for email, want := range cases {
		got, err := dir.AccountStatus(context.Background(), email)
		if err != nil {
			t.Fatalf("AccountStatus(%q): %v", email, err)
		}
		if got != want {
			t.Errorf("AccountStatus(%q) = %q, want %q", email, got, want)
		}
	}
}

// An email the directory has never heard of is absent — the account
// does not exist in the identity provider — not an error.
func TestFakeIdPDirectoryUnknownEmailIsAbsent(t *testing.T) {
	dir := NewFakeIdPDirectory()
	got, err := dir.AccountStatus(context.Background(), "ghost@client.com")
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	if got != AccountAbsent {
		t.Errorf("unknown email status = %q, want %q", got, AccountAbsent)
	}
}

func TestFakeIdPDirectoryIsAnIdPDirectory(t *testing.T) {
	var _ IdPDirectory = NewFakeIdPDirectory()
}
