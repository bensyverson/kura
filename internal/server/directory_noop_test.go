package server

import (
	"context"
	"testing"

	"github.com/bensyverson/kura/internal/identity"
)

// The noop directory is the placeholder for IdPs (generic OIDC) that
// expose no standard directory API. It reports every email as
// AccountActive — the most conservative answer compatible with the
// mismatch endpoint: callers see *no* mismatches, which matches reality
// (Kura cannot tell) and never produces a false positive.
func TestNoopDirectoryReportsActiveForAnyEmail(t *testing.T) {
	dir := NewNoopDirectory()
	for _, email := range []string{
		"alex@client.com",
		"someone-else@otherfirm.example",
		"definitely-not-real@nowhere.test",
	} {
		got, err := dir.AccountStatus(context.Background(), email)
		if err != nil {
			t.Fatalf("AccountStatus(%q): %v", email, err)
		}
		if got != identity.AccountActive {
			t.Errorf("AccountStatus(%q) = %q, want %q", email, got, identity.AccountActive)
		}
	}
}

func TestNoopDirectoryIsADirectory(t *testing.T) {
	var _ identity.Directory = NewNoopDirectory()
}
