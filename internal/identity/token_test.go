package identity

import (
	"errors"
	"testing"
	"time"
)

func testAuth() *Authenticator {
	return NewAuthenticator([]byte("test-signing-secret-please-rotate-me"))
}

func TestTokenRoundTrip(t *testing.T) {
	a := testAuth()
	p := Principal{Type: PrincipalConsultant, ID: "alex@firm.com", Email: "alex@firm.com", Tenant: "firm.com"}

	tok, err := a.Issue(p, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := a.Resolve(tok)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != p {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, p)
	}
}

func TestResolveRejectsExpiredToken(t *testing.T) {
	a := testAuth()
	base := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return base }

	tok, err := a.Issue(Principal{Type: PrincipalUser, ID: "u@c.com", Email: "u@c.com", Tenant: "c.com"}, 15*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	a.now = func() time.Time { return base.Add(time.Hour) }
	if _, err := a.Resolve(tok); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestResolveRejectsTamperedToken(t *testing.T) {
	a := testAuth()
	tok, _ := a.Issue(Principal{Type: PrincipalUser, ID: "u@c.com", Email: "u@c.com", Tenant: "c.com"}, time.Hour)

	tampered := tok[:len(tok)-2] + "xx"
	if _, err := a.Resolve(tampered); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for a tampered token, got %v", err)
	}
}

func TestResolveRejectsWrongSecret(t *testing.T) {
	a := testAuth()
	tok, _ := a.Issue(Principal{Type: PrincipalUser, ID: "u@c.com", Email: "u@c.com", Tenant: "c.com"}, time.Hour)

	other := NewAuthenticator([]byte("an-entirely-different-signing-secret"))
	if _, err := other.Resolve(tok); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for a token signed with another secret, got %v", err)
	}
}

func TestResolveRejectsMalformedToken(t *testing.T) {
	a := testAuth()
	for _, bad := range []string{"not-a-token", "a.b.c", "@@@.@@@", "."} {
		if _, err := a.Resolve(bad); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("Resolve(%q): expected ErrTokenInvalid, got %v", bad, err)
		}
	}
}

// No anonymous path: a request carrying no credential resolves to no
// principal and is denied.
func TestResolveRejectsMissingCredential(t *testing.T) {
	a := testAuth()
	p, err := a.Resolve("")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("empty credential: expected ErrUnauthenticated, got %v", err)
	}
	if p != (Principal{}) {
		t.Errorf("empty credential should resolve to no principal, got %+v", p)
	}
}

func TestIssueRejectsInvalidPrincipal(t *testing.T) {
	a := testAuth()
	if _, err := a.Issue(Principal{Type: "bogus", ID: "x"}, time.Hour); err == nil {
		t.Error("Issue should refuse to mint a token for an invalid principal")
	}
}
