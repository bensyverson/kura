package identity

import (
	"strings"
	"testing"
)

// Principal types map to the Cedar entity types recorded in the Phase 0
// consultant-auth decision (docs/concepts/identity.md).
func TestPrincipalTypeMapsToCedarEntityType(t *testing.T) {
	cases := map[PrincipalType]string{
		PrincipalUser:       "User",
		PrincipalAdmin:      "Admin",
		PrincipalConsultant: "Consultant",
		PrincipalService:    "Service",
	}
	for pt, want := range cases {
		if !pt.Valid() {
			t.Errorf("%q should be a valid principal type", pt)
		}
		if got := pt.CedarEntityType(); got != want {
			t.Errorf("%q.CedarEntityType() = %q, want %q", pt, got, want)
		}
	}
}

func TestUnknownPrincipalTypeIsInvalid(t *testing.T) {
	for _, pt := range []PrincipalType{"", "root", "USER", "agent"} {
		if pt.Valid() {
			t.Errorf("%q should not be a valid principal type", pt)
		}
		if pt.CedarEntityType() != "" {
			t.Errorf("%q.CedarEntityType() should be empty", pt)
		}
	}
}

func TestPrincipalValidation(t *testing.T) {
	valid := []Principal{
		{Type: PrincipalUser, ID: "alice@client.com", Email: "alice@client.com", Tenant: "client.com"},
		{Type: PrincipalConsultant, ID: "alex@firm.com", Email: "alex@firm.com", Tenant: "firm.com"},
		{Type: PrincipalService, ID: "ingest-worker"},
	}
	for _, p := range valid {
		if err := p.Valid(); err != nil {
			t.Errorf("valid principal %+v rejected: %v", p, err)
		}
	}

	invalid := []Principal{
		{Type: "bogus", ID: "x"},
		{Type: PrincipalUser, ID: ""},
		{Type: PrincipalUser, ID: "alice", Tenant: "client.com"},   // human, no email
		{Type: PrincipalAdmin, ID: "bob", Email: "bob@client.com"}, // human, no tenant
	}
	for _, p := range invalid {
		if err := p.Valid(); err == nil {
			t.Errorf("invalid principal %+v was accepted", p)
		}
	}
}

// Human-principal validation errors should name the missing field in the
// new (IdP-agnostic) vocabulary: "tenant", not "domain".
func TestPrincipalValidationErrorsUseTenantVocabulary(t *testing.T) {
	p := Principal{Type: PrincipalAdmin, ID: "bob", Email: "bob@client.com"}
	err := p.Valid()
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "tenant") {
		t.Errorf("error %q should mention %q", err.Error(), "tenant")
	}
	if strings.Contains(err.Error(), "domain") {
		t.Errorf("error %q should no longer mention %q", err.Error(), "domain")
	}
}
