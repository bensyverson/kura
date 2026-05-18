package identity

import (
	"errors"
	"testing"
)

func testTrust() TenantTrust {
	return TenantTrust{
		FirmTenant:    "examplefirm.com",
		ClientTenants: []string{"client.example", "client-eu.example"},
		AdminEmails:   []string{"boss@client.example"},
	}
}

// A human authenticating against the firm's IdP tenant is a
// Consultant — tenant trust, not directory membership, is what makes
// them one.
func TestTenantTrustFirmTenantIsConsultant(t *testing.T) {
	p, err := testTrust().Principal("alex@examplefirm.com", "examplefirm.com")
	if err != nil {
		t.Fatalf("Principal returned error: %v", err)
	}
	if p.Type != PrincipalConsultant {
		t.Errorf("type = %q, want consultant", p.Type)
	}
	if p.ID != "alex@examplefirm.com" || p.Email != "alex@examplefirm.com" || p.Tenant != "examplefirm.com" {
		t.Errorf("principal fields not populated from the identity: %+v", p)
	}
	if err := p.Valid(); err != nil {
		t.Errorf("resolved principal is not valid: %v", err)
	}
}

// A client-tenant human with no elevated grant is a plain User.
func TestTenantTrustClientTenantIsUser(t *testing.T) {
	p, err := testTrust().Principal("worker@client.example", "client.example")
	if err != nil {
		t.Fatalf("Principal returned error: %v", err)
	}
	if p.Type != PrincipalUser {
		t.Errorf("type = %q, want user", p.Type)
	}
}

// A client-tenant human whose email is in the admin allowlist is an
// Admin — onboarding an admin is a config edit, not a directory change.
func TestTenantTrustAdminEmailIsAdmin(t *testing.T) {
	p, err := testTrust().Principal("boss@client.example", "client.example")
	if err != nil {
		t.Fatalf("Principal returned error: %v", err)
	}
	if p.Type != PrincipalAdmin {
		t.Errorf("type = %q, want admin", p.Type)
	}
}

// A tenant the deployment does not trust yields no principal — there is
// no default principal type.
func TestTenantTrustUntrustedTenantRejected(t *testing.T) {
	_, err := testTrust().Principal("mallory@evil.example", "evil.example")
	if !errors.Is(err, ErrUntrustedTenant) {
		t.Errorf("error = %v, want ErrUntrustedTenant", err)
	}
}

// Tenant comparison is case-insensitive: IdP-supplied tenant strings
// and email casing must not be a way to dodge the trust list.
func TestTenantTrustComparisonIsCaseInsensitive(t *testing.T) {
	p, err := testTrust().Principal("Alex@ExampleFirm.com", "ExampleFirm.COM")
	if err != nil {
		t.Fatalf("Principal returned error: %v", err)
	}
	if p.Type != PrincipalConsultant {
		t.Errorf("type = %q, want consultant for case-varied firm tenant", p.Type)
	}
}

// An empty email or tenant is rejected — an unverified identity must
// never resolve to a principal.
func TestTenantTrustRejectsEmptyIdentity(t *testing.T) {
	if _, err := testTrust().Principal("", "examplefirm.com"); err == nil {
		t.Error("empty email resolved to a principal")
	}
	if _, err := testTrust().Principal("alex@examplefirm.com", ""); err == nil {
		t.Error("empty tenant resolved to a principal")
	}
}
