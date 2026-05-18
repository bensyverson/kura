package identity

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUntrustedTenant means a verified identity authenticated against an
// IdP tenant the deployment does not trust. There is no default
// principal type — an untrusted tenant yields no principal.
var ErrUntrustedTenant = errors.New("identity: tenant is not trusted by this deployment")

// TenantTrust is the per-deployment mapping from a verified IdP tenant
// identifier to a Kura principal type. Tenant trust — not directory
// membership — is what separates a Consultant from a User: every human
// authenticates through some IdP, and this mapping decides which tenant
// becomes which principal type.
//
// The tenant identifier comes from whichever IdP family the deployment
// uses — a Google Workspace domain, an Entra (Azure AD) tenant ID, or an
// Okta org. TenantTrust does not care which one; it only compares the
// tenant key it is given against the configured allowlists.
//
// It is configuration, supplied per deployment. Kura hardwires no firm
// identity.
type TenantTrust struct {
	// FirmTenant is the consulting firm's own IdP tenant identifier. A
	// human who authenticates against it is a Consultant.
	FirmTenant string
	// ClientTenants are the client's IdP tenant identifiers. A human who
	// authenticates against one is a User — or an Admin, if their email
	// is in AdminEmails.
	ClientTenants []string
	// AdminEmails are the client-tenant humans granted the elevated
	// Admin principal type. Onboarding or offboarding an admin is a
	// config edit, consistent with Kura's declarative engagement model.
	AdminEmails []string
}

// Principal maps a verified identity — an email and the IdP tenant
// identifier that came with it — to the Kura principal it represents.
// It is called only after the OAuth/OIDC layer has verified the
// identity; its job is the trust decision, not verification.
//
// A tenant the deployment does not trust yields ErrUntrustedTenant. An
// empty email or tenant is rejected outright: an unverified identity
// must never resolve to a principal.
func (t TenantTrust) Principal(email, tenant string) (Principal, error) {
	if email == "" || tenant == "" {
		return Principal{}, fmt.Errorf("identity: verified identity must carry an email and a tenant")
	}
	email = strings.ToLower(email)
	tenant = strings.ToLower(tenant)

	if tenant == strings.ToLower(t.FirmTenant) {
		return Principal{
			Type:   PrincipalConsultant,
			ID:     email,
			Email:  email,
			Tenant: tenant,
		}, nil
	}

	for _, cd := range t.ClientTenants {
		if tenant != strings.ToLower(cd) {
			continue
		}
		ptype := PrincipalUser
		for _, ae := range t.AdminEmails {
			if email == strings.ToLower(ae) {
				ptype = PrincipalAdmin
				break
			}
		}
		return Principal{
			Type:   ptype,
			ID:     email,
			Email:  email,
			Tenant: tenant,
		}, nil
	}

	return Principal{}, fmt.Errorf("%w: %q", ErrUntrustedTenant, tenant)
}
