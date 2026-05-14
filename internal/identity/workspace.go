package identity

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUntrustedDomain means a verified Google identity authenticated
// against a Workspace domain the deployment does not trust. There is no
// default principal type — an untrusted domain yields no principal.
var ErrUntrustedDomain = errors.New("identity: workspace domain is not trusted by this deployment")

// DomainTrust is the per-deployment mapping from a verified Google
// Workspace domain to a Kura principal type. Domain trust — not directory
// membership — is what separates a Consultant from a User: both
// authenticate with Google OAuth, and this mapping decides which
// Workspace domain becomes which principal type.
//
// It is configuration, supplied per deployment. Kura hardwires no firm
// identity.
type DomainTrust struct {
	// FirmDomain is the consulting firm's own Workspace domain. A human
	// who authenticates against it is a Consultant.
	FirmDomain string
	// ClientDomains are the client's Workspace domains. A human who
	// authenticates against one is a User — or an Admin, if their email
	// is in AdminEmails.
	ClientDomains []string
	// AdminEmails are the client-domain humans granted the elevated
	// Admin principal type. Onboarding or offboarding an admin is a
	// config edit, consistent with Kura's declarative engagement model.
	AdminEmails []string
}

// Principal maps a verified Google identity — an email and the `hd`
// hosted-domain claim that came with it — to the Kura principal it
// represents. It is called only after the OAuth layer has verified the
// identity; its job is the trust decision, not verification.
//
// A domain the deployment does not trust yields ErrUntrustedDomain. An
// empty email or domain is rejected outright: an unverified identity
// must never resolve to a principal.
func (t DomainTrust) Principal(email, domain string) (Principal, error) {
	if email == "" || domain == "" {
		return Principal{}, fmt.Errorf("identity: verified identity must carry an email and a domain")
	}
	email = strings.ToLower(email)
	domain = strings.ToLower(domain)

	if domain == strings.ToLower(t.FirmDomain) {
		return Principal{
			Type:   PrincipalConsultant,
			ID:     email,
			Email:  email,
			Domain: domain,
		}, nil
	}

	for _, cd := range t.ClientDomains {
		if domain != strings.ToLower(cd) {
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
			Domain: domain,
		}, nil
	}

	return Principal{}, fmt.Errorf("%w: %q", ErrUntrustedDomain, domain)
}
