// Package identity is Kura's identity core: the principal types Cedar
// reasons about, and the short-lived token model that backs every
// authenticated action.
//
// Unlike job, identity here has teeth. A principal is a security
// boundary, every action is attributed to one, and there is no anonymous
// path and no "trusted CLI" path — a request with no valid credential
// resolves to no principal and is denied.
package identity

import "fmt"

// PrincipalType is the kind of actor a principal represents. The four
// types match the Cedar principal schema recorded in the Phase 0
// consultant-auth decision (docs/concepts/identity.md).
type PrincipalType string

const (
	PrincipalUser       PrincipalType = "user"
	PrincipalAdmin      PrincipalType = "admin"
	PrincipalConsultant PrincipalType = "consultant"
	PrincipalService    PrincipalType = "service"
)

// cedarEntityTypes maps each principal type to its Cedar entity type
// name — the bridge between Kura's identity model and Cedar policy.
var cedarEntityTypes = map[PrincipalType]string{
	PrincipalUser:       "User",
	PrincipalAdmin:      "Admin",
	PrincipalConsultant: "Consultant",
	PrincipalService:    "Service",
}

// Valid reports whether t is a recognized principal type.
func (t PrincipalType) Valid() bool {
	_, ok := cedarEntityTypes[t]
	return ok
}

// CedarEntityType returns the Cedar entity type name for t, or "" if t is
// not a recognized principal type.
func (t PrincipalType) CedarEntityType() string {
	return cedarEntityTypes[t]
}

// isHuman reports whether t is a human principal (as opposed to a
// non-human service principal). Human principals authenticate via an
// IdP and so always carry an email and a tenant identifier.
func (t PrincipalType) isHuman() bool {
	return t == PrincipalUser || t == PrincipalAdmin || t == PrincipalConsultant
}

// Principal is an authenticated actor. Every action in Kura is
// attributed to one in the audit log.
type Principal struct {
	Type PrincipalType `json:"type"`
	// ID is the stable identifier — the Cedar entity id. For a human
	// principal it is the email; for a service principal it is the
	// service name.
	ID string `json:"id"`
	// Email and Tenant are populated for human principals only. Tenant
	// is the IdP tenant identifier (e.g. a Workspace domain, an Entra
	// tenant ID, or an Okta org).
	Email  string `json:"email,omitempty"`
	Tenant string `json:"tenant,omitempty"`
}

// Valid reports whether p is a well-formed principal, naming the first
// problem it finds.
func (p Principal) Valid() error {
	if !p.Type.Valid() {
		return fmt.Errorf("identity: unrecognized principal type %q", p.Type)
	}
	if p.ID == "" {
		return fmt.Errorf("identity: principal ID must not be empty")
	}
	if p.Type.isHuman() {
		if p.Email == "" {
			return fmt.Errorf("identity: %s principal %q must carry an email", p.Type, p.ID)
		}
		if p.Tenant == "" {
			return fmt.Errorf("identity: %s principal %q must carry a tenant", p.Type, p.ID)
		}
	}
	return nil
}
