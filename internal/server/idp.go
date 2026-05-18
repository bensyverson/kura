package server

import "context"

// IdentityProvider is the seam over a single IdP family's side of the
// OAuth/OIDC sign-in flow. A real implementation builds the consent URL,
// exchanges the auth code, and verifies the id_token; a fake stands in
// for it in tests so the handler logic is testable without a live IdP.
//
// The interface is deliberately family-agnostic: Google Workspace,
// Microsoft Entra (Azure AD), Okta, and generic OIDC providers all
// satisfy it. Each implementation lives in its own file
// (internal/server/idp_<family>.go) so a deployment can pick the IdP
// without dragging in the others.
type IdentityProvider interface {
	// AuthCodeURL returns the IdP consent-screen URL for state.
	AuthCodeURL(state string) string
	// Exchange swaps an auth code for a verified identity.
	Exchange(ctx context.Context, code string) (VerifiedIdentity, error)
}
