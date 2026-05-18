package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// MicrosoftConfig is the Microsoft Entra OAuth/OIDC client
// configuration kura serve needs to broker sign-in. The client ID and
// secret are issued by Entra for the deployment's app registration;
// RedirectURL is kura serve's own public /oauth/callback URL,
// registered with Entra as a redirect_uri.
type MicrosoftConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// TenantID is the Microsoft Entra tenant ID — the GUID of a
	// specific Entra tenant, or "common" for multi-tenant sign-in. A
	// specific TenantID restricts who can sign in (the verifier checks
	// that the iss claim names that tenant); "common" accepts a token
	// from any Entra tenant and leaves the trust decision to
	// TenantTrust via the tid claim.
	TenantID string
}

// microsoftClaims are the id_token claims microsoftIdP reads from an
// Entra-issued token. preferred_username is the human-readable login
// identifier; email is the fallback for personal-account tokens that
// omit preferred_username; tid is the actual signing tenant; iss is
// the canonical OIDC issuer URL.
type microsoftClaims struct {
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	TID               string `json:"tid"`
	Iss               string `json:"iss"`
}

// microsoftTokenVerifier is the seam over go-oidc's id-token verifier
// so microsoftIdP's claim mapping and validation rules are testable
// without a live IdP. The real implementation wraps an
// *oidc.IDTokenVerifier; tests substitute a fake.
type microsoftTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (microsoftClaims, error)
}

// goOIDCVerifier adapts a *oidc.IDTokenVerifier to
// microsoftTokenVerifier by returning the Microsoft-specific claims
// shape Kura reads.
type goOIDCVerifier struct {
	v *oidc.IDTokenVerifier
}

func (g *goOIDCVerifier) Verify(ctx context.Context, raw string) (microsoftClaims, error) {
	tok, err := g.v.Verify(ctx, raw)
	if err != nil {
		return microsoftClaims{}, err
	}
	var c microsoftClaims
	if err := tok.Claims(&c); err != nil {
		return microsoftClaims{}, fmt.Errorf("server: parsing microsoft id_token claims: %w", err)
	}
	return c, nil
}

// microsoftIdP is the Microsoft Entra IdentityProvider. It runs OIDC
// discovery against the configured tenant at construction time and
// from then on holds a verifier and an oauth2 config. It holds no
// Kura logic beyond claim mapping and the no-anonymous-tid rule — the
// trust decision belongs to identity.TenantTrust and the token model
// to identity.Authenticator.
type microsoftIdP struct {
	oauth    *oauth2.Config
	verifier microsoftTokenVerifier
}

// NewMicrosoftIdP runs OIDC discovery against the configured Entra
// tenant and returns a ready Microsoft IdentityProvider. The "common"
// tenant accepts tokens from any Entra tenant; a specific tenant ID
// restricts sign-in to that tenant's issuer.
//
// Discovery and the JWKS fetch happen here, so this constructor
// requires network access; callers should pass a context with a
// reasonable timeout.
func NewMicrosoftIdP(ctx context.Context, cfg MicrosoftConfig) (IdentityProvider, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("server: microsoft idp: TenantID is required (\"common\" for multi-tenant)")
	}
	issuerURL := "https://login.microsoftonline.com/" + cfg.TenantID + "/v2.0"
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("server: microsoft oidc discovery: %w", err)
	}
	oidcCfg := &oidc.Config{ClientID: cfg.ClientID}
	if cfg.TenantID == "common" {
		// The /common discovery doc's iss is a template
		// (https://login.microsoftonline.com/{tenantid}/v2.0), so the
		// default per-token issuer-equality check would fail every
		// real token. Skip it — the per-tenant trust decision is
		// TenantTrust's job, made from the tid claim in verifyAndMap.
		oidcCfg.SkipIssuerCheck = true
	}
	return &microsoftIdP{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier: &goOIDCVerifier{v: provider.Verifier(oidcCfg)},
	}, nil
}

// AuthCodeURL returns the Entra consent-screen URL for state.
func (m *microsoftIdP) AuthCodeURL(state string) string {
	return m.oauth.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// Exchange swaps an auth code for a verified Microsoft identity. The
// token exchange is a network call against Entra; verification is
// JWKS-based against the cached signing keys.
func (m *microsoftIdP) Exchange(ctx context.Context, code string) (VerifiedIdentity, error) {
	tok, err := m.oauth.Exchange(ctx, code)
	if err != nil {
		return VerifiedIdentity{}, fmt.Errorf("server: microsoft code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return VerifiedIdentity{}, fmt.Errorf("server: microsoft token carried no id_token")
	}
	return m.verifyAndMap(ctx, raw)
}

// verifyAndMap verifies the raw id_token and turns its claims into a
// VerifiedIdentity. preferred_username is preferred over email when
// both are present; a token with no tid claim is rejected — a token
// without tid is anonymous-shaped and TenantTrust has nothing to
// decide on.
func (m *microsoftIdP) verifyAndMap(ctx context.Context, rawIDToken string) (VerifiedIdentity, error) {
	c, err := m.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return VerifiedIdentity{}, fmt.Errorf("server: verifying microsoft id_token: %w", err)
	}
	email := c.PreferredUsername
	if email == "" {
		email = c.Email
	}
	if email == "" {
		return VerifiedIdentity{}, fmt.Errorf("server: microsoft id_token has no preferred_username or email claim")
	}
	if c.TID == "" {
		return VerifiedIdentity{}, fmt.Errorf("server: microsoft id_token missing tid claim")
	}
	return VerifiedIdentity{
		Email:  strings.ToLower(email),
		Tenant: c.TID,
		Issuer: c.Iss,
	}, nil
}
