package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig is the generic OIDC client configuration. The IssuerURL
// is the OIDC issuer's base URL — discovery happens at
// `<IssuerURL>/.well-known/openid-configuration`. ClientID and
// ClientSecret are issued by the IdP for kura serve as a confidential
// relying party; RedirectURL is kura serve's own public
// /oauth/callback URL, registered with the IdP as a redirect_uri.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// oidcClaims are the id_token claims oidcIdP reads. Generic OIDC has
// no tenant claim — the issuer URL is the closest universal proxy for
// tenancy, and oidcIdP stamps it into the VerifiedIdentity itself.
type oidcClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// oidcTokenVerifier is the seam over go-oidc's id-token verifier so
// oidcIdP's claim mapping and validation rules are testable without a
// live IdP. The real implementation wraps an *oidc.IDTokenVerifier;
// tests substitute a fake.
type oidcTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (oidcClaims, error)
}

// goOIDCGenericVerifier adapts a *oidc.IDTokenVerifier to
// oidcTokenVerifier by returning the generic-OIDC claims shape Kura
// reads.
type goOIDCGenericVerifier struct {
	v *oidc.IDTokenVerifier
}

func (g *goOIDCGenericVerifier) Verify(ctx context.Context, raw string) (oidcClaims, error) {
	tok, err := g.v.Verify(ctx, raw)
	if err != nil {
		return oidcClaims{}, err
	}
	var c oidcClaims
	if err := tok.Claims(&c); err != nil {
		return oidcClaims{}, fmt.Errorf("server: parsing oidc id_token claims: %w", err)
	}
	return c, nil
}

// oidcIdP is the generic OIDC IdentityProvider — anything that speaks
// OpenID Connect Discovery and signs id_tokens with a published JWKS.
// It runs OIDC discovery against the configured IssuerURL at
// construction time and from then on holds a verifier and an oauth2
// config. It holds no Kura logic beyond the email-verified rule and
// the issuer-as-tenant convention.
type oidcIdP struct {
	oauth     *oauth2.Config
	verifier  oidcTokenVerifier
	issuerURL string
}

// NewOIDCIdP runs OIDC discovery against the configured issuer and
// returns a ready generic-OIDC IdentityProvider.
//
// Discovery and the JWKS fetch happen here, so this constructor
// requires network access; callers should pass a context with a
// reasonable timeout.
func NewOIDCIdP(ctx context.Context, cfg OIDCConfig) (IdentityProvider, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("server: oidc idp: IssuerURL is required")
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("server: oidc discovery: %w", err)
	}
	return &oidcIdP{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email"},
		},
		verifier:  &goOIDCGenericVerifier{v: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})},
		issuerURL: cfg.IssuerURL,
	}, nil
}

// AuthCodeURL returns the IdP consent-screen URL for state.
func (o *oidcIdP) AuthCodeURL(state string) string {
	return o.oauth.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// Exchange swaps an auth code for a verified identity. The token
// exchange is a network call against the IdP; verification is
// JWKS-based against the cached signing keys.
func (o *oidcIdP) Exchange(ctx context.Context, code string) (VerifiedIdentity, error) {
	tok, err := o.oauth.Exchange(ctx, code)
	if err != nil {
		return VerifiedIdentity{}, fmt.Errorf("server: oidc code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return VerifiedIdentity{}, fmt.Errorf("server: oidc token carried no id_token")
	}
	return o.verifyAndMap(ctx, raw)
}

// verifyAndMap verifies the raw id_token and turns its claims into a
// VerifiedIdentity. The issuer URL the IdP was configured for becomes
// both the Tenant and Issuer — vanilla OIDC has no tenant claim, and
// the issuer URL is the closest universal proxy for tenancy.
//
// A token without email_verified=true is rejected: Kura requires the
// IdP to have proven the email, not merely transcribed it.
func (o *oidcIdP) verifyAndMap(ctx context.Context, rawIDToken string) (VerifiedIdentity, error) {
	c, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return VerifiedIdentity{}, fmt.Errorf("server: verifying oidc id_token: %w", err)
	}
	if !c.EmailVerified {
		return VerifiedIdentity{}, fmt.Errorf("server: oidc id_token has email_verified=false")
	}
	if c.Email == "" {
		return VerifiedIdentity{}, fmt.Errorf("server: oidc id_token has no email claim")
	}
	return VerifiedIdentity{
		Email:  strings.ToLower(c.Email),
		Tenant: o.issuerURL,
		Issuer: o.issuerURL,
	}, nil
}
