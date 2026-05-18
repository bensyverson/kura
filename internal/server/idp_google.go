package server

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

// GoogleConfig is the Google OAuth client configuration kura serve needs
// to broker sign-in. The client ID and secret are issued by Google for
// the deployment; RedirectURL is kura serve's own public
// /oauth/callback URL, registered with Google as the redirect_uri.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// googleIdP is the real Google IdentityProvider: a thin adapter over
// x/oauth2 for the code exchange and api/idtoken for id_token
// verification. It holds no Kura logic — the trust decision belongs to
// identity.TenantTrust and the token model to identity.Authenticator.
// This is the untestable seam by design: the fake in the tests stands
// in for exactly this type.
type googleIdP struct {
	oauth    *oauth2.Config
	clientID string
}

// NewGoogleIdP builds the real Google IdentityProvider from cfg. The
// "openid" and "email" scopes are the minimum that yields an id_token
// carrying the email and `hd` hosted-domain claims Kura's trust decision
// needs — nothing more is requested.
func NewGoogleIdP(cfg GoogleConfig) IdentityProvider {
	return &googleIdP{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"openid", "email"},
		},
		clientID: cfg.ClientID,
	}
}

// AuthCodeURL returns the Google consent-screen URL for state.
func (g *googleIdP) AuthCodeURL(state string) string {
	return g.oauth.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// googleIssuer is the canonical OIDC issuer URL Google publishes in its
// id_tokens — used as the Issuer of every VerifiedIdentity this
// authenticator returns.
const googleIssuer = "https://accounts.google.com"

// Exchange swaps an auth code for a verified Workspace identity: it
// trades the code for a token, pulls the id_token out, verifies its
// signature and audience against Google, and returns the email and `hd`
// claim. An id_token without a verified email or an `hd` claim is
// rejected — a Kura principal must come from a verified Workspace
// identity, never a bare Gmail account.
func (g *googleIdP) Exchange(ctx context.Context, code string) (VerifiedIdentity, error) {
	tok, err := g.oauth.Exchange(ctx, code)
	if err != nil {
		return VerifiedIdentity{}, fmt.Errorf("server: google code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return VerifiedIdentity{}, fmt.Errorf("server: google token carried no id_token")
	}
	payload, err := idtoken.Validate(ctx, raw, g.clientID)
	if err != nil {
		return VerifiedIdentity{}, fmt.Errorf("server: verifying id_token: %w", err)
	}
	if verified, _ := payload.Claims["email_verified"].(bool); !verified {
		return VerifiedIdentity{}, fmt.Errorf("server: id_token email is not verified")
	}
	email, _ := payload.Claims["email"].(string)
	domain, _ := payload.Claims["hd"].(string)
	if email == "" || domain == "" {
		return VerifiedIdentity{}, fmt.Errorf("server: id_token missing email or hd (hosted-domain) claim")
	}
	return VerifiedIdentity{Email: email, Tenant: domain, Issuer: googleIssuer}, nil
}
