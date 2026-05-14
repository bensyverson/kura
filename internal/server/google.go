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

// googleAuthenticator is the real GoogleAuthenticator: a thin adapter
// over x/oauth2 for the code exchange and api/idtoken for id_token
// verification. It holds no Kura logic — the trust decision belongs to
// identity.DomainTrust and the token model to identity.Authenticator.
// This is the untestable seam by design: the fake in the tests stands in
// for exactly this type.
type googleAuthenticator struct {
	oauth    *oauth2.Config
	clientID string
}

// NewGoogleAuthenticator builds the real authenticator from cfg. The
// "openid" and "email" scopes are the minimum that yields an id_token
// carrying the email and `hd` hosted-domain claims Kura's trust decision
// needs — nothing more is requested.
func NewGoogleAuthenticator(cfg GoogleConfig) GoogleAuthenticator {
	return &googleAuthenticator{
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
func (g *googleAuthenticator) AuthCodeURL(state string) string {
	return g.oauth.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// Exchange swaps an auth code for a verified Workspace identity: it
// trades the code for a token, pulls the id_token out, verifies its
// signature and audience against Google, and returns the email and `hd`
// claim. An id_token without a verified email or an `hd` claim is
// rejected — a Kura principal must come from a verified Workspace
// identity, never a bare Gmail account.
func (g *googleAuthenticator) Exchange(ctx context.Context, code string) (WorkspaceIdentity, error) {
	tok, err := g.oauth.Exchange(ctx, code)
	if err != nil {
		return WorkspaceIdentity{}, fmt.Errorf("server: google code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return WorkspaceIdentity{}, fmt.Errorf("server: google token carried no id_token")
	}
	payload, err := idtoken.Validate(ctx, raw, g.clientID)
	if err != nil {
		return WorkspaceIdentity{}, fmt.Errorf("server: verifying id_token: %w", err)
	}
	if verified, _ := payload.Claims["email_verified"].(bool); !verified {
		return WorkspaceIdentity{}, fmt.Errorf("server: id_token email is not verified")
	}
	email, _ := payload.Claims["email"].(string)
	domain, _ := payload.Claims["hd"].(string)
	if email == "" || domain == "" {
		return WorkspaceIdentity{}, fmt.Errorf("server: id_token missing email or hd (hosted-domain) claim")
	}
	return WorkspaceIdentity{Email: email, Domain: domain}, nil
}
