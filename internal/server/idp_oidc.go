package server

import (
	"context"
	"encoding/base64"
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

// oidcClaims are the id_token (and /userinfo) claims oidcIdP reads.
// EmailVerified is a *bool so an absent claim ("the IdP didn't say
// anything about verification") is distinguishable from an explicit
// false. The distinction is what gates the /userinfo fallback:
// minimal-id_token IdPs like Zitadel leave the claim out entirely and
// expect the relying party to call /userinfo for it.
type oidcClaims struct {
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
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

// userinfoFetcher is the seam over an OIDC /userinfo call. It is
// invoked only when the id_token lacked the email_verified claim — see
// oidcIdP.resolveIdentity. The real implementation wraps go-oidc's
// Provider.UserInfo; tests substitute a fake.
type userinfoFetcher interface {
	Fetch(ctx context.Context, token *oauth2.Token) (oidcClaims, error)
}

// goOIDCUserinfoFetcher adapts go-oidc's Provider.UserInfo to the
// userinfoFetcher seam. It unmarshals the response into the same
// oidcClaims shape used for id_tokens so the merge step downstream is
// symmetric. Presence of email_verified in the JSON is preserved by
// the *bool field — an IdP that simply doesn't return the claim leaves
// it nil, and the caller treats that as "still no proof".
type goOIDCUserinfoFetcher struct {
	p *oidc.Provider
}

func (g *goOIDCUserinfoFetcher) Fetch(ctx context.Context, tok *oauth2.Token) (oidcClaims, error) {
	ui, err := g.p.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		return oidcClaims{}, err
	}
	var c oidcClaims
	if err := ui.Claims(&c); err != nil {
		return oidcClaims{}, fmt.Errorf("server: parsing oidc userinfo claims: %w", err)
	}
	return c, nil
}

// oidcIdP is the generic OIDC IdentityProvider — anything that speaks
// OpenID Connect Discovery and signs id_tokens with a published JWKS.
// It runs OIDC discovery against the configured IssuerURL at
// construction time and from then on holds a verifier, an oauth2
// config, and a /userinfo fallback fetcher. It holds no Kura logic
// beyond the email-verified rule and the issuer-as-tenant convention.
type oidcIdP struct {
	oauth     *oauth2.Config
	verifier  oidcTokenVerifier
	userinfo  userinfoFetcher
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
		userinfo:  &goOIDCUserinfoFetcher{p: provider},
		issuerURL: cfg.IssuerURL,
	}, nil
}

// AuthCodeURL returns the IdP consent-screen URL for state.
func (o *oidcIdP) AuthCodeURL(state string) string {
	return o.oauth.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// Exchange swaps an auth code for a verified identity. The token
// exchange is a network call against the IdP; verification is
// JWKS-based against the cached signing keys, with a /userinfo
// fallback when the id_token lacked the email_verified claim.
func (o *oidcIdP) Exchange(ctx context.Context, code string) (VerifiedIdentity, error) {
	tok, err := o.oauth.Exchange(ctx, code)
	if err != nil {
		return VerifiedIdentity{}, fmt.Errorf("server: oidc code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return VerifiedIdentity{}, fmt.Errorf("server: oidc token carried no id_token")
	}
	return o.resolveIdentity(ctx, raw, tok)
}

// verifyAndMap is the unit-test seam used to exercise claim mapping in
// isolation. It runs the full resolution path with a nil token, so the
// /userinfo fallback is structurally unreachable — the unit tests
// assert only the verifier + claim-rule behavior.
func (o *oidcIdP) verifyAndMap(ctx context.Context, rawIDToken string) (VerifiedIdentity, error) {
	return o.resolveIdentity(ctx, rawIDToken, nil)
}

// resolveIdentity verifies the id_token, optionally calls /userinfo to
// fill in a missing email_verified claim, and applies the email-rule
// gate. It is the single entry point for both the production Exchange
// path and the unit-test claim-mapping path.
//
// The fallback only triggers when:
//   - the id_token's email_verified claim is absent (nil), AND
//   - a token is available to authenticate the /userinfo call, AND
//   - a userinfo fetcher is configured.
//
// An explicit email_verified=false from the id_token is a definitive
// negative from the IdP and is NOT re-checked against /userinfo;
// overriding it via a second endpoint would silently downgrade the
// IdP's assertion.
func (o *oidcIdP) resolveIdentity(ctx context.Context, rawIDToken string, tok *oauth2.Token) (VerifiedIdentity, error) {
	c, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return VerifiedIdentity{}, fmt.Errorf("server: verifying oidc id_token: %w", err)
	}
	if c.EmailVerified == nil && tok != nil && o.userinfo != nil {
		ui, err := o.userinfo.Fetch(ctx, tok)
		if err != nil {
			return VerifiedIdentity{}, fmt.Errorf("server: oidc userinfo fallback: %w", err)
		}
		c = mergeOIDCClaims(c, ui)
	}
	return o.applyClaimRules(c, rawIDToken)
}

// mergeOIDCClaims merges userinfo claims into a base set from the
// id_token. The userinfo source is authoritative for email_verified
// (that is the whole point of the fallback). For email, the id_token's
// value wins when present — userinfo only fills it in when the
// id_token didn't carry one.
func mergeOIDCClaims(base, ui oidcClaims) oidcClaims {
	out := base
	if ui.EmailVerified != nil {
		out.EmailVerified = ui.EmailVerified
	}
	if out.Email == "" {
		out.Email = ui.Email
	}
	return out
}

// applyClaimRules enforces the email-verified guarantee and the
// non-empty-email requirement, then projects the verified claims into
// a VerifiedIdentity stamped with the configured issuer as both tenant
// and issuer.
func (o *oidcIdP) applyClaimRules(c oidcClaims, rawIDToken string) (VerifiedIdentity, error) {
	if c.EmailVerified == nil || !*c.EmailVerified {
		return VerifiedIdentity{}, fmt.Errorf("server: oidc id_token has email_verified=false (raw claims: %s)", decodeJWTPayloadForDebug(rawIDToken))
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

// decodeJWTPayloadForDebug returns the JWT payload section of a JWS as
// a UTF-8 string for diagnostic embedding in error messages. The
// signature has already been verified by the time this is called; this
// is decode-for-display, not decode-for-trust. On any malformed input
// it returns a placeholder rather than an error — diagnostics must not
// shadow the underlying problem.
func decodeJWTPayloadForDebug(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return "<not a JWT>"
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "<unparseable payload>"
	}
	return string(payload)
}
