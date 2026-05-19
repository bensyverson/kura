package server

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// boolp is a one-liner pointer to a bool, used in tests so oidcClaims
// literals can spell out "email_verified was present in the id_token
// with this value" vs "email_verified was absent" (nil).
//
//go:fix inline
func boolp(b bool) *bool { return new(b) }

// fakeOIDCVerifier stands in for go-oidc's id-token verifier so
// oidcIdP's claim mapping is testable without a live IdP and JWKS
// endpoint.
type fakeOIDCVerifier struct {
	claims oidcClaims
	err    error
}

func (f *fakeOIDCVerifier) Verify(_ context.Context, _ string) (oidcClaims, error) {
	if f.err != nil {
		return oidcClaims{}, f.err
	}
	return f.claims, nil
}

// fakeUserinfoFetcher stands in for a real OIDC /userinfo call so the
// id_token-lacks-email_verified fallback is testable without a live
// IdP. It records how many times it was invoked so tests can prove the
// fallback was (or wasn't) triggered.
type fakeUserinfoFetcher struct {
	claims oidcClaims
	err    error
	calls  int
}

func (f *fakeUserinfoFetcher) Fetch(_ context.Context, _ *oauth2.Token) (oidcClaims, error) {
	f.calls++
	if f.err != nil {
		return oidcClaims{}, f.err
	}
	return f.claims, nil
}

// A verified id_token's claims map onto VerifiedIdentity: email →
// Email (lowercased), and both Tenant and Issuer get the configured
// IssuerURL (vanilla OIDC has no tenant claim; the issuer URL is the
// closest universal proxy for tenancy).
func TestOIDCIdPMapsClaimsToVerifiedIdentity(t *testing.T) {
	v := &fakeOIDCVerifier{claims: oidcClaims{
		Email:         "Alex@ExampleFirm.com",
		EmailVerified: new(true),
	}}
	idp := &oidcIdP{
		issuerURL: "https://auth.examplefirm.com",
		verifier:  v,
	}
	got, err := idp.verifyAndMap(context.Background(), "raw")
	if err != nil {
		t.Fatalf("verifyAndMap: %v", err)
	}
	if got.Email != "alex@examplefirm.com" {
		t.Errorf("Email = %q, want alex@examplefirm.com (lowercased)", got.Email)
	}
	if got.Tenant != "https://auth.examplefirm.com" {
		t.Errorf("Tenant = %q, want the configured IssuerURL", got.Tenant)
	}
	if got.Issuer != "https://auth.examplefirm.com" {
		t.Errorf("Issuer = %q, want the configured IssuerURL", got.Issuer)
	}
}

// A token with email_verified=false has not had its email proven —
// generic OIDC providers vary in how they handle this, but Kura
// requires the verified-email guarantee. Reject the token.
func TestOIDCIdPRejectsUnverifiedEmail(t *testing.T) {
	v := &fakeOIDCVerifier{claims: oidcClaims{
		Email:         "alex@examplefirm.com",
		EmailVerified: new(false),
	}}
	idp := &oidcIdP{issuerURL: "https://auth.examplefirm.com", verifier: v}
	_, err := idp.verifyAndMap(context.Background(), "raw")
	if err == nil {
		t.Fatal("expected an error when email_verified is false")
	}
	if !strings.Contains(err.Error(), "email_verified") {
		t.Errorf("error %q should name the missing email_verified guarantee", err.Error())
	}
}

// A token with no email claim cannot identify a human — reject it.
// (Even if email_verified were true, an empty email is not an
// identity.)
func TestOIDCIdPRejectsTokenWithoutEmailClaim(t *testing.T) {
	v := &fakeOIDCVerifier{claims: oidcClaims{
		EmailVerified: new(true),
	}}
	idp := &oidcIdP{issuerURL: "https://auth.examplefirm.com", verifier: v}
	_, err := idp.verifyAndMap(context.Background(), "raw")
	if err == nil {
		t.Fatal("expected an error when the email claim is missing")
	}
}

// A verifier failure (bad signature, expired, unknown issuer) must
// propagate — Kura's mapping logic must not paper over a failed
// verification.
func TestOIDCIdPPropagatesVerifierError(t *testing.T) {
	boom := errors.New("signature invalid")
	v := &fakeOIDCVerifier{err: boom}
	idp := &oidcIdP{issuerURL: "https://auth.examplefirm.com", verifier: v}
	_, err := idp.verifyAndMap(context.Background(), "raw")
	if err == nil {
		t.Fatal("expected an error when the verifier rejects the token")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error chain should wrap the verifier's error, got %v", err)
	}
}

// On an email_verified=false rejection, the error must carry the
// id_token's decoded claims so an operator can diagnose which user
// signed in and which claims the IdP actually emitted. The Zitadel
// smoke surfaced this need: without the dump, "email_verified=false"
// reads identically whether the user is unverified, signed in as the
// wrong account, or the IdP simply omitted the email scope.
func TestOIDCIdPEmbedsClaimsInRejectionError(t *testing.T) {
	payload := `{"iss":"https://auth.examplefirm.com","sub":"unverified-user","email":"alex@examplefirm.com","email_verified":false}`
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	rawJWT := "header." + encoded + ".signature"

	v := &fakeOIDCVerifier{claims: oidcClaims{
		Email:         "alex@examplefirm.com",
		EmailVerified: new(false),
	}}
	idp := &oidcIdP{issuerURL: "https://auth.examplefirm.com", verifier: v}
	_, err := idp.verifyAndMap(context.Background(), rawJWT)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), payload) {
		t.Errorf("error %q does not embed the decoded JWT payload — operator cannot see what claims the IdP sent", err.Error())
	}
}

// decodeJWTPayloadForDebug returns a stable placeholder for inputs
// that are not a real JWT — diagnostics must not shadow the
// underlying problem with their own panic or error.
func TestDecodeJWTPayloadForDebugHandlesMalformed(t *testing.T) {
	for _, raw := range []string{"", "not-a-jwt", "only.two", "header.@@@notbase64@@@.sig"} {
		got := decodeJWTPayloadForDebug(raw)
		if got == "" {
			t.Errorf("decodeJWTPayloadForDebug(%q) returned an empty string — must always return a placeholder", raw)
		}
		if strings.HasPrefix(got, "{") {
			t.Errorf("decodeJWTPayloadForDebug(%q) = %q, must not look like real claims for malformed input", raw, got)
		}
	}
}

// AuthCodeURL produces a consent-screen URL at the configured authorize
// endpoint carrying the state the caller passed in.
func TestOIDCIdPAuthCodeURLEmbedsState(t *testing.T) {
	idp := &oidcIdP{
		issuerURL: "https://auth.examplefirm.com",
		oauth: &oauth2.Config{
			ClientID:    "client-id",
			RedirectURL: "https://kura.example/oauth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.examplefirm.com/oauth2/authorize",
				TokenURL: "https://auth.examplefirm.com/oauth2/token",
			},
			Scopes: []string{"openid", "email"},
		},
	}
	got := idp.AuthCodeURL("state-xyz")
	if !strings.HasPrefix(got, "https://auth.examplefirm.com/oauth2/authorize") {
		t.Errorf("AuthCodeURL = %q, want configured authorize endpoint prefix", got)
	}
	if !strings.Contains(got, "state=state-xyz") {
		t.Errorf("AuthCodeURL = %q, want state=state-xyz in the querystring", got)
	}
}

// Zitadel and other IdPs that default to "minimal id_token + rich
// userinfo" emit id_tokens that don't carry email_verified at all. When
// the id_token lacks the email_verified claim, oidcIdP must fall back to
// the /userinfo endpoint (authenticated with the access_token) to fetch
// it. A merged claim set with email_verified=true is then accepted.
func TestOIDCIdPFallsBackToUserinfoWhenIDTokenLacksEmailVerified(t *testing.T) {
	v := &fakeOIDCVerifier{claims: oidcClaims{
		Email:         "alex@examplefirm.com",
		EmailVerified: nil, // absent from the id_token
	}}
	ui := &fakeUserinfoFetcher{claims: oidcClaims{
		Email:         "alex@examplefirm.com",
		EmailVerified: new(true),
	}}
	idp := &oidcIdP{
		issuerURL: "https://auth.examplefirm.com",
		verifier:  v,
		userinfo:  ui,
	}
	got, err := idp.resolveIdentity(context.Background(), "raw", &oauth2.Token{AccessToken: "at"})
	if err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}
	if ui.calls != 1 {
		t.Errorf("expected exactly 1 /userinfo call, got %d", ui.calls)
	}
	if got.Email != "alex@examplefirm.com" {
		t.Errorf("Email = %q, want alex@examplefirm.com", got.Email)
	}
}

// If userinfo also reports email_verified=false (or never sets it), the
// caller has not proven the email — reject. The fallback is a permission
// to *look harder*, not a permission to *override* a definitive false.
func TestOIDCIdPRejectsWhenUserinfoStillLacksVerifiedEmail(t *testing.T) {
	v := &fakeOIDCVerifier{claims: oidcClaims{
		Email:         "alex@examplefirm.com",
		EmailVerified: nil,
	}}
	ui := &fakeUserinfoFetcher{claims: oidcClaims{
		Email:         "alex@examplefirm.com",
		EmailVerified: new(false),
	}}
	idp := &oidcIdP{
		issuerURL: "https://auth.examplefirm.com",
		verifier:  v,
		userinfo:  ui,
	}
	_, err := idp.resolveIdentity(context.Background(), "raw", &oauth2.Token{AccessToken: "at"})
	if err == nil {
		t.Fatal("expected rejection when userinfo also lacks a verified email")
	}
	if ui.calls != 1 {
		t.Errorf("expected exactly 1 /userinfo call, got %d", ui.calls)
	}
}

// If the id_token already carries a definitive email_verified claim
// (true or false), oidcIdP must NOT call /userinfo. An explicit false
// is a definitive statement from the IdP and overriding it via a second
// endpoint would be a downgrade; an explicit true means we already have
// the proof and a second call is wasted latency.
func TestOIDCIdPDoesNotCallUserinfoWhenIDTokenSettlesEmailVerified(t *testing.T) {
	for _, tc := range []struct {
		name string
		emv  *bool
	}{
		{"verified=true settles it", new(true)},
		{"verified=false settles it", new(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &fakeOIDCVerifier{claims: oidcClaims{
				Email:         "alex@examplefirm.com",
				EmailVerified: tc.emv,
			}}
			ui := &fakeUserinfoFetcher{err: errors.New("must not be called")}
			idp := &oidcIdP{
				issuerURL: "https://auth.examplefirm.com",
				verifier:  v,
				userinfo:  ui,
			}
			_, _ = idp.resolveIdentity(context.Background(), "raw", &oauth2.Token{AccessToken: "at"})
			if ui.calls != 0 {
				t.Errorf("expected zero /userinfo calls when id_token settles email_verified, got %d", ui.calls)
			}
		})
	}
}

// When the id_token is missing the email claim itself (Zitadel's
// minimal-id_token mode can produce this), the /userinfo response's
// email must fill it in. The merged identity carries that email
// (lowercased) on success.
func TestOIDCIdPMergesEmailFromUserinfoWhenIDTokenLacksIt(t *testing.T) {
	v := &fakeOIDCVerifier{claims: oidcClaims{
		Email:         "",
		EmailVerified: nil,
	}}
	ui := &fakeUserinfoFetcher{claims: oidcClaims{
		Email:         "Alex@ExampleFirm.com",
		EmailVerified: new(true),
	}}
	idp := &oidcIdP{
		issuerURL: "https://auth.examplefirm.com",
		verifier:  v,
		userinfo:  ui,
	}
	got, err := idp.resolveIdentity(context.Background(), "raw", &oauth2.Token{AccessToken: "at"})
	if err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}
	if got.Email != "alex@examplefirm.com" {
		t.Errorf("Email = %q, want alex@examplefirm.com (sourced from userinfo, lowercased)", got.Email)
	}
}

// A /userinfo fetch failure (network, 401, malformed JSON) must
// propagate as a verification error — Kura's identity-resolution path
// must not paper over the IdP being unreachable.
func TestOIDCIdPPropagatesUserinfoError(t *testing.T) {
	boom := errors.New("userinfo: 503 service unavailable")
	v := &fakeOIDCVerifier{claims: oidcClaims{
		Email:         "alex@examplefirm.com",
		EmailVerified: nil,
	}}
	ui := &fakeUserinfoFetcher{err: boom}
	idp := &oidcIdP{
		issuerURL: "https://auth.examplefirm.com",
		verifier:  v,
		userinfo:  ui,
	}
	_, err := idp.resolveIdentity(context.Background(), "raw", &oauth2.Token{AccessToken: "at"})
	if err == nil {
		t.Fatal("expected an error when userinfo fetch fails")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error chain should wrap the userinfo fetcher's error, got %v", err)
	}
}
