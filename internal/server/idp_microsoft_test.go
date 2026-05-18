package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// fakeMSVerifier stands in for go-oidc's id-token verifier so
// microsoftIdP's claim mapping is testable without a live Entra tenant.
type fakeMSVerifier struct {
	claims microsoftClaims
	err    error
}

func (f *fakeMSVerifier) Verify(_ context.Context, _ string) (microsoftClaims, error) {
	if f.err != nil {
		return microsoftClaims{}, f.err
	}
	return f.claims, nil
}

// A verified Microsoft id_token's claims map onto VerifiedIdentity:
// preferred_username → Email (lowercased), tid → Tenant, iss → Issuer.
func TestMicrosoftIdPMapsClaimsToVerifiedIdentity(t *testing.T) {
	v := &fakeMSVerifier{claims: microsoftClaims{
		PreferredUsername: "Alex@ExampleFirm.com",
		TID:               "tenant-abc",
		Iss:               "https://login.microsoftonline.com/tenant-abc/v2.0",
	}}
	idp := &microsoftIdP{verifier: v}
	got, err := idp.verifyAndMap(context.Background(), "raw")
	if err != nil {
		t.Fatalf("verifyAndMap: %v", err)
	}
	if got.Email != "alex@examplefirm.com" {
		t.Errorf("Email = %q, want alex@examplefirm.com (lowercased)", got.Email)
	}
	if got.Tenant != "tenant-abc" {
		t.Errorf("Tenant = %q, want tenant-abc", got.Tenant)
	}
	if got.Issuer != "https://login.microsoftonline.com/tenant-abc/v2.0" {
		t.Errorf("Issuer = %q, want the iss claim verbatim", got.Issuer)
	}
}

// Personal Microsoft accounts sometimes omit preferred_username; the
// email claim is the documented fallback.
func TestMicrosoftIdPFallsBackToEmailClaim(t *testing.T) {
	v := &fakeMSVerifier{claims: microsoftClaims{
		Email: "bob@client.example",
		TID:   "tenant-xyz",
		Iss:   "https://login.microsoftonline.com/tenant-xyz/v2.0",
	}}
	idp := &microsoftIdP{verifier: v}
	got, err := idp.verifyAndMap(context.Background(), "raw")
	if err != nil {
		t.Fatalf("verifyAndMap: %v", err)
	}
	if got.Email != "bob@client.example" {
		t.Errorf("Email = %q, want bob@client.example", got.Email)
	}
}

// A token with no tid claim is anonymous-shaped — a /common deployment
// must not accept it, because TenantTrust has nothing to decide on. A
// single-tenant deployment never produces such a token in the first
// place, but defense in depth: reject it here.
func TestMicrosoftIdPRejectsTokenWithoutTID(t *testing.T) {
	v := &fakeMSVerifier{claims: microsoftClaims{
		PreferredUsername: "alex@examplefirm.com",
		Iss:               "https://login.microsoftonline.com/common/v2.0",
	}}
	idp := &microsoftIdP{verifier: v}
	_, err := idp.verifyAndMap(context.Background(), "raw")
	if err == nil {
		t.Fatal("expected an error when tid is missing")
	}
	if !strings.Contains(err.Error(), "tid") {
		t.Errorf("error %q should name the missing tid claim", err.Error())
	}
}

// A token with neither preferred_username nor email cannot identify a
// human — reject it. A Kura principal must carry an email.
func TestMicrosoftIdPRejectsTokenWithoutEmailClaim(t *testing.T) {
	v := &fakeMSVerifier{claims: microsoftClaims{
		TID: "tenant-abc",
		Iss: "https://login.microsoftonline.com/tenant-abc/v2.0",
	}}
	idp := &microsoftIdP{verifier: v}
	_, err := idp.verifyAndMap(context.Background(), "raw")
	if err == nil {
		t.Fatal("expected an error when no email/preferred_username claim is present")
	}
}

// A verifier failure (bad signature, expired token, unknown issuer)
// must propagate — Kura's mapping logic must not paper over a failed
// verification.
func TestMicrosoftIdPPropagatesVerifierError(t *testing.T) {
	boom := errors.New("signature invalid")
	v := &fakeMSVerifier{err: boom}
	idp := &microsoftIdP{verifier: v}
	_, err := idp.verifyAndMap(context.Background(), "raw")
	if err == nil {
		t.Fatal("expected an error when the verifier rejects the token")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error chain should wrap the verifier's error, got %v", err)
	}
}

// AuthCodeURL produces a Microsoft-authorize URL carrying the state
// the caller passed in.
func TestMicrosoftIdPAuthCodeURLEmbedsState(t *testing.T) {
	idp := &microsoftIdP{oauth: &oauth2.Config{
		ClientID:    "client-id",
		RedirectURL: "https://kura.example/oauth/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/tenant-abc/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/tenant-abc/oauth2/v2.0/token",
		},
		Scopes: []string{"openid", "email", "profile"},
	}}
	got := idp.AuthCodeURL("state-xyz")
	if !strings.HasPrefix(got, "https://login.microsoftonline.com/tenant-abc/oauth2/v2.0/authorize") {
		t.Errorf("AuthCodeURL = %q, want microsoft authorize endpoint prefix", got)
	}
	if !strings.Contains(got, "state=state-xyz") {
		t.Errorf("AuthCodeURL = %q, want state=state-xyz in the querystring", got)
	}
}
