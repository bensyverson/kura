package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/identity"
	"golang.org/x/oauth2"
)

// fakeGraphAPI stands in for the Microsoft Graph users.get call so
// microsoftDirectory's status mapping is testable without a live Entra
// tenant.
type fakeGraphAPI struct {
	user *microsoftDirectoryUser
	err  error
}

func (f *fakeGraphAPI) GetUser(_ context.Context, _ string) (*microsoftDirectoryUser, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.user, nil
}

// An enabled (accountEnabled=true) Entra user maps to AccountActive.
func TestMicrosoftDirectoryReportsActiveForEnabledUser(t *testing.T) {
	dir := &microsoftDirectory{api: &fakeGraphAPI{user: &microsoftDirectoryUser{AccountEnabled: true}}}
	got, err := dir.AccountStatus(context.Background(), "alex@client.com")
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	if got != identity.AccountActive {
		t.Errorf("AccountStatus = %q, want %q", got, identity.AccountActive)
	}
}

// A disabled (accountEnabled=false) Entra user maps to AccountSuspended:
// Entra's term is "blocked sign-in," which is the same access-revocation
// semantics as Google's "suspended."
func TestMicrosoftDirectoryReportsSuspendedForDisabledUser(t *testing.T) {
	dir := &microsoftDirectory{api: &fakeGraphAPI{user: &microsoftDirectoryUser{AccountEnabled: false}}}
	got, err := dir.AccountStatus(context.Background(), "alex@client.com")
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	if got != identity.AccountSuspended {
		t.Errorf("AccountStatus = %q, want %q", got, identity.AccountSuspended)
	}
}

// A 404 from Graph means the directory has no such user — AccountAbsent,
// not an error.
func TestMicrosoftDirectoryReportsAbsentForNotFound(t *testing.T) {
	dir := &microsoftDirectory{api: &fakeGraphAPI{err: errMicrosoftUserNotFound}}
	got, err := dir.AccountStatus(context.Background(), "ghost@client.com")
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	if got != identity.AccountAbsent {
		t.Errorf("AccountStatus = %q, want %q", got, identity.AccountAbsent)
	}
}

// A non-404 error must propagate so callers can distinguish "no such
// account" from "we could not ask."
func TestMicrosoftDirectoryPropagatesTransportError(t *testing.T) {
	dir := &microsoftDirectory{api: &fakeGraphAPI{err: fmt.Errorf("graph: 500 backend error")}}
	_, err := dir.AccountStatus(context.Background(), "alex@client.com")
	if err == nil {
		t.Fatal("expected an error when Graph returns 500")
	}
}

// microsoftDirectory must satisfy identity.Directory.
func TestMicrosoftDirectoryIsADirectory(t *testing.T) {
	var _ identity.Directory = &microsoftDirectory{api: &fakeGraphAPI{}}
}

// The HTTP-level Graph adapter must request exactly accountEnabled,
// strip the surrounding URL/auth, and parse the JSON shape Graph
// returns for GET /users/{email}?$select=accountEnabled. A 200 with
// accountEnabled=false must round-trip to a *microsoftDirectoryUser
// with AccountEnabled=false.
func TestGraphHTTPAdapterRoundTripsAccountEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1.0/users/") {
			t.Errorf("path = %q, want /v1.0/users/<email>", r.URL.Path)
		}
		if got := r.URL.Query().Get("$select"); got != "accountEnabled" {
			t.Errorf("$select = %q, want accountEnabled", got)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q, want Bearer test-token", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accountEnabled": false}`))
	}))
	defer srv.Close()

	api := &graphHTTPAPI{
		client:  srv.Client(),
		baseURL: srv.URL,
		token:   oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}),
	}
	u, err := api.GetUser(context.Background(), "alex@client.com")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u.AccountEnabled {
		t.Errorf("AccountEnabled = true, want false")
	}
}

// A 404 from Graph (the documented response when the user does not
// exist) round-trips to errMicrosoftUserNotFound so AccountStatus can
// turn it into AccountAbsent. Any other non-2xx is a transport error.
func TestGraphHTTPAdapterMapsNotFoundSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"Request_ResourceNotFound","message":"Resource 'ghost@client.com' does not exist."}}`))
	}))
	defer srv.Close()

	api := &graphHTTPAPI{
		client:  srv.Client(),
		baseURL: srv.URL,
		token:   oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}),
	}
	_, err := api.GetUser(context.Background(), "ghost@client.com")
	if !errors.Is(err, errMicrosoftUserNotFound) {
		t.Fatalf("err = %v, want errMicrosoftUserNotFound", err)
	}
}
