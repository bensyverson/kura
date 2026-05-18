package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/bensyverson/kura/internal/identity"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
)

// fakeGoogleAdminAPI stands in for the Admin SDK Directory client so
// googleDirectory's status mapping is testable without a live
// Workspace tenant.
type fakeGoogleAdminAPI struct {
	user *admin.User
	err  error
}

func (f *fakeGoogleAdminAPI) GetUser(_ context.Context, _ string) (*admin.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.user, nil
}

// An enabled (not-suspended) Workspace user maps to AccountActive.
func TestGoogleDirectoryReportsActiveForUnsuspendedUser(t *testing.T) {
	dir := &googleDirectory{api: &fakeGoogleAdminAPI{user: &admin.User{Suspended: false}}}
	got, err := dir.AccountStatus(context.Background(), "alex@client.com")
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	if got != identity.AccountActive {
		t.Errorf("AccountStatus = %q, want %q", got, identity.AccountActive)
	}
}

// A suspended Workspace user maps to AccountSuspended.
func TestGoogleDirectoryReportsSuspendedForSuspendedUser(t *testing.T) {
	dir := &googleDirectory{api: &fakeGoogleAdminAPI{user: &admin.User{Suspended: true}}}
	got, err := dir.AccountStatus(context.Background(), "alex@client.com")
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	if got != identity.AccountSuspended {
		t.Errorf("AccountStatus = %q, want %q", got, identity.AccountSuspended)
	}
}

// A 404 from the Admin SDK means the account does not exist in the
// directory — that is AccountAbsent, not a transport error.
func TestGoogleDirectoryReportsAbsentForNotFound(t *testing.T) {
	dir := &googleDirectory{api: &fakeGoogleAdminAPI{err: &googleapi.Error{Code: http.StatusNotFound, Message: "Resource Not Found: userKey"}}}
	got, err := dir.AccountStatus(context.Background(), "ghost@client.com")
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	if got != identity.AccountAbsent {
		t.Errorf("AccountStatus = %q, want %q", got, identity.AccountAbsent)
	}
}

// A non-404 API error is a real failure — it must propagate so callers
// can distinguish "no such account" from "we could not ask".
func TestGoogleDirectoryPropagatesTransportError(t *testing.T) {
	apiErr := &googleapi.Error{Code: http.StatusInternalServerError, Message: "backend error"}
	dir := &googleDirectory{api: &fakeGoogleAdminAPI{err: apiErr}}
	_, err := dir.AccountStatus(context.Background(), "alex@client.com")
	if err == nil {
		t.Fatal("expected an error when the Admin SDK returns 500")
	}
	var gerr *googleapi.Error
	if !errors.As(err, &gerr) || gerr.Code != http.StatusInternalServerError {
		t.Errorf("error chain did not preserve googleapi.Error{Code:500}: %v", err)
	}
}

// Non-API errors (network, context cancel) must also propagate as errors.
func TestGoogleDirectoryPropagatesNonAPIError(t *testing.T) {
	dir := &googleDirectory{api: &fakeGoogleAdminAPI{err: fmt.Errorf("dial tcp: i/o timeout")}}
	_, err := dir.AccountStatus(context.Background(), "alex@client.com")
	if err == nil {
		t.Fatal("expected an error when the underlying call fails")
	}
}

// googleDirectory must satisfy identity.Directory so it can be wired
// into the server config alongside any other directory implementation.
func TestGoogleDirectoryIsADirectory(t *testing.T) {
	var _ identity.Directory = &googleDirectory{api: &fakeGoogleAdminAPI{}}
}
