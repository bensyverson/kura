package gate

import (
	"context"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/audit"
)

// The gate exposes the policy IR it enforces, so an adapter can render
// the effective policy without re-deriving it.
func TestGateExposesItsPolicy(t *testing.T) {
	h := newHarness(t)
	if h.gate.Policy() == nil {
		t.Fatal("Gate.Policy returned nil")
	}
	if h.gate.Policy() != h.gate.evaluator.Policy() {
		t.Error("Gate.Policy is not the evaluator's policy")
	}
}

// noopDo is an admin operation that records whether it ran.
func noopDo(ran *bool) func(context.Context) error {
	return func(context.Context) error {
		*ran = true
		return nil
	}
}

// AdminManage — mutating the authorized list or role assignments — is
// allowed for an admin, runs the operation, and records the full chain:
// authentication, authorization, and the access that the op happened.
func TestAdminManageAllowedForAnAdmin(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	ran := false
	principal, err := h.gate.Admin(context.Background(), AdminRequest{
		Token:    tok,
		Action:   AdminManage,
		Resource: audit.Resource{Entity: "user", ID: "bob@client.com"},
	}, noopDo(&ran))
	if err != nil {
		t.Fatalf("Admin: %v", err)
	}
	if principal.ID != "alice" {
		t.Errorf("principal.ID = %q, want alice", principal.ID)
	}
	if !ran {
		t.Error("the admin operation did not run for an authorized admin")
	}
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization, audit.KindAccess}
	if len(kinds) != 3 || kinds[0] != want[0] || kinds[1] != want[1] || kinds[2] != want[2] {
		t.Errorf("audit kinds = %v, want %v", kinds, want)
	}
}

// AdminManage is denied for a non-admin: the operation never runs, and
// the denial is recorded as an authorization event.
func TestAdminManageDeniedForANonAdmin(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "bob", "user")

	ran := false
	_, err := h.gate.Admin(context.Background(), AdminRequest{
		Token:    tok,
		Action:   AdminManage,
		Resource: audit.Resource{Entity: "role", ID: "carol@client.com"},
	}, noopDo(&ran))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Admin err = %v, want ErrDenied", err)
	}
	if ran {
		t.Error("the admin operation ran for an unauthorized principal")
	}
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization}
	if len(kinds) != 2 || kinds[0] != want[0] || kinds[1] != want[1] {
		t.Errorf("audit kinds = %v, want %v (no access event for a denied op)", kinds, want)
	}
}

// AdminReview — reading effective policy, surfacing IdP mismatches — is
// access-review work, so the read-only auditor may do it.
func TestAdminReviewAllowedForAnAuditor(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "carol", "auditor")

	ran := false
	if _, err := h.gate.Admin(context.Background(), AdminRequest{
		Token:    tok,
		Action:   AdminReview,
		Resource: audit.Resource{Entity: "policy"},
	}, noopDo(&ran)); err != nil {
		t.Fatalf("Admin review as auditor: %v", err)
	}
	if !ran {
		t.Error("the review operation did not run for an auditor")
	}
}

// AdminReview is also allowed for an admin — admin is a superset.
func TestAdminReviewAllowedForAnAdmin(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")
	ran := false
	if _, err := h.gate.Admin(context.Background(), AdminRequest{
		Token: tok, Action: AdminReview, Resource: audit.Resource{Entity: "policy"},
	}, noopDo(&ran)); err != nil {
		t.Fatalf("Admin review as admin: %v", err)
	}
	if !ran {
		t.Error("the review operation did not run for an admin")
	}
}

// A plain user is neither admin nor auditor: AdminReview is denied.
func TestAdminReviewDeniedForAPlainUser(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "bob", "user")
	ran := false
	_, err := h.gate.Admin(context.Background(), AdminRequest{
		Token: tok, Action: AdminReview, Resource: audit.Resource{Entity: "policy"},
	}, noopDo(&ran))
	if !errors.Is(err, ErrDenied) {
		t.Errorf("Admin review as user err = %v, want ErrDenied", err)
	}
	if ran {
		t.Error("the review operation ran for an unauthorized user")
	}
}

// An unauthenticated admin request never runs the operation, and the
// failed authentication is recorded.
func TestAdminRejectsBadTokenBeforeRunning(t *testing.T) {
	h := newHarness(t)
	ran := false
	_, err := h.gate.Admin(context.Background(), AdminRequest{
		Token: "not-a-token", Action: AdminManage, Resource: audit.Resource{Entity: "user"},
	}, noopDo(&ran))
	if err == nil {
		t.Fatal("Admin with a bad token: want error, got nil")
	}
	if ran {
		t.Error("the admin operation ran for an unauthenticated request")
	}
	kinds := eventKinds(t, h.store)
	if len(kinds) != 1 || kinds[0] != audit.KindAuthentication {
		t.Errorf("audit kinds = %v, want one authentication event", kinds)
	}
}

// If the operation itself fails, Admin returns the error and records no
// access event — the op did not happen.
func TestAdminPropagatesOperationError(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	_, err := h.gate.Admin(context.Background(), AdminRequest{
		Token: tok, Action: AdminManage, Resource: audit.Resource{Entity: "user", ID: "bob@client.com"},
	}, func(context.Context) error {
		return errors.New("user store unreachable")
	})
	if err == nil {
		t.Fatal("Admin with a failing operation: want error, got nil")
	}
	for _, k := range eventKinds(t, h.store) {
		if k == audit.KindAccess {
			t.Error("an access event was recorded although the operation failed")
		}
	}
}
