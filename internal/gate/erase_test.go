package gate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
)

// failingEraser is an Eraser that reports the shred failed. It stands in
// for a key-store outage so the audit trail of a failed erase can be
// asserted.
func failingEraser(err error) Eraser {
	return func(context.Context, []string) (int, error) {
		return 0, err
	}
}

// adminTokenWithTenant issues a token for a human admin bound to a tenant,
// so the audit trail's actor-tenant can be asserted — erasure records who,
// in which tenant, forgot which records.
func (h *harness) adminTokenWithTenant(t *testing.T, id, tenant string) string {
	t.Helper()
	h.roles.Assign(id, "admin")
	tok, err := h.auth.Issue(identity.Principal{
		Type:   identity.PrincipalConsultant,
		ID:     id,
		Email:  id,
		Tenant: tenant,
	}, time.Hour)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}
	return tok
}

// recordingEraser is a fake Eraser that records the ids it was asked to
// shred and returns a fixed count of destroyed DEKs.
func recordingEraser(got *[]string, shredded int) Eraser {
	return func(_ context.Context, ids []string) (int, error) {
		*got = append(*got, ids...)
		return shredded, nil
	}
}

// Erase is allowed for an admin: the eraser runs over exactly the named
// records, the shredded count comes back, and the full chain is audited —
// with one access event per erased record so the trail names exactly what
// was forgotten.
func TestEraseAllowedForAnAdmin(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	var erased []string
	res, err := h.gate.Erase(context.Background(), EraseRequest{
		Token:     tok,
		RecordIDs: []string{"r1", "r2"},
	}, recordingEraser(&erased, 3))
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if res.Principal.ID != "alice" {
		t.Errorf("principal.ID = %q, want alice", res.Principal.ID)
	}
	if res.Shredded != 3 {
		t.Errorf("Shredded = %d, want 3", res.Shredded)
	}
	if len(erased) != 2 || erased[0] != "r1" || erased[1] != "r2" {
		t.Errorf("eraser saw ids %v, want [r1 r2]", erased)
	}
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization, audit.KindAccess, audit.KindAccess}
	if len(kinds) != len(want) {
		t.Fatalf("audit kinds = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Errorf("audit kind[%d] = %v, want %v", i, kinds[i], want[i])
		}
	}
}

// Erase is denied for a non-admin: the eraser never runs, ErrDenied comes
// back, and only the authentication and the denied authorization are
// recorded — never an access event, because nothing was erased.
func TestEraseDeniedForANonAdmin(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "bob", "user")

	var erased []string
	_, err := h.gate.Erase(context.Background(), EraseRequest{
		Token:     tok,
		RecordIDs: []string{"r1"},
	}, recordingEraser(&erased, 0))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Erase err = %v, want ErrDenied", err)
	}
	if len(erased) != 0 {
		t.Errorf("eraser ran for an unauthorized principal: saw %v", erased)
	}
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization}
	if len(kinds) != len(want) || kinds[0] != want[0] || kinds[1] != want[1] {
		t.Errorf("audit kinds = %v, want %v", kinds, want)
	}
}

// Erasure is the admin role's capability alone — unlike the read-only
// review capability, an auditor may not erase. This pins erase to admin so
// a future policy change cannot silently widen who can forget a record.
func TestEraseDeniedForAnAuditor(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "eve", "auditor")

	var erased []string
	_, err := h.gate.Erase(context.Background(), EraseRequest{
		Token:     tok,
		RecordIDs: []string{"r1"},
	}, recordingEraser(&erased, 0))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Erase err = %v, want ErrDenied (erasure is admin-only, not an auditor capability)", err)
	}
	if len(erased) != 0 {
		t.Errorf("eraser ran for an auditor: saw %v", erased)
	}
}

// fqxtc/pTB + IxY: each erase emits an audit event carrying the acting
// principal, its tenant, and the records affected — and nothing else. The
// audit trail must name who, in which tenant, forgot which records, while
// carrying no key material and no erased plaintext (structurally
// impossible here: the recorder takes only ids and metadata).
func TestEraseAuditsPrincipalTenantAndRecordsOnly(t *testing.T) {
	h := newHarness(t)
	tok := h.adminTokenWithTenant(t, "alice@acme.example", "acme.example")

	var erased []string
	if _, err := h.gate.Erase(context.Background(), EraseRequest{
		Token:     tok,
		RecordIDs: []string{"r1", "r2"},
	}, recordingEraser(&erased, 2)); err != nil {
		t.Fatalf("Erase: %v", err)
	}

	events, err := h.store.Query(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatalf("querying audit store: %v", err)
	}
	var accessed []audit.Event
	for _, e := range events {
		if e.Kind == audit.KindAccess {
			accessed = append(accessed, e)
		}
	}
	if len(accessed) != 2 {
		t.Fatalf("recorded %d access events, want one per erased record (2)", len(accessed))
	}
	gotIDs := map[string]bool{}
	for _, e := range accessed {
		if e.Actor.ID != "alice@acme.example" {
			t.Errorf("access actor = %q, want the acting admin", e.Actor.ID)
		}
		if e.Actor.Tenant != "acme.example" {
			t.Errorf("access actor tenant = %q, want acme.example", e.Actor.Tenant)
		}
		if e.Action != string(AdminErase) {
			t.Errorf("access action = %q, want %q", e.Action, AdminErase)
		}
		if e.Resource.ID == "" {
			t.Error("access event names no record")
		}
		// No key material or plaintext leaks: an erase resource is a bare
		// record id, never a field name or value.
		if e.Resource.Entity != "" {
			t.Errorf("erase access event carries an entity %q; erasure is domain-agnostic and should name only the record id", e.Resource.Entity)
		}
		gotIDs[e.Resource.ID] = true
	}
	if !gotIDs["r1"] || !gotIDs["r2"] {
		t.Errorf("access events named %v, want both r1 and r2", gotIDs)
	}
}

// fqxtc/00A: a failed erase is distinguishable in the audit trail from a
// completed one. A completed erase records the authorization (allowed)
// followed by one access event per record; a failed erase records the
// authorization (allowed) but no access event — the shred did not happen,
// so no access is claimed. (The shred is atomic, so there is no partial
// state between these two.) This also stays distinct from a denial, whose
// authorization outcome is "denied".
func TestEraseFailureIsDistinguishableFromCompletion(t *testing.T) {
	h := newHarness(t)
	tok := h.adminTokenWithTenant(t, "alice@acme.example", "acme.example")

	_, err := h.gate.Erase(context.Background(), EraseRequest{
		Token:     tok,
		RecordIDs: []string{"r1", "r2"},
	}, failingEraser(errors.New("key store unavailable")))
	if err == nil {
		t.Fatal("Erase returned no error when the eraser failed")
	}

	events, qerr := h.store.Query(context.Background(), audit.Filter{})
	if qerr != nil {
		t.Fatalf("querying audit store: %v", qerr)
	}
	var authz *audit.Event
	accessCount := 0
	for i := range events {
		switch events[i].Kind {
		case audit.KindAuthorization:
			authz = &events[i]
		case audit.KindAccess:
			accessCount++
		}
	}
	if authz == nil {
		t.Fatal("a failed erase recorded no authorization event")
	}
	if authz.Outcome != audit.OutcomeAllowed {
		t.Errorf("failed-erase authorization outcome = %q, want allowed (the caller was authorized; the shred failed)", authz.Outcome)
	}
	if accessCount != 0 {
		t.Errorf("a failed erase recorded %d access events, want 0 — no access may be claimed for a shred that did not happen", accessCount)
	}
}
