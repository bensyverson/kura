package gate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// testManifest is a one-entity manifest: a patient with a person-name
// field, an email field, and an account-number field (high-sensitivity).
func testManifest() *manifest.Manifest {
	return &manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{{
			Name: "patient",
			Fields: []manifest.Field{
				{Name: "full_name", Type: manifest.FieldString, PII: new(pii.CategoryPerson)},
				{Name: "email", Type: manifest.FieldString, PII: new(pii.CategoryEmail)},
				{Name: "account", Type: manifest.FieldString, PII: new(pii.CategoryAccountNumber)},
			},
		}},
	}
}

// harness bundles a Gate with the collaborators a test needs to reach.
type harness struct {
	gate     *Gate
	auth     *identity.Authenticator
	roles    *MapRoleResolver
	store    *audit.MemStore
	detector *pii.FakeDetector
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	m := testManifest()
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	roles := NewMapRoleResolver()
	store := audit.NewMemStore()
	detector := pii.NewFakeDetector().
		Register("Jane Doe", pii.CategoryPerson, 0.99).
		Register("jane@example.com", pii.CategoryEmail, 0.99).
		Register("ACCT-555", pii.CategoryAccountNumber, 0.99).
		Register("555-1234", pii.CategoryPhone, 0.99)

	g, err := New(auth, evaluator, roles, m, pii.NewScanner(detector), audit.NewRecorder(store))
	if err != nil {
		t.Fatalf("New gate: %v", err)
	}
	return &harness{gate: g, auth: auth, roles: roles, store: store, detector: detector}
}

func (h *harness) token(t *testing.T, principalID string, roles ...string) string {
	t.Helper()
	p := identity.Principal{Type: identity.PrincipalService, ID: principalID}
	h.roles.Assign(principalID, roles...)
	tok, err := h.auth.Issue(p, time.Hour)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}
	return tok
}

func patientFetcher() Fetcher {
	return func(_ context.Context) (map[string]string, error) {
		return map[string]string{
			"full_name": "Jane Doe",
			"email":     "jane@example.com",
			"account":   "ACCT-555",
		}, nil
	}
}

func eventKinds(t *testing.T, store *audit.MemStore) []audit.Kind {
	t.Helper()
	events, err := store.Query(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatalf("querying audit store: %v", err)
	}
	kinds := make([]audit.Kind, len(events))
	for i, e := range events {
		kinds[i] = e.Kind
	}
	return kinds
}

func TestAccessRunsTheFullChainForAnAuthorizedAdmin(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	res, err := h.gate.Access(context.Background(), AccessRequest{
		Token: tok, Action: cedar.ActionRead, Entity: "patient", ResourceID: "p1",
	}, patientFetcher())
	if err != nil {
		t.Fatalf("Access: %v", err)
	}
	if res.Principal.ID != "alice" {
		t.Errorf("result Principal.ID = %q, want %q", res.Principal.ID, "alice")
	}
	// admin sees every category in plaintext.
	if res.Fields["full_name"] != "Jane Doe" {
		t.Errorf("admin full_name = %q, want plaintext", res.Fields["full_name"])
	}
	if res.Fields["account"] != "ACCT-555" {
		t.Errorf("admin account = %q, want plaintext", res.Fields["account"])
	}
	// authn -> authz -> access all recorded, in order.
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization, audit.KindAccess}
	if len(kinds) != 3 || kinds[0] != want[0] || kinds[1] != want[1] || kinds[2] != want[2] {
		t.Errorf("audit kinds = %v, want %v", kinds, want)
	}
}

func TestAccessMasksHighSensitivityCategoriesForAUser(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "bob", "user")

	res, err := h.gate.Access(context.Background(), AccessRequest{
		Token: tok, Action: cedar.ActionRead, Entity: "patient", ResourceID: "p1",
	}, patientFetcher())
	if err != nil {
		t.Fatalf("Access: %v", err)
	}
	// user sees person and email (not high-sensitivity)...
	if res.Fields["full_name"] != "Jane Doe" {
		t.Errorf("user full_name = %q, want plaintext", res.Fields["full_name"])
	}
	if res.Fields["email"] != "jane@example.com" {
		t.Errorf("user email = %q, want plaintext", res.Fields["email"])
	}
	// ...but the account number (high-sensitivity) is redacted.
	if res.Fields["account"] != Redacted {
		t.Errorf("user account = %q, want %q", res.Fields["account"], Redacted)
	}
}

func TestAccessMasksEveryCategoryForAnAuditor(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "carol", "auditor")

	res, err := h.gate.Access(context.Background(), AccessRequest{
		Token: tok, Action: cedar.ActionRead, Entity: "patient", ResourceID: "p1",
	}, patientFetcher())
	if err != nil {
		t.Fatalf("Access: %v", err)
	}
	for _, field := range []string{"full_name", "email", "account"} {
		if res.Fields[field] != Redacted {
			t.Errorf("auditor %s = %q, want %q", field, res.Fields[field], Redacted)
		}
	}
}

func TestAccessRedactsSpanLevelAndIsDriftSafe(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "bob", "user")

	// The fetched name carries a phone number too — a category the
	// manifest never declared for this entity, so the authorization
	// decision never classified it. It must still be masked: a category
	// the decision did not make visible is not visible.
	fetch := func(_ context.Context) (map[string]string, error) {
		return map[string]string{"full_name": "Jane Doe 555-1234"}, nil
	}
	res, err := h.gate.Access(context.Background(), AccessRequest{
		Token: tok, Action: cedar.ActionRead, Entity: "patient", ResourceID: "p1",
	}, fetch)
	if err != nil {
		t.Fatalf("Access: %v", err)
	}
	got := res.Fields["full_name"]
	// "Jane Doe" (person, visible to user) stays; "555-1234" (phone,
	// undeclared/undecided) is redacted in place.
	if got != "Jane Doe "+Redacted {
		t.Errorf("full_name = %q, want %q", got, "Jane Doe "+Redacted)
	}
}

func TestAccessRejectsAnInvalidToken(t *testing.T) {
	h := newHarness(t)
	fetched := false
	fetch := func(_ context.Context) (map[string]string, error) {
		fetched = true
		return nil, nil
	}

	_, err := h.gate.Access(context.Background(), AccessRequest{
		Token: "not-a-real-token", Action: cedar.ActionRead, Entity: "patient", ResourceID: "p1",
	}, fetch)
	if err == nil {
		t.Fatal("Access with invalid token: want error, got nil")
	}
	if fetched {
		t.Error("fetcher was invoked for an unauthenticated request")
	}
	// The failed authentication is itself recorded.
	kinds := eventKinds(t, h.store)
	if len(kinds) != 1 || kinds[0] != audit.KindAuthentication {
		t.Errorf("audit kinds = %v, want one authentication event", kinds)
	}
}

func TestAccessDeniedAuthorizationReturnsErrDeniedAndDoesNotFetch(t *testing.T) {
	h := newHarness(t)
	// An auditor may read/list but not delete.
	tok := h.token(t, "carol", "auditor")
	fetched := false
	fetch := func(_ context.Context) (map[string]string, error) {
		fetched = true
		return nil, nil
	}

	_, err := h.gate.Access(context.Background(), AccessRequest{
		Token: tok, Action: cedar.ActionDelete, Entity: "patient", ResourceID: "p1",
	}, fetch)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Access denied err = %v, want ErrDenied", err)
	}
	if fetched {
		t.Error("fetcher was invoked for a denied request")
	}
	// authn allowed, authz denied, no access event.
	kinds := eventKinds(t, h.store)
	want := []audit.Kind{audit.KindAuthentication, audit.KindAuthorization}
	if len(kinds) != 2 || kinds[0] != want[0] || kinds[1] != want[1] {
		t.Errorf("audit kinds = %v, want %v", kinds, want)
	}
}

func TestAccessUnknownEntityReturnsError(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")

	_, err := h.gate.Access(context.Background(), AccessRequest{
		Token: tok, Action: cedar.ActionRead, Entity: "ghost", ResourceID: "x",
	}, patientFetcher())
	if !errors.Is(err, ErrUnknownEntity) {
		t.Errorf("Access unknown entity err = %v, want ErrUnknownEntity", err)
	}
}

func TestAccessPropagatesFetchError(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "alice", "admin")
	fetch := func(_ context.Context) (map[string]string, error) {
		return nil, errors.New("database unreachable")
	}

	_, err := h.gate.Access(context.Background(), AccessRequest{
		Token: tok, Action: cedar.ActionRead, Entity: "patient", ResourceID: "p1",
	}, fetch)
	if err == nil {
		t.Fatal("Access with failing fetch: want error, got nil")
	}
	// authn and authz happened; the access did not, so no access event.
	for _, k := range eventKinds(t, h.store) {
		if k == audit.KindAccess {
			t.Error("an access event was recorded although the fetch failed")
		}
	}
}

// failingStore is an audit.Store whose Append always errors.
type failingStore struct{}

func (failingStore) Append(context.Context, audit.Event) error {
	return errors.New("audit store down")
}
func (failingStore) Query(context.Context, audit.Filter) ([]audit.Event, error) {
	return nil, nil
}
func (failingStore) Subscribe(context.Context) <-chan audit.Event {
	ch := make(chan audit.Event)
	close(ch)
	return ch
}

func TestAccessFailsClosedWhenAuditingFails(t *testing.T) {
	m := testManifest()
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		t.Fatalf("building evaluator: %v", err)
	}
	auth := identity.NewAuthenticator([]byte("test-signing-secret"))
	roles := NewMapRoleResolver()
	roles.Assign("alice", "admin")
	detector := pii.NewFakeDetector()
	g, err := New(auth, evaluator, roles, m, pii.NewScanner(detector), audit.NewRecorder(failingStore{}))
	if err != nil {
		t.Fatalf("New gate: %v", err)
	}
	tok, _ := auth.Issue(identity.Principal{Type: identity.PrincipalService, ID: "alice"}, time.Hour)

	res, err := g.Access(context.Background(), AccessRequest{
		Token: tok, Action: cedar.ActionRead, Entity: "patient", ResourceID: "p1",
	}, patientFetcher())
	if err == nil {
		t.Fatal("Access with failing audit: want error, got nil")
	}
	if res.Fields != nil {
		t.Errorf("Access with failing audit returned fields %v, want nil — must fail closed", res.Fields)
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	m := testManifest()
	evaluator, _ := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	auth := identity.NewAuthenticator([]byte("s"))
	scanner := pii.NewScanner(pii.NewFakeDetector())
	recorder := audit.NewRecorder(audit.NewMemStore())
	roles := NewMapRoleResolver()

	if _, err := New(nil, evaluator, roles, m, scanner, recorder); !errors.Is(err, ErrMissingDependency) {
		t.Errorf("New with nil auth err = %v, want ErrMissingDependency", err)
	}
	if _, err := New(auth, evaluator, roles, m, scanner, nil); !errors.Is(err, ErrMissingDependency) {
		t.Errorf("New with nil recorder err = %v, want ErrMissingDependency", err)
	}
}
