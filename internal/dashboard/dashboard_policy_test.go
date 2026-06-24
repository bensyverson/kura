package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// viewerPolicy is a small two-entity, two-role policy the Cedar viewer
// tests render: an admin who reads PII and deletes, and an auditor who may
// only list and sees nothing in plaintext.
func viewerPolicy() cedar.Policy {
	return cedar.Policy{
		Roles: []cedar.Role{
			{Name: "admin", Description: "Full access to every entity and PII category."},
			{Name: "auditor", Description: "Read-only review; all PII masked."},
		},
		Grants: []cedar.Grant{
			{Role: "admin", Entity: "patient", Action: cedar.ActionRead, VisiblePII: []pii.Category{pii.CategoryPerson}},
			{Role: "admin", Entity: "patient", Action: cedar.ActionDelete},
			{Role: "admin", Entity: "invoice", Action: cedar.ActionRead, VisiblePII: []pii.Category{pii.CategoryAccountNumber}},
			{Role: "auditor", Entity: "patient", Action: cedar.ActionList},
		},
	}
}

func policyFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := newFakeRemote(t)
	fr.policy = viewerPolicy()
	return fr
}

// Criterion RZT: the policy renders as a structured grid built from the IR
// — its roles, entities, and actions all appear.
func TestPolicyPageRendersGridFromIR(t *testing.T) {
	fr := policyFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/policy"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /policy = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"admin", "auditor", "patient", "invoice", "read", "list", "delete"} {
		if !strings.Contains(body, want) {
			t.Errorf("policy grid missing %q; body:\n%s", want, body)
		}
	}
}

// Criterion Hy7: the viewer reads the same IR the future editor will edit —
// proven by faithfully reflecting per-role PII visibility from the grants:
// the admin's visible categories appear, the auditor sees none.
func TestPolicyPageReflectsPIIVisibilityFromIR(t *testing.T) {
	fr := policyFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/policy"))

	body := rec.Body.String()
	if !strings.Contains(body, string(pii.CategoryPerson)) {
		t.Errorf("admin's visible PII category not rendered; body:\n%s", body)
	}
	if !strings.Contains(body, string(pii.CategoryAccountNumber)) {
		t.Errorf("admin's invoice PII category not rendered; body:\n%s", body)
	}
}

// The description calls for plain-language statements alongside the grid,
// so a non-technical reviewer can read the policy in prose.
func TestPolicyPageHasPlainLanguageStatements(t *testing.T) {
	fr := policyFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/policy"))

	body := rec.Body.String()
	if !strings.Contains(body, "can read") {
		t.Errorf("policy page has no plain-language statements; body:\n%s", body)
	}
}

// V1 is a read-only viewer: free-form Cedar authoring stays a repo/PR
// activity, so the page exposes no editor.
func TestPolicyPageIsReadOnly(t *testing.T) {
	fr := policyFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/policy"))

	body := rec.Body.String()
	if strings.Contains(body, "<textarea") {
		t.Error("the Cedar viewer exposes an editor; V1 is read-only (authoring is repo/PR)")
	}
}

// For an append-only entity, update and delete are structurally
// unavailable, not merely ungranted: the viewer marks those cells N/A so
// the immutability is legible, while create stays a normal granted cell and
// a non-append-only entity's mutation cells are unaffected.
func TestBuildPolicyViewMarksAppendOnlyMutationsUnavailable(t *testing.T) {
	p := cedar.Policy{
		Roles: []cedar.Role{{Name: "admin"}},
		Grants: []cedar.Grant{
			{Role: "admin", Entity: "order", Action: cedar.ActionCreate},
			{Role: "admin", Entity: "order", Action: cedar.ActionRead},
			{Role: "admin", Entity: "customer", Action: cedar.ActionUpdate},
		},
	}
	view := buildPolicyView(&p, map[string]bool{"order": true})

	cellFor := func(entity, role string, action cedar.Action) policyCell {
		t.Helper()
		for _, e := range view.Entities {
			if e.Entity != entity {
				continue
			}
			for _, r := range e.Rows {
				if r.Role != role {
					continue
				}
				for i, a := range view.Actions {
					if a == string(action) {
						return r.Cells[i]
					}
				}
			}
		}
		t.Fatalf("no cell for %s/%s/%s", entity, role, action)
		return policyCell{}
	}

	for _, a := range []cedar.Action{cedar.ActionUpdate, cedar.ActionDelete} {
		c := cellFor("order", "admin", a)
		if !c.Unavailable {
			t.Errorf("order/%s should be N/A on an append-only entity", a)
		}
		if c.Granted {
			t.Errorf("order/%s should not be granted", a)
		}
	}
	if c := cellFor("order", "admin", cedar.ActionCreate); c.Unavailable || !c.Granted {
		t.Errorf("order/create should be a granted, available cell: %+v", c)
	}
	if c := cellFor("customer", "admin", cedar.ActionUpdate); c.Unavailable {
		t.Errorf("customer/update should not be N/A on a non-append-only entity")
	}
}

// End-to-end: the policy page renders N/A for an append-only entity's
// update/delete, derived from the manifest the page fetches alongside the
// policy.
func TestPolicyPageShowsNAForAppendOnly(t *testing.T) {
	fr := newFakeRemote(t)
	m := manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{
			{Name: "order", AppendOnly: true, Fields: []manifest.Field{{Name: "id", Type: manifest.FieldString}}},
		},
	}
	fr.schema = m
	fr.policy = *cedar.DefaultPolicy(&m)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/policy"))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /policy = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "N/A") {
		t.Errorf("append-only entity should render N/A for update/delete; body:\n%s", rec.Body.String())
	}
}

func TestPolicyPageReadsRemoteAndHidesToken(t *testing.T) {
	fr := policyFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "super-secret"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/policy"))

	if fr.hits == 0 {
		t.Fatal("policy page did not authenticate against the remote API")
	}
	if strings.Contains(rec.Body.String(), "super-secret") {
		t.Error("the bearer token leaked into the policy page HTML")
	}
}
