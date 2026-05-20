package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
)

// browserManifest is a two-entity schema with a relationship in each
// direction and a PII-tagged field, used to prove the browser is purely
// manifest-driven: nothing in the dashboard names "customer" or "order".
func browserManifest() manifest.Manifest {
	person := pii.CategoryPerson
	return manifest.Manifest{
		Version: "1",
		Entities: []manifest.Entity{
			{
				Name:        "customer",
				Description: "A person whose data the client holds.",
				Fields: []manifest.Field{
					{Name: "id", Type: manifest.FieldString},
					{Name: "full_name", Type: manifest.FieldString, PII: &person},
				},
				Relationships: []manifest.Relationship{
					{Name: "orders", Kind: manifest.RelationshipMany, Target: "order"},
				},
			},
			{
				Name:        "order",
				Description: "A single purchase.",
				Fields: []manifest.Field{
					{Name: "id", Type: manifest.FieldString},
					{Name: "total_cents", Type: manifest.FieldInteger},
				},
				Relationships: []manifest.Relationship{
					{Name: "customer", Kind: manifest.RelationshipOne, Target: "customer"},
				},
			},
		},
	}
}

func dataFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := newFakeRemote(t)
	fr.schema = browserManifest()
	fr.records = map[string][]recordWire{
		"customer": {
			{ID: "c1", Fields: map[string]string{"id": "c1", "full_name": "[redacted]"}},
			{ID: "c2", Fields: map[string]string{"id": "c2", "full_name": "Dana Public"}},
		},
		"order": {
			{ID: "o1", Fields: map[string]string{"id": "o1", "total_cents": "1299"}},
		},
	}
	return fr
}

// The entity index lists every entity in the manifest — both, by name, with
// no entity-specific code in the dashboard.
func TestDataIndexListsEntitiesFromManifest(t *testing.T) {
	fr := dataFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/data"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /data = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"customer", "order", "/data/customer", "/data/order"} {
		if !strings.Contains(body, want) {
			t.Errorf("entity index missing %q; body:\n%s", want, body)
		}
	}
}

// An entity's list page renders its records with a column per manifest
// field, and links each record to its detail page.
func TestDataListRendersRecordsAndColumns(t *testing.T) {
	fr := dataFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/data/customer"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /data/customer = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"full_name",         // column header from the manifest
		"Dana Public",       // an unmasked value passes through
		"/data/customer/c1", // a record link
		"/data/customer/c2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("entity list missing %q; body:\n%s", want, body)
		}
	}
}

// The list page renders the entity's relationships as links to the target
// entity's browser — "follow relationships" with no join key required.
func TestDataListRendersRelationshipLinks(t *testing.T) {
	fr := dataFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/data/customer"))

	body := rec.Body.String()
	for _, want := range []string{"orders", "/data/order"} {
		if !strings.Contains(body, want) {
			t.Errorf("relationship link missing %q; body:\n%s", want, body)
		}
	}
}

// A record's detail page renders each field, masked exactly as the remote
// returned it — the dashboard never unmasks. The PII field is labeled so a
// reviewer knows what category it carries.
func TestDataRecordRendersMaskedFields(t *testing.T) {
	fr := dataFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/data/customer/c1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /data/customer/c1 = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "[redacted]") {
		t.Errorf("record detail did not render the masked value; body:\n%s", body)
	}
	if !strings.Contains(body, "full_name") {
		t.Errorf("record detail missing the field name; body:\n%s", body)
	}
	// The PII category is surfaced so the reviewer can see what is masked.
	if !strings.Contains(body, string(pii.CategoryPerson)) {
		t.Errorf("record detail did not label the PII category; body:\n%s", body)
	}
}

// The record detail follows relationships to the target entity's browser.
func TestDataRecordRendersRelationshipLinks(t *testing.T) {
	fr := dataFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/data/customer/c1"))

	body := rec.Body.String()
	if !strings.Contains(body, "/data/order") {
		t.Errorf("record detail missing relationship link to /data/order; body:\n%s", body)
	}
}

// An unknown entity (not in the manifest) is a clean 404, not a 502 or a
// blank page — the browser is bounded by the schema.
func TestDataListUnknownEntityIsNotFound(t *testing.T) {
	fr := dataFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/data/ghost"))

	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /data/ghost = %d, want 404", rec.Code)
	}
}

func TestDataBrowserReadsRemoteAndHidesToken(t *testing.T) {
	fr := dataFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "super-secret"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/data"))

	if fr.manifestHits == 0 {
		t.Fatal("data browser did not read the schema from the remote API")
	}
	if strings.Contains(rec.Body.String(), "super-secret") {
		t.Error("the bearer token leaked into the data browser HTML")
	}
}
