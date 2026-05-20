package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The schema manifest drives the dashboard's data browser, so the API
// exposes it as a read. It is an AdminReview read like the overview and the
// policy: an admin (or auditor) may see the schema; a plain user may not.
func TestManifestReturnsSchemaForAdmin(t *testing.T) {
	srv, _, _, _, _, adminTok, _ := overviewServer(t)

	rec := doReq(t, srv, http.MethodGet, "/api/manifest", adminTok, "")
	if rec.status != http.StatusOK {
		t.Fatalf("GET /api/manifest as admin: status = %d, want 200; body %s", rec.status, rec.body.String())
	}

	var got struct {
		Version  string `json:"version"`
		Entities []struct {
			Name   string `json:"name"`
			Fields []struct {
				Name string  `json:"name"`
				Type string  `json:"type"`
				PII  *string `json:"pii"`
			} `json:"fields"`
		} `json:"entities"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &got); err != nil {
		t.Fatalf("decoding manifest: %v; body %s", err, rec.body.String())
	}

	if got.Version == "" {
		t.Error("manifest reported no version")
	}
	names := map[string]bool{}
	for _, e := range got.Entities {
		names[e.Name] = true
	}
	if !names["patient"] || !names["doctor"] {
		t.Errorf("entities = %v, want patient and doctor", names)
	}

	// The PII annotation must survive serialization — the browser labels
	// PII columns from it.
	var sawPII bool
	for _, e := range got.Entities {
		for _, f := range e.Fields {
			if f.Name == "full_name" && f.PII != nil && *f.PII == "private_person" {
				sawPII = true
			}
		}
	}
	if !sawPII {
		t.Error("manifest did not carry the full_name field's private_person PII category")
	}
}

// A plain user may not read the schema — it is AdminReview-gated, so the
// gate refuses with a 403, exactly like the overview and policy reads.
func TestManifestRequiresReviewRole(t *testing.T) {
	srv, _, _, _, _, _, userTok := overviewServer(t)

	if rec := doReq(t, srv, http.MethodGet, "/api/manifest", userTok, ""); rec.status != http.StatusForbidden {
		t.Errorf("manifest as plain user: status = %d, want 403", rec.status)
	}
}
