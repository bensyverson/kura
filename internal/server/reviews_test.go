package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

// reviewWire mirrors the /api/reviews JSON for decoding in tests.
type reviewWire struct {
	ID          string  `json:"id"`
	StartedBy   string  `json:"started_by"`
	Status      string  `json:"status"`
	CompletedAt *string `json:"completed_at"`
	Items       []struct {
		Email         string   `json:"email"`
		RolesAtReview []string `json:"roles_at_review"`
		Decision      string   `json:"decision"`
		Note          string   `json:"note"`
	} `json:"items"`
}

// Starting a review snapshots the current authorized list as pending
// subjects — an admin action. The seeded admin and user both appear.
func TestReviewStartSnapshotsAuthorizedList(t *testing.T) {
	srv, _, _, _, _, adminTok, _ := overviewServer(t)

	rec := doReq(t, srv, http.MethodPost, "/api/reviews", adminTok, "")
	if rec.status != http.StatusOK {
		t.Fatalf("POST /api/reviews as admin: status = %d, want 200; body %s", rec.status, rec.body.String())
	}
	var r reviewWire
	if err := json.Unmarshal(rec.body.Bytes(), &r); err != nil {
		t.Fatalf("decoding review: %v; body %s", err, rec.body.String())
	}
	if r.ID == "" || r.Status != "open" {
		t.Fatalf("review malformed: %+v", r)
	}
	emails := map[string]string{}
	for _, it := range r.Items {
		emails[it.Email] = it.Decision
	}
	if emails["admin@client.com"] != "pending" || emails["user@client.com"] != "pending" {
		t.Errorf("snapshot = %+v, want admin and user both pending", emails)
	}
}

// Starting, deciding, and completing a review are admin-only management
// actions; a plain user is forbidden.
func TestReviewStartRequiresAdmin(t *testing.T) {
	srv, _, _, _, _, _, userTok := overviewServer(t)
	if rec := doReq(t, srv, http.MethodPost, "/api/reviews", userTok, ""); rec.status != http.StatusForbidden {
		t.Errorf("start review as plain user: status = %d, want 403", rec.status)
	}
}

// A reviewer records approve/remove per person and completes the review;
// the completed artifact is retrievable with its decisions intact.
func TestReviewDecideCompleteAndRetrieve(t *testing.T) {
	srv, _, _, _, _, adminTok, _ := overviewServer(t)

	start := doReq(t, srv, http.MethodPost, "/api/reviews", adminTok, "")
	if start.status != http.StatusOK {
		t.Fatalf("start: %d %s", start.status, start.body.String())
	}
	var created reviewWire
	_ = json.Unmarshal(start.body.Bytes(), &created)

	if rec := doReq(t, srv, http.MethodPost, "/api/reviews/"+created.ID+"/decisions", adminTok,
		`{"email":"admin@client.com","decision":"approved"}`); rec.status != http.StatusNoContent {
		t.Fatalf("decide approve: %d %s", rec.status, rec.body.String())
	}
	if rec := doReq(t, srv, http.MethodPost, "/api/reviews/"+created.ID+"/decisions", adminTok,
		`{"email":"user@client.com","decision":"removed","note":"left"}`); rec.status != http.StatusNoContent {
		t.Fatalf("decide remove: %d %s", rec.status, rec.body.String())
	}
	if rec := doReq(t, srv, http.MethodPost, "/api/reviews/"+created.ID+"/complete", adminTok, ""); rec.status != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.status, rec.body.String())
	}

	get := doReq(t, srv, http.MethodGet, "/api/reviews/"+created.ID, adminTok, "")
	if get.status != http.StatusOK {
		t.Fatalf("get: %d %s", get.status, get.body.String())
	}
	var got reviewWire
	_ = json.Unmarshal(get.body.Bytes(), &got)
	if got.Status != "completed" || got.CompletedAt == nil {
		t.Errorf("retrieved artifact not completed: %+v", got)
	}
	decisions := map[string]string{}
	for _, it := range got.Items {
		decisions[it.Email] = it.Decision
	}
	if decisions["admin@client.com"] != "approved" || decisions["user@client.com"] != "removed" {
		t.Errorf("decisions = %+v, want admin approved & user removed", decisions)
	}
}

// Reads are AdminReview (admin or auditor); a plain user cannot list or get.
func TestReviewReadsRequireReviewRole(t *testing.T) {
	srv, _, _, _, _, adminTok, userTok := overviewServer(t)
	created := doReq(t, srv, http.MethodPost, "/api/reviews", adminTok, "")
	var r reviewWire
	_ = json.Unmarshal(created.body.Bytes(), &r)

	if rec := doReq(t, srv, http.MethodGet, "/api/reviews", userTok, ""); rec.status != http.StatusForbidden {
		t.Errorf("list reviews as user: status = %d, want 403", rec.status)
	}
	if rec := doReq(t, srv, http.MethodGet, "/api/reviews/"+r.ID, userTok, ""); rec.status != http.StatusForbidden {
		t.Errorf("get review as user: status = %d, want 403", rec.status)
	}
	if rec := doReq(t, srv, http.MethodGet, "/api/reviews", adminTok, ""); rec.status != http.StatusOK {
		t.Errorf("list reviews as admin: status = %d, want 200", rec.status)
	}
}

// Error mapping: an unknown review or subject is a 404, a malformed
// decision a 400, and a decision on a completed review a 409.
func TestReviewErrorMapping(t *testing.T) {
	srv, _, _, _, _, adminTok, _ := overviewServer(t)

	if rec := doReq(t, srv, http.MethodGet, "/api/reviews/nope", adminTok, ""); rec.status != http.StatusNotFound {
		t.Errorf("get unknown review: status = %d, want 404", rec.status)
	}

	start := doReq(t, srv, http.MethodPost, "/api/reviews", adminTok, "")
	var r reviewWire
	_ = json.Unmarshal(start.body.Bytes(), &r)

	if rec := doReq(t, srv, http.MethodPost, "/api/reviews/"+r.ID+"/decisions", adminTok,
		`{"email":"ghost@client.com","decision":"approved"}`); rec.status != http.StatusNotFound {
		t.Errorf("decide unknown subject: status = %d, want 404", rec.status)
	}
	if rec := doReq(t, srv, http.MethodPost, "/api/reviews/"+r.ID+"/decisions", adminTok,
		`{"email":"admin@client.com","decision":"maybe"}`); rec.status != http.StatusBadRequest {
		t.Errorf("invalid decision: status = %d, want 400", rec.status)
	}
	if rec := doReq(t, srv, http.MethodPost, "/api/reviews/"+r.ID+"/complete", adminTok, ""); rec.status != http.StatusOK {
		t.Fatalf("complete: %d", rec.status)
	}
	if rec := doReq(t, srv, http.MethodPost, "/api/reviews/"+r.ID+"/decisions", adminTok,
		`{"email":"admin@client.com","decision":"approved"}`); rec.status != http.StatusConflict {
		t.Errorf("decide on completed review: status = %d, want 409", rec.status)
	}
}
