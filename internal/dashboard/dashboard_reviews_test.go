package dashboard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bensyverson/kura/internal/review"
)

func reviewsFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := newFakeRemote(t)
	fr.users = []userRow{
		{Email: "ada@client.example", Roles: []string{"admin"}},
		{Email: "noroles@client.example", Roles: nil},
	}
	return fr
}

// seedReview creates a review directly in the fake's store, so detail-page
// tests have an artifact to render without going through the start flow.
func seedReview(t *testing.T, fr *fakeRemote) review.Review {
	t.Helper()
	r, err := fr.reviews.Create(t.Context(), "boss@client.example", []review.Item{
		{Email: "ada@client.example", RolesAtReview: []string{"admin"}},
		{Email: "noroles@client.example", RolesAtReview: nil},
	})
	if err != nil {
		t.Fatalf("seedReview: %v", err)
	}
	return r
}

// The reviews page lists past reviews and offers a way to start a new one.
func TestReviewsPageListsAndOffersStart(t *testing.T) {
	fr := reviewsFakeRemote(t)
	r := seedReview(t, fr)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/reviews"))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /reviews = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/reviews/"+r.ID) {
		t.Errorf("reviews list missing a link to the review %s; body:\n%s", r.ID, body)
	}
	if !strings.Contains(body, `action="/reviews"`) || !strings.Contains(body, "method=\"post\"") {
		t.Errorf("reviews page has no start-a-review form; body:\n%s", body)
	}
}

// Starting a review snapshots the list and redirects to the new review's
// detail page (POST-redirect-GET).
func TestStartReviewRedirectsToDetail(t *testing.T) {
	fr := reviewsFakeRemote(t)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackPost("/reviews", url.Values{}))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /reviews = %d, want 303", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/reviews/") {
		t.Errorf("start redirect Location = %q, want /reviews/{id}", loc)
	}
	// The review really exists in the store now.
	list, _ := fr.reviews.List(t.Context())
	if len(list) != 1 {
		t.Errorf("after start, store has %d reviews, want 1", len(list))
	}
}

// The detail page shows each subject with its role snapshot and an
// approve/remove control — criterion I6N's "approve/remove each person".
func TestReviewDetailShowsSubjectsAndDecisionForms(t *testing.T) {
	fr := reviewsFakeRemote(t)
	r := seedReview(t, fr)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/reviews/"+r.ID))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /reviews/%s = %d, want 200", r.ID, rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"ada@client.example",
		"admin", // the role snapshot
		`action="/reviews/` + r.ID + `/decisions"`, // the decision form
		`value="approved"`,
		`value="removed"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("review detail missing %q; body:\n%s", want, body)
		}
	}
}

// Recording a decision posts to the remote and redirects back to the
// detail; the store reflects the recorded verdict.
func TestReviewDecideRecordsAndRedirects(t *testing.T) {
	fr := reviewsFakeRemote(t)
	r := seedReview(t, fr)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	form := url.Values{"email": {"ada@client.example"}, "decision": {"approved"}}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackPost("/reviews/"+r.ID+"/decisions", form))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST decisions = %d, want 303", rec.Code)
	}
	got, _ := fr.reviews.Get(t.Context(), r.ID)
	for _, it := range got.Items {
		if it.Email == "ada@client.example" && it.Decision != review.DecisionApproved {
			t.Errorf("ada decision = %q, want approved", it.Decision)
		}
	}
}

// Completing a review archives it; the detail then renders the artifact
// read-only (no decision forms) — criterion 2pa.
func TestReviewCompleteArchivesArtifact(t *testing.T) {
	fr := reviewsFakeRemote(t)
	r := seedReview(t, fr)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackPost("/reviews/"+r.ID+"/complete", url.Values{}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST complete = %d, want 303", rec.Code)
	}

	got, _ := fr.reviews.Get(t.Context(), r.ID)
	if got.Status != review.StatusCompleted {
		t.Fatalf("store status = %q, want completed", got.Status)
	}

	// The archived artifact renders without decision controls.
	detail := httptest.NewRecorder()
	s.Handler().ServeHTTP(detail, loopbackGet("/reviews/"+r.ID))
	body := detail.Body.String()
	if !strings.Contains(body, "completed") {
		t.Errorf("completed review detail does not show its status; body:\n%s", body)
	}
	if strings.Contains(body, `action="/reviews/`+r.ID+`/decisions"`) {
		t.Errorf("a completed review still shows decision forms; body:\n%s", body)
	}
}

// State-changing review actions require a same-origin request, like every
// other dashboard mutation.
func TestReviewMutationsRejectCrossOrigin(t *testing.T) {
	fr := reviewsFakeRemote(t)
	r := seedReview(t, fr)
	s := newTestServer(t, fr.URL, staticToken{token: "tok"})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7777/reviews/"+r.ID+"/complete", nil)
	req.Host = "127.0.0.1:7777" // loopback Host, but no Origin/Referer
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin complete = %d, want 403", rec.Code)
	}
}

func TestReviewsPageHidesToken(t *testing.T) {
	fr := reviewsFakeRemote(t)
	seedReview(t, fr)
	s := newTestServer(t, fr.URL, staticToken{token: "super-secret"})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, loopbackGet("/reviews"))

	if strings.Contains(rec.Body.String(), "super-secret") {
		t.Error("the bearer token leaked into the reviews page HTML")
	}
}
