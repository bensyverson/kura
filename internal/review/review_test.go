package review

import (
	"errors"
	"testing"
	"time"
)

func subjects() []Item {
	return []Item{
		{Email: "ada@client.example", RolesAtReview: []string{"admin"}},
		{Email: "boss@client.example", RolesAtReview: []string{"auditor", "user"}},
	}
}

// Creating a review snapshots the subjects as pending, attributes it to the
// reviewer, opens it, and stamps a start time.
func TestCreateSnapshotsSubjectsAsPending(t *testing.T) {
	s := NewMemStore()
	r, err := s.Create(t.Context(), "reviewer@client.example", subjects())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if r.ID == "" {
		t.Error("review got no id")
	}
	if r.Status != StatusOpen {
		t.Errorf("status = %q, want open", r.Status)
	}
	if r.StartedBy != "reviewer@client.example" {
		t.Errorf("startedBy = %q", r.StartedBy)
	}
	if r.StartedAt.IsZero() {
		t.Error("StartedAt not set")
	}
	if r.CompletedAt != nil {
		t.Error("a new review should not be completed")
	}
	if len(r.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(r.Items))
	}
	for _, it := range r.Items {
		if it.Decision != DecisionPending {
			t.Errorf("item %s decision = %q, want pending", it.Email, it.Decision)
		}
	}
	if got := r.Items[0].RolesAtReview; len(got) != 1 || got[0] != "admin" {
		t.Errorf("roles snapshot = %v, want [admin]", got)
	}
}

func TestCreateRejectsEmpty(t *testing.T) {
	s := NewMemStore()
	if _, err := s.Create(t.Context(), "r@x", nil); !errors.Is(err, ErrEmptyReview) {
		t.Errorf("Create empty = %v, want ErrEmptyReview", err)
	}
}

func TestGetUnknownIsNotFound(t *testing.T) {
	s := NewMemStore()
	if _, err := s.Get(t.Context(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get unknown = %v, want ErrNotFound", err)
	}
}

// A reviewer records approve and remove decisions per subject, and Get
// reflects them — the heart of criterion I6N.
func TestDecideRecordsApproveAndRemove(t *testing.T) {
	s := NewMemStore()
	r, _ := s.Create(t.Context(), "r@x", subjects())

	if err := s.Decide(t.Context(), r.ID, "ada@client.example", DecisionApproved, ""); err != nil {
		t.Fatalf("Decide approve: %v", err)
	}
	if err := s.Decide(t.Context(), r.ID, "boss@client.example", DecisionRemoved, "left the firm"); err != nil {
		t.Fatalf("Decide remove: %v", err)
	}

	got, _ := s.Get(t.Context(), r.ID)
	byEmail := map[string]Item{}
	for _, it := range got.Items {
		byEmail[it.Email] = it
	}
	if byEmail["ada@client.example"].Decision != DecisionApproved {
		t.Errorf("ada decision = %q, want approved", byEmail["ada@client.example"].Decision)
	}
	if byEmail["boss@client.example"].Decision != DecisionRemoved {
		t.Errorf("boss decision = %q, want removed", byEmail["boss@client.example"].Decision)
	}
	if byEmail["boss@client.example"].Note != "left the firm" {
		t.Errorf("boss note = %q", byEmail["boss@client.example"].Note)
	}
}

func TestDecideInvalidDecisionRejected(t *testing.T) {
	s := NewMemStore()
	r, _ := s.Create(t.Context(), "r@x", subjects())
	if err := s.Decide(t.Context(), r.ID, "ada@client.example", DecisionPending, ""); !errors.Is(err, ErrInvalidDecision) {
		t.Errorf("Decide pending = %v, want ErrInvalidDecision", err)
	}
}

func TestDecideUnknownSubject(t *testing.T) {
	s := NewMemStore()
	r, _ := s.Create(t.Context(), "r@x", subjects())
	if err := s.Decide(t.Context(), r.ID, "ghost@client.example", DecisionApproved, ""); !errors.Is(err, ErrSubjectNotFound) {
		t.Errorf("Decide unknown subject = %v, want ErrSubjectNotFound", err)
	}
}

// Completing a review archives it as an immutable, retrievable artifact —
// criterion 2pa. A completed review rejects further decisions.
func TestCompleteArchivesAndLocks(t *testing.T) {
	s := NewMemStore()
	r, _ := s.Create(t.Context(), "r@x", subjects())
	_ = s.Decide(t.Context(), r.ID, "ada@client.example", DecisionApproved, "")

	done, err := s.Complete(t.Context(), r.ID)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if done.Status != StatusCompleted {
		t.Errorf("status = %q, want completed", done.Status)
	}
	if done.CompletedAt == nil {
		t.Error("CompletedAt not set on a completed review")
	}

	// Retrievable after completion.
	got, err := s.Get(t.Context(), r.ID)
	if err != nil {
		t.Fatalf("Get completed: %v", err)
	}
	if got.Status != StatusCompleted {
		t.Errorf("retrieved status = %q, want completed", got.Status)
	}

	// Immutable after completion.
	if err := s.Decide(t.Context(), r.ID, "boss@client.example", DecisionRemoved, ""); !errors.Is(err, ErrClosed) {
		t.Errorf("Decide on completed = %v, want ErrClosed", err)
	}
	if _, err := s.Complete(t.Context(), r.ID); !errors.Is(err, ErrClosed) {
		t.Errorf("Complete twice = %v, want ErrClosed", err)
	}
}

func TestCompleteUnknownIsNotFound(t *testing.T) {
	s := NewMemStore()
	if _, err := s.Complete(t.Context(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Complete unknown = %v, want ErrNotFound", err)
	}
}

// List returns reviews newest-first so the dashboard shows the most recent
// at the top.
func TestListNewestFirst(t *testing.T) {
	s := NewMemStore()
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }
	older, _ := s.Create(t.Context(), "r@x", subjects())
	s.now = func() time.Time { return base.Add(time.Hour) }
	newer, _ := s.Create(t.Context(), "r@x", subjects())

	list, err := s.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("list = %d, want 2", len(list))
	}
	if list[0].ID != newer.ID || list[1].ID != older.ID {
		t.Errorf("List order = [%s, %s], want newest [%s, %s]", list[0].ID, list[1].ID, newer.ID, older.ID)
	}
}
