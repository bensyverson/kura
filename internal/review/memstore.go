package review

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// MemStore is an in-memory Store for tests and database-less adapters.
// Operations are serialized under a mutex, so a decision and a completion
// never race. Reviews are held by id; List sorts them newest-first.
type MemStore struct {
	mu      sync.RWMutex
	reviews map[string]Review
	now     func() time.Time
}

var _ Store = (*MemStore)(nil)

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{reviews: make(map[string]Review), now: time.Now}
}

// Create persists a new open review snapshotting subjects.
func (s *MemStore) Create(_ context.Context, startedBy string, subjects []Item) (Review, error) {
	if len(subjects) == 0 {
		return Review{}, ErrEmptyReview
	}
	id, err := newReviewID()
	if err != nil {
		return Review{}, err
	}
	items := make([]Item, len(subjects))
	for i, sub := range subjects {
		items[i] = Item{
			Email:         strings.ToLower(sub.Email),
			RolesAtReview: append([]string(nil), sub.RolesAtReview...),
			Decision:      DecisionPending,
		}
	}
	r := Review{
		ID:        id,
		StartedAt: s.now().UTC(),
		StartedBy: startedBy,
		Status:    StatusOpen,
		Items:     items,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reviews[id] = cloneReview(r)
	return cloneReview(r), nil
}

// Get returns the review with id.
func (s *MemStore) Get(_ context.Context, id string) (Review, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.reviews[id]
	if !ok {
		return Review{}, ErrNotFound
	}
	return cloneReview(r), nil
}

// List returns reviews newest-first (by StartedAt, id as a stable tiebreak).
func (s *MemStore) List(_ context.Context) ([]Review, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Review, 0, len(s.reviews))
	for _, r := range s.reviews {
		out = append(out, cloneReview(r))
	}
	slices.SortFunc(out, func(a, b Review) int {
		if a.StartedAt.Equal(b.StartedAt) {
			return strings.Compare(b.ID, a.ID)
		}
		if a.StartedAt.After(b.StartedAt) {
			return -1
		}
		return 1
	})
	return out, nil
}

// Decide records decision and note for email in an open review.
func (s *MemStore) Decide(_ context.Context, id, email string, decision Decision, note string) error {
	if !decision.recordable() {
		return ErrInvalidDecision
	}
	email = strings.ToLower(email)
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reviews[id]
	if !ok {
		return ErrNotFound
	}
	if r.Status == StatusCompleted {
		return ErrClosed
	}
	for i := range r.Items {
		if r.Items[i].Email == email {
			r.Items[i].Decision = decision
			r.Items[i].Note = note
			s.reviews[id] = r
			return nil
		}
	}
	return ErrSubjectNotFound
}

// Complete marks an open review completed and returns the artifact.
func (s *MemStore) Complete(_ context.Context, id string) (Review, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reviews[id]
	if !ok {
		return Review{}, ErrNotFound
	}
	if r.Status == StatusCompleted {
		return Review{}, ErrClosed
	}
	t := s.now().UTC()
	r.Status = StatusCompleted
	r.CompletedAt = &t
	s.reviews[id] = r
	return cloneReview(r), nil
}

// cloneReview returns a deep copy so a stored review cannot be mutated by a
// caller holding a returned value.
func cloneReview(r Review) Review {
	out := r
	if r.CompletedAt != nil {
		t := *r.CompletedAt
		out.CompletedAt = &t
	}
	out.Items = make([]Item, len(r.Items))
	for i, it := range r.Items {
		it.RolesAtReview = append([]string(nil), it.RolesAtReview...)
		out.Items[i] = it
	}
	return out
}

// newReviewID returns a random 128-bit hex id — unique and lexically
// sortable, the same span of entropy as a UUID, matching the jobs ledger's
// id scheme.
func newReviewID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("review: generating id: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}
