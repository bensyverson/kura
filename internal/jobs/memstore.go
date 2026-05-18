package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemStore is an in-memory Store, used by tests and by adapters that
// have no database yet. It is safe for concurrent use; every mutation
// runs under the same mutex, so transitions are linearizable — which
// matches what Postgres gives us with the right row locking.
//
// MemStore does NOT survive a process restart. The Postgres-backed
// store is the one the "ledger survives a process restart" criterion
// relies on; MemStore is for unit tests.
type MemStore struct {
	mu   sync.Mutex
	jobs map[string]Job // id -> job
}

var _ Store = (*MemStore)(nil)

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{jobs: make(map[string]Job)}
}

// put inserts j directly. Test-only — production paths go through
// Submit, which enforces idempotency. Exported within the package so
// the orphan-recovery test can hand-stamp a "running" job.
func (s *MemStore) put(j Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[j.ID] = j.clone()
}

// Submit either inserts j or returns the existing job for the same
// (actor, kind, idempotencyKey).
func (s *MemStore) Submit(_ context.Context, j Job) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.jobs {
		if existing.Actor == j.Actor && existing.Kind == j.Kind && existing.IdempotencyKey == j.IdempotencyKey {
			return existing.clone(), false, nil
		}
	}
	s.jobs[j.ID] = j.clone()
	return j.clone(), true, nil
}

// Get returns the actor's job by id, or ErrJobNotFound.
func (s *MemStore) Get(_ context.Context, actor, id string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok || j.Actor != actor {
		return Job{}, ErrJobNotFound
	}
	return j.clone(), nil
}

// List returns every job owned by actor, newest first by CreatedAt.
func (s *MemStore) List(_ context.Context, actor string) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Job
	for _, j := range s.jobs {
		if j.Actor == actor {
			out = append(out, j.clone())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// ClaimNextPending picks the oldest pending job, flips it to running,
// and returns it. The mutex serializes this so two callers cannot claim
// the same job.
func (s *MemStore) ClaimNextPending(_ context.Context) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var oldestID string
	var oldestCreated time.Time
	for id, j := range s.jobs {
		if j.Status != StatusPending {
			continue
		}
		if oldestID == "" || j.CreatedAt.Before(oldestCreated) {
			oldestID = id
			oldestCreated = j.CreatedAt
		}
	}
	if oldestID == "" {
		return Job{}, false, nil
	}
	j := s.jobs[oldestID]
	now := time.Now().UTC()
	j.Status = StatusRunning
	j.StartedAt = &now
	s.jobs[oldestID] = j.clone()
	return j.clone(), true, nil
}

// MarkSucceeded records a successful completion.
func (s *MemStore) MarkSucceeded(_ context.Context, id string, result json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return fmt.Errorf("jobs: MarkSucceeded: %w (id=%s)", ErrJobNotFound, id)
	}
	now := time.Now().UTC()
	j.Status = StatusSucceeded
	j.Result = append(json.RawMessage(nil), result...)
	j.FinishedAt = &now
	j.Error = ""
	s.jobs[id] = j
	return nil
}

// MarkFailed records a failed completion.
func (s *MemStore) MarkFailed(_ context.Context, id string, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return fmt.Errorf("jobs: MarkFailed: %w (id=%s)", ErrJobNotFound, id)
	}
	now := time.Now().UTC()
	j.Status = StatusFailed
	j.Error = errMsg
	j.FinishedAt = &now
	s.jobs[id] = j
	return nil
}

// ResetOrphans flips every running job back to pending. Called on
// startup so a crashed worker's in-flight jobs get picked up exactly
// once by the next process.
func (s *MemStore) ResetOrphans(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, j := range s.jobs {
		if j.Status == StatusRunning {
			j.Status = StatusPending
			j.StartedAt = nil
			s.jobs[id] = j
		}
	}
	return nil
}

// clone returns a deep copy of j so the store's internal map cannot be
// mutated by a caller that holds the returned value.
func (j Job) clone() Job {
	out := j
	if j.Params != nil {
		out.Params = append(json.RawMessage(nil), j.Params...)
	}
	if j.Result != nil {
		out.Result = append(json.RawMessage(nil), j.Result...)
	}
	if j.StartedAt != nil {
		t := *j.StartedAt
		out.StartedAt = &t
	}
	if j.FinishedAt != nil {
		t := *j.FinishedAt
		out.FinishedAt = &t
	}
	return out
}
