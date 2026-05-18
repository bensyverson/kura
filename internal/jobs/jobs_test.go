package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Submit returns a fresh job on the first call and the same job on the
// second call with the same actor+kind+key. "Retry finds existing work"
// is the ledger's core contract: a caller that lost track of its job id
// can re-submit with the same idempotency key and pick up where it left
// off, without duplicating the work.
func TestSubmitIdempotency(t *testing.T) {
	m := NewManager(NewMemStore())
	m.Register("noop", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})

	first, created, err := m.Submit(context.Background(), "alex@example.com", "noop", "k-1", nil)
	if err != nil {
		t.Fatalf("first submit: %v", err)
	}
	if !created {
		t.Fatalf("first submit created=false; want true")
	}
	if first.ID == "" {
		t.Fatalf("first submit returned empty id")
	}

	second, created, err := m.Submit(context.Background(), "alex@example.com", "noop", "k-1", nil)
	if err != nil {
		t.Fatalf("second submit: %v", err)
	}
	if created {
		t.Fatalf("second submit created=true; want false (idempotent)")
	}
	if second.ID != first.ID {
		t.Fatalf("second submit id %q != first id %q", second.ID, first.ID)
	}
}

// Idempotency is scoped per actor: two distinct actors using the same
// key get distinct jobs. Without this, one client could shadow another's
// retry slot.
func TestSubmitIdempotencyIsPerActor(t *testing.T) {
	m := NewManager(NewMemStore())
	m.Register("noop", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})
	a, _, err := m.Submit(context.Background(), "alex@example.com", "noop", "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, created, err := m.Submit(context.Background(), "bob@example.com", "noop", "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatalf("second submit (different actor) created=false; want true")
	}
	if a.ID == b.ID {
		t.Fatalf("distinct actors collided on idempotency key: id=%q", a.ID)
	}
}

// Submit rejects an unregistered kind — the ledger never accepts a job
// no worker can run, so a queue full of orphans can't accumulate.
func TestSubmitUnknownKind(t *testing.T) {
	m := NewManager(NewMemStore())
	_, _, err := m.Submit(context.Background(), "alex@example.com", "no-such-kind", "k", nil)
	if !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("err = %v; want ErrUnknownKind", err)
	}
}

// RunOnce drives one round of the worker loop: pick a pending job, run
// its handler, record the result. Tests use it for deterministic stepping;
// production uses Run() which loops on it.
func TestRunOnceSucceedsAJob(t *testing.T) {
	m := NewManager(NewMemStore())
	m.Register("echo", func(_ context.Context, p json.RawMessage) (json.RawMessage, error) {
		return p, nil
	})
	j, _, err := m.Submit(context.Background(), "alex@example.com", "echo", "k", json.RawMessage(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	ran, err := m.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !ran {
		t.Fatalf("RunOnce ran=false; want true (a pending job existed)")
	}
	got, err := m.Get(context.Background(), "alex@example.com", j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusSucceeded {
		t.Fatalf("status = %q; want %q", got.Status, StatusSucceeded)
	}
	if string(got.Result) != `{"x":1}` {
		t.Fatalf("result = %q; want %q", string(got.Result), `{"x":1}`)
	}
	if got.FinishedAt == nil {
		t.Fatalf("FinishedAt = nil; want set")
	}
}

// A handler that returns an error marks the job failed; the error text
// becomes the job's Error field. The job is still terminal — failed
// jobs don't get re-tried automatically.
func TestRunOnceFailsAJob(t *testing.T) {
	m := NewManager(NewMemStore())
	m.Register("boom", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, errors.New("kaboom")
	})
	j, _, err := m.Submit(context.Background(), "alex@example.com", "boom", "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := m.Get(context.Background(), "alex@example.com", j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusFailed {
		t.Fatalf("status = %q; want %q", got.Status, StatusFailed)
	}
	if !strings.Contains(got.Error, "kaboom") {
		t.Fatalf("Error = %q; want it to contain %q", got.Error, "kaboom")
	}
}

// RunOnce with no pending work reports ran=false without blocking. The
// production Run loop uses this to back off.
func TestRunOnceNoWork(t *testing.T) {
	m := NewManager(NewMemStore())
	ran, err := m.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatalf("RunOnce ran=true with empty queue; want false")
	}
}

// List returns the caller's jobs and nothing else — the ledger is
// actor-scoped on read, just like Submit is actor-scoped on dedupe.
func TestListIsActorScoped(t *testing.T) {
	m := NewManager(NewMemStore())
	m.Register("noop", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})
	if _, _, err := m.Submit(context.Background(), "alex@example.com", "noop", "a", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Submit(context.Background(), "bob@example.com", "noop", "b", nil); err != nil {
		t.Fatal(err)
	}
	alex, err := m.List(context.Background(), "alex@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(alex) != 1 {
		t.Fatalf("alex sees %d jobs; want 1", len(alex))
	}
	if alex[0].Actor != "alex@example.com" {
		t.Fatalf("alex sees actor=%q; want alex@", alex[0].Actor)
	}
}

// Get returns a not-found-style error when the actor does not own the
// job. A caller cannot read another actor's job by guessing its id; the
// ledger is the source of truth for that boundary.
func TestGetIsActorScoped(t *testing.T) {
	m := NewManager(NewMemStore())
	m.Register("noop", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})
	j, _, err := m.Submit(context.Background(), "alex@example.com", "noop", "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Get(context.Background(), "bob@example.com", j.ID)
	if !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("cross-actor Get err = %v; want ErrJobNotFound", err)
	}
}

// ResetOrphans flips any job left in "running" back to "pending" — the
// recovery step that lets the ledger survive a worker crash mid-job. The
// next RunOnce picks it up exactly once.
func TestResetOrphansRecoversCrashedJobs(t *testing.T) {
	store := NewMemStore()
	m := NewManager(store)

	// Hand-stamp a job in "running" status to simulate a process that
	// crashed between MarkRunning and the handler returning.
	j := Job{
		ID:             "j-orphan",
		Kind:           "noop",
		Status:         StatusRunning,
		Actor:          "alex@example.com",
		IdempotencyKey: "k",
		CreatedAt:      time.Now(),
	}
	startedAt := time.Now().Add(-1 * time.Minute)
	j.StartedAt = &startedAt
	store.put(j)

	if err := m.ResetOrphans(context.Background()); err != nil {
		t.Fatalf("ResetOrphans: %v", err)
	}
	got, err := m.Get(context.Background(), "alex@example.com", "j-orphan")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusPending {
		t.Fatalf("status = %q; want %q (orphan should be back in queue)", got.Status, StatusPending)
	}
}

// Run is the production worker loop: it polls until ctx is cancelled,
// processing pending jobs as they arrive. The test cancels via context
// once the job is observed terminal.
func TestRunProcessesPendingThenStopsOnCancel(t *testing.T) {
	m := NewManager(NewMemStore())
	var wg sync.WaitGroup
	wg.Add(1)
	m.Register("done", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		defer wg.Done()
		return json.RawMessage(`"ok"`), nil
	})
	j, _, err := m.Submit(context.Background(), "alex@example.com", "done", "k", nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan error, 1)
	go func() { loopDone <- m.Run(ctx) }()

	wg.Wait()
	// Wait until the manager records the terminal status, then cancel.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := m.Get(context.Background(), "alex@example.com", j.ID)
		if err == nil && got.Status.Terminal() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-loopDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v; want nil or context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return after cancel")
	}
}
