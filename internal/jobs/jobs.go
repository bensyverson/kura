// Package jobs is Kura's async-operation ledger and worker. A job is a
// long-running operation submitted by an actor — a backup, a restore,
// any provisioning step that wants to outlive a single HTTP call — and
// the ledger is the durable record of what was submitted, what is in
// flight, and what finished how.
//
// The ledger has two cardinal properties:
//
//   - It is idempotent on (actor, kind, idempotency_key). A caller that
//     loses its job id can re-submit with the same key and pick up the
//     existing job rather than spawning a duplicate. This is what makes
//     a retry safe.
//   - It survives a process restart. The store is durable; on startup,
//     ResetOrphans flips any job left in "running" (a worker that
//     crashed mid-job) back to "pending" so the next worker can pick it
//     up exactly once.
//
// The Manager registers handlers per kind — a kind without a handler is
// rejected at Submit time, so the queue can never accumulate orphans no
// worker can run. The CLI's `--wait` flag is a thin client of Get: it
// polls until the job is terminal or the timeout fires.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// Errors the ledger returns to callers.
var (
	// ErrJobNotFound is returned when an actor asks for a job id that is
	// not on the ledger — either it never existed or it belongs to a
	// different actor (the ledger is actor-scoped on read).
	ErrJobNotFound = errors.New("jobs: job not found")
	// ErrUnknownKind is returned when Submit is called with a kind that
	// no handler has been registered for. The ledger never accepts work
	// no worker can run.
	ErrUnknownKind = errors.New("jobs: unknown kind")
)

// Status is the state of a job in its lifecycle. The four states are
// exhaustive: a job is either waiting to run, running, or done one of
// two ways.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
)

// Terminal reports whether s is an end state — i.e. the job is done and
// will not transition further on its own. `--wait` stops polling on
// Terminal.
func (s Status) Terminal() bool {
	return s == StatusSucceeded || s == StatusFailed
}

// Job is one entry in the ledger. The structure is what every store —
// memory, Postgres — produces, so callers above the store see a single
// shape regardless of backend.
type Job struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	Status         Status          `json:"status"`
	Actor          string          `json:"actor"`
	IdempotencyKey string          `json:"idempotency_key"`
	Params         json.RawMessage `json:"params,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	Error          string          `json:"error,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	FinishedAt     *time.Time      `json:"finished_at,omitempty"`
}

// Handler runs one job of a kind. It is invoked by the worker only after
// the store has flipped the job to "running"; its return values are what
// the worker records on the job. A non-nil error becomes the job's Error
// and the status is StatusFailed; otherwise the (possibly nil) result is
// stored and the status is StatusSucceeded.
type Handler func(ctx context.Context, params json.RawMessage) (json.RawMessage, error)

// Store is the durable backing for the ledger. The Manager is the only
// caller of Store; adapters above (HTTP, CLI) talk to the Manager. The
// interface is small on purpose — every backend (in-memory for tests,
// Postgres for production) implements the same handful of methods.
type Store interface {
	// Submit inserts a new job, or returns the existing job when one
	// already exists for (actor, kind, idempotencyKey). created reports
	// which it was, so callers can teach the agent whether work was
	// freshly enqueued or just re-attached to.
	Submit(ctx context.Context, j Job) (existing Job, created bool, err error)
	// Get returns the job for (actor, id) — or ErrJobNotFound when no
	// such job exists under that actor. Cross-actor reads return
	// ErrJobNotFound, never another actor's row.
	Get(ctx context.Context, actor, id string) (Job, error)
	// List returns every job owned by actor, newest first.
	List(ctx context.Context, actor string) ([]Job, error)
	// ClaimNextPending atomically transitions one pending job to
	// running, returning the claimed job. ok is false — with a nil
	// error — when there is no pending work.
	ClaimNextPending(ctx context.Context) (Job, bool, error)
	// MarkSucceeded transitions a running job to succeeded, recording
	// the result and the finish time. The store is the only writer of
	// terminal state; handlers return their result and the manager
	// hands it to the store.
	MarkSucceeded(ctx context.Context, id string, result json.RawMessage) error
	// MarkFailed transitions a running job to failed, recording the
	// error message and the finish time.
	MarkFailed(ctx context.Context, id string, errMsg string) error
	// ResetOrphans transitions any job stuck in "running" — left over
	// from a previous process that crashed mid-job — back to pending.
	// The next worker picks it up exactly once. Called on startup.
	ResetOrphans(ctx context.Context) error
}

// Manager is the ledger's orchestrator. It owns the registered handlers,
// drives submission and lookup through the store, and runs the worker
// loop that processes pending jobs.
type Manager struct {
	store       Store
	log         *slog.Logger
	idleBackoff time.Duration

	mu    sync.RWMutex
	kinds map[string]Handler
}

// NewManager wires a Manager over store. The manager starts with no
// kinds registered; an adapter (the server, in production) calls
// Register for each kind it intends to support before driving Submit.
func NewManager(store Store) *Manager {
	return &Manager{
		store:       store,
		log:         slog.Default(),
		idleBackoff: 50 * time.Millisecond,
		kinds:       make(map[string]Handler),
	}
}

// WithLogger sets the manager's logger. Worker activity is logged as
// operational telemetry; nothing about job params or results is logged,
// to keep the audit boundary at the gate.
func (m *Manager) WithLogger(log *slog.Logger) *Manager {
	if log != nil {
		m.log = log
	}
	return m
}

// WithIdleBackoff sets the wait between polls when the queue is empty.
// Tests use a tiny value for liveness; production uses the default.
func (m *Manager) WithIdleBackoff(d time.Duration) *Manager {
	if d > 0 {
		m.idleBackoff = d
	}
	return m
}

// Register binds a Handler to a kind. Re-registering the same kind
// replaces the handler — handy in tests that swap in a fake without
// rebuilding the manager.
func (m *Manager) Register(kind string, h Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kinds[kind] = h
}

// Kinds returns the registered kind names in alphabetical order. Useful
// for diagnostics and for `kura agent-context` to surface which jobs a
// deployment understands.
func (m *Manager) Kinds() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.kinds))
	for k := range m.kinds {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Submit either enqueues a new job or returns the existing one for the
// same (actor, kind, idempotencyKey). It rejects unregistered kinds —
// the queue never accepts work no worker can run.
func (m *Manager) Submit(ctx context.Context, actor, kind, idempotencyKey string, params json.RawMessage) (Job, bool, error) {
	if actor == "" {
		return Job{}, false, errors.New("jobs: submit requires an actor")
	}
	if kind == "" {
		return Job{}, false, errors.New("jobs: submit requires a kind")
	}
	if idempotencyKey == "" {
		return Job{}, false, errors.New("jobs: submit requires an idempotency key")
	}
	m.mu.RLock()
	_, ok := m.kinds[kind]
	m.mu.RUnlock()
	if !ok {
		return Job{}, false, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}
	id, err := newJobID()
	if err != nil {
		return Job{}, false, err
	}
	j := Job{
		ID:             id,
		Kind:           kind,
		Status:         StatusPending,
		Actor:          actor,
		IdempotencyKey: idempotencyKey,
		Params:         params,
		CreatedAt:      time.Now().UTC(),
	}
	return m.store.Submit(ctx, j)
}

// Get returns the actor's job by id, or ErrJobNotFound.
func (m *Manager) Get(ctx context.Context, actor, id string) (Job, error) {
	return m.store.Get(ctx, actor, id)
}

// List returns every job the actor owns.
func (m *Manager) List(ctx context.Context, actor string) ([]Job, error) {
	return m.store.List(ctx, actor)
}

// ResetOrphans is the recovery step a host calls at startup. Any job
// left in "running" — a worker that crashed mid-job — is flipped back to
// pending; the next worker will process it exactly once.
func (m *Manager) ResetOrphans(ctx context.Context) error {
	return m.store.ResetOrphans(ctx)
}

// RunOnce processes at most one pending job: claim it, invoke its
// handler, record the outcome. It returns ran=true if a job was
// processed (success or failure both count), ran=false on an empty
// queue. Production uses Run; tests use RunOnce for deterministic
// stepping.
func (m *Manager) RunOnce(ctx context.Context) (bool, error) {
	job, ok, err := m.store.ClaimNextPending(ctx)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	m.mu.RLock()
	h, registered := m.kinds[job.Kind]
	m.mu.RUnlock()
	if !registered {
		// The kind was registered when the job was submitted but is no
		// longer — most likely because the host wired a different set
		// at startup. Fail the job; the operator sees it on the ledger
		// rather than the job sitting "running" forever.
		if err := m.store.MarkFailed(ctx, job.ID, fmt.Sprintf("no handler registered for kind %q", job.Kind)); err != nil {
			return true, err
		}
		return true, nil
	}
	result, runErr := h(ctx, job.Params)
	if runErr != nil {
		if err := m.store.MarkFailed(ctx, job.ID, runErr.Error()); err != nil {
			return true, err
		}
		return true, nil
	}
	if err := m.store.MarkSucceeded(ctx, job.ID, result); err != nil {
		return true, err
	}
	return true, nil
}

// Run is the production worker loop. It polls the ledger, processes
// pending jobs, and idles between empty polls. It returns nil when ctx
// is cancelled, or the first non-context error it encounters.
func (m *Manager) Run(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		ran, err := m.RunOnce(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			m.log.Error("jobs: run loop", "err", err)
			// Back off briefly so an unhealthy store does not pin a CPU.
			if !sleepCtx(ctx, m.idleBackoff) {
				return nil
			}
			continue
		}
		if !ran {
			if !sleepCtx(ctx, m.idleBackoff) {
				return nil
			}
		}
	}
}

// newJobID returns a random 128-bit hex id. It is not a UUID — the store
// only requires uniqueness and stable lexical sort, which a hex string
// gives — but it is the same span of entropy.
func newJobID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("jobs: generating id: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// sleepCtx sleeps for d, returning false if ctx fires first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
