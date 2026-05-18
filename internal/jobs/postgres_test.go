package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/db"
)

// jobsTestEnv mirrors internal/data's testEnv: a freshly created,
// uniquely named database, migrated to current, with a kura_api role
// pool. We re-build it here rather than share to keep internal/jobs from
// importing internal/data.
type jobsTestEnv struct {
	DB     *sql.DB
	APIDSN string
	Tenant string
}

func newJobsTestEnv(t *testing.T) jobsTestEnv {
	t.Helper()
	base := os.Getenv("KURA_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("KURA_TEST_DATABASE_URL not set; skipping integration test")
	}
	admin, err := db.Open(base)
	if err != nil {
		t.Fatalf("connect cluster: %v", err)
	}
	name := fmt.Sprintf("kura_jobs_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		admin.Close()
		t.Fatalf("create db: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		admin.Close()
		t.Fatalf("parse url: %v", err)
	}
	u.Path = "/" + name
	dsn := u.String()
	pool, err := db.Open(dsn)
	if err != nil {
		admin.Close()
		t.Fatalf("connect db: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`); err != nil {
			t.Logf("drop db: %v", err)
		}
		admin.Close()
	})
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	const pw = "kura-test-api-pw"
	if _, err := pool.Exec(`ALTER ROLE kura_api LOGIN PASSWORD '` + pw + `'`); err != nil {
		t.Fatalf("grant LOGIN to kura_api: %v", err)
	}
	apiURL, _ := url.Parse(dsn)
	apiURL.User = url.UserPassword("kura_api", pw)

	var tenant string
	if err := pool.QueryRow(`SELECT gen_random_uuid()`).Scan(&tenant); err != nil {
		t.Fatalf("tenant id: %v", err)
	}
	return jobsTestEnv{DB: pool, APIDSN: apiURL.String(), Tenant: tenant}
}

func openAPIPool(t *testing.T, env jobsTestEnv) *sql.DB {
	t.Helper()
	pool, err := db.Open(env.APIDSN)
	if err != nil {
		t.Fatalf("open api pool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// PostgresStore round-trips a job: submit, list, get all see the same
// row, and idempotent re-submit returns the existing job.
func TestPostgresStoreRoundTripAndIdempotency(t *testing.T) {
	env := newJobsTestEnv(t)
	pool := openAPIPool(t, env)
	store, err := NewPostgresStore(pool, env.Tenant)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	ctx := context.Background()

	j := Job{
		ID:             "j-1",
		Kind:           "backup",
		Status:         StatusPending,
		Actor:          "alex@example.com",
		IdempotencyKey: "k-1",
		Params:         json.RawMessage(`{"target":"primary"}`),
		CreatedAt:      time.Now().UTC(),
	}
	got, created, err := store.Submit(ctx, j)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if !created {
		t.Fatalf("first submit created=false; want true")
	}
	if got.ID != "j-1" || got.Status != StatusPending {
		t.Fatalf("got = %+v", got)
	}

	// Retry returns the existing job — same id, created=false. This is
	// the "retry finds existing work" leg of the criterion.
	again, created, err := store.Submit(ctx, Job{
		ID: "j-2", Kind: "backup", Actor: "alex@example.com",
		IdempotencyKey: "k-1", Status: StatusPending, CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("retry submit: %v", err)
	}
	if created {
		t.Fatalf("retry submit created=true; want false (idempotent)")
	}
	if again.ID != "j-1" {
		t.Fatalf("retry id = %q; want %q (the original)", again.ID, "j-1")
	}

	one, err := store.Get(ctx, "alex@example.com", "j-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(one.Params) != `{"target": "primary"}` && string(one.Params) != `{"target":"primary"}` {
		t.Fatalf("params = %q", string(one.Params))
	}

	list, err := store.List(ctx, "alex@example.com")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != "j-1" {
		t.Fatalf("list = %+v; want one job j-1", list)
	}
}

// Cross-tenant isolation: a store scoped to tenant B sees no jobs from
// tenant A, even by id. RLS binds the read; this is the same guarantee
// the records and users tables give.
func TestPostgresStoreTenantIsolation(t *testing.T) {
	env := newJobsTestEnv(t)
	pool := openAPIPool(t, env)
	storeA, err := NewPostgresStore(pool, env.Tenant)
	if err != nil {
		t.Fatal(err)
	}

	// A second tenant on the same DB.
	var tenantB string
	if err := env.DB.QueryRow(`SELECT gen_random_uuid()`).Scan(&tenantB); err != nil {
		t.Fatalf("second tenant id: %v", err)
	}
	storeB, err := NewPostgresStore(pool, tenantB)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := storeA.Submit(context.Background(), Job{
		ID: "a1", Kind: "backup", Actor: "alex@example.com",
		IdempotencyKey: "k", Status: StatusPending, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("storeA submit: %v", err)
	}

	_, err = storeB.Get(context.Background(), "alex@example.com", "a1")
	if !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("storeB.Get for tenantA's job: err = %v; want ErrJobNotFound", err)
	}
	list, err := storeB.List(context.Background(), "alex@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("storeB.List = %d jobs; want 0", len(list))
	}
}

// The full lifecycle through the worker: submit, claim, succeed. Each
// transition is durable; the timestamps land in the right columns.
func TestPostgresStoreLifecycle(t *testing.T) {
	env := newJobsTestEnv(t)
	pool := openAPIPool(t, env)
	store, err := NewPostgresStore(pool, env.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	j := Job{
		ID: "j-1", Kind: "backup", Actor: "alex@example.com",
		IdempotencyKey: "k", Status: StatusPending, CreatedAt: time.Now().UTC(),
		Params: json.RawMessage(`{}`),
	}
	if _, _, err := store.Submit(ctx, j); err != nil {
		t.Fatalf("submit: %v", err)
	}

	claimed, ok, err := store.ClaimNextPending(ctx)
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if claimed.Status != StatusRunning || claimed.StartedAt == nil {
		t.Fatalf("claimed = %+v; want running+started", claimed)
	}

	if err := store.MarkSucceeded(ctx, "j-1", json.RawMessage(`{"ok":true}`)); err != nil {
		t.Fatalf("mark succeeded: %v", err)
	}
	got, err := store.Get(ctx, "alex@example.com", "j-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusSucceeded {
		t.Fatalf("status=%q want succeeded", got.Status)
	}
	if got.FinishedAt == nil {
		t.Fatalf("FinishedAt nil; want set")
	}
	if string(got.Result) != `{"ok": true}` && string(got.Result) != `{"ok":true}` {
		t.Fatalf("result = %q", string(got.Result))
	}
}

// The criterion: a process restart leaves the ledger intact, and a
// retry through a fresh Manager finds the previous job. The "crash" is
// simulated by leaving a running job behind and constructing a new
// Manager that calls ResetOrphans on startup; the second submit with
// the same key sees the same id.
func TestPostgresStoreSurvivesProcessRestart(t *testing.T) {
	env := newJobsTestEnv(t)
	pool := openAPIPool(t, env)

	// Process 1: submit a job, claim it (worker starts on it), then
	// "crash" — return without finishing.
	mgr1 := NewManager(mustPgStore(t, pool, env.Tenant))
	mgr1.Register("backup", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})
	first, created, err := mgr1.Submit(context.Background(), "alex@example.com", "backup", "key-X", nil)
	if err != nil {
		t.Fatalf("mgr1 submit: %v", err)
	}
	if !created {
		t.Fatalf("mgr1 first submit created=false")
	}
	// Claim the job to put it in 'running', then crash.
	if _, ok, err := mgr1.store.ClaimNextPending(context.Background()); err != nil || !ok {
		t.Fatalf("mgr1 claim: ok=%v err=%v", ok, err)
	}

	// Process 2: a fresh manager over the same DB. Its startup recovery
	// resets the orphan; an idempotent re-submit with the same key
	// finds the existing job by id.
	mgr2 := NewManager(mustPgStore(t, pool, env.Tenant))
	mgr2.Register("backup", func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})
	if err := mgr2.ResetOrphans(context.Background()); err != nil {
		t.Fatalf("ResetOrphans: %v", err)
	}
	again, created, err := mgr2.Submit(context.Background(), "alex@example.com", "backup", "key-X", nil)
	if err != nil {
		t.Fatalf("mgr2 submit: %v", err)
	}
	if created {
		t.Fatalf("mgr2 retry submit created=true; want false (must find existing work)")
	}
	if again.ID != first.ID {
		t.Fatalf("mgr2 saw id %q; want the original %q", again.ID, first.ID)
	}
	// And the recovered job is back in pending — ready to be picked up.
	got, err := mgr2.Get(context.Background(), "alex@example.com", first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusPending {
		t.Fatalf("recovered status = %q; want %q", got.Status, StatusPending)
	}
}

func mustPgStore(t *testing.T, db *sql.DB, tenant string) *PostgresStore {
	t.Helper()
	s, err := NewPostgresStore(db, tenant)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	return s
}
