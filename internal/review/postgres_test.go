package review

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestNewPostgresStoreRejectsMisconfiguration(t *testing.T) {
	if _, err := NewPostgresStore(nil, "tenant"); !errors.Is(err, ErrMissingDependency) {
		t.Errorf("nil db: err = %v, want ErrMissingDependency", err)
	}
}

func TestPostgresStoreIsAStore(t *testing.T) {
	var _ Store = (*PostgresStore)(nil)
}

// A review round-trips through Postgres: created with a snapshot, decisions
// recorded, completed, and read back as an immutable artifact.
func TestPostgresStoreReviewLifecycle(t *testing.T) {
	env := newReviewTestEnv(t)
	tenant := newTenantID(t, env)
	store, err := NewPostgresStore(connectAsAPIRole(t, env), tenant)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	ctx := context.Background()

	created, err := store.Create(ctx, "reviewer@client.com", []Item{
		{Email: "ada@client.com", RolesAtReview: []string{"admin"}},
		{Email: "boss@client.com", RolesAtReview: []string{"auditor", "user"}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" || created.Status != StatusOpen || created.StartedAt.IsZero() {
		t.Fatalf("created review malformed: %+v", created)
	}

	if err := store.Decide(ctx, created.ID, "ada@client.com", DecisionApproved, ""); err != nil {
		t.Fatalf("Decide approve: %v", err)
	}
	if err := store.Decide(ctx, created.ID, "boss@client.com", DecisionRemoved, "left the firm"); err != nil {
		t.Fatalf("Decide remove: %v", err)
	}

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	byEmail := map[string]Item{}
	for _, it := range got.Items {
		byEmail[it.Email] = it
	}
	if byEmail["ada@client.com"].Decision != DecisionApproved {
		t.Errorf("ada decision = %q, want approved", byEmail["ada@client.com"].Decision)
	}
	boss := byEmail["boss@client.com"]
	if boss.Decision != DecisionRemoved || boss.Note != "left the firm" {
		t.Errorf("boss item = %+v, want removed with note", boss)
	}
	if !slices.Equal(boss.RolesAtReview, []string{"auditor", "user"}) {
		t.Errorf("boss roles snapshot = %v, want [auditor user]", boss.RolesAtReview)
	}

	done, err := store.Complete(ctx, created.ID)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if done.Status != StatusCompleted || done.CompletedAt == nil {
		t.Errorf("completed review malformed: %+v", done)
	}

	// Immutable after completion.
	if err := store.Decide(ctx, created.ID, "ada@client.com", DecisionRemoved, ""); !errors.Is(err, ErrClosed) {
		t.Errorf("Decide on completed = %v, want ErrClosed", err)
	}
}

func TestPostgresStoreErrorsAndList(t *testing.T) {
	env := newReviewTestEnv(t)
	tenant := newTenantID(t, env)
	store, err := NewPostgresStore(connectAsAPIRole(t, env), tenant)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	ctx := context.Background()

	if _, err := store.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing = %v, want ErrNotFound", err)
	}
	if _, err := store.Complete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Complete missing = %v, want ErrNotFound", err)
	}
	if _, err := store.Create(ctx, "r@x", nil); !errors.Is(err, ErrEmptyReview) {
		t.Errorf("Create empty = %v, want ErrEmptyReview", err)
	}

	r, err := store.Create(ctx, "r@x", []Item{{Email: "a@client.com", RolesAtReview: []string{"user"}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.Decide(ctx, r.ID, "ghost@client.com", DecisionApproved, ""); !errors.Is(err, ErrSubjectNotFound) {
		t.Errorf("Decide unknown subject = %v, want ErrSubjectNotFound", err)
	}
	if err := store.Decide(ctx, r.ID, "a@client.com", DecisionPending, ""); !errors.Is(err, ErrInvalidDecision) {
		t.Errorf("Decide pending = %v, want ErrInvalidDecision", err)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != r.ID {
		t.Errorf("List = %+v, want the one created review", list)
	}
	if len(list[0].Items) != 1 || list[0].Items[0].Email != "a@client.com" {
		t.Errorf("List item not hydrated: %+v", list[0].Items)
	}
}

// RLS isolates reviews by tenant: a store scoped to one tenant cannot see
// another tenant's reviews.
func TestPostgresStoreTenantIsolation(t *testing.T) {
	env := newReviewTestEnv(t)
	tenantA := newTenantID(t, env)
	tenantB := newTenantID(t, env)
	pool := connectAsAPIRole(t, env)
	storeA, _ := NewPostgresStore(pool, tenantA)
	storeB, _ := NewPostgresStore(pool, tenantB)
	ctx := context.Background()

	created, err := storeA.Create(ctx, "r@x", []Item{{Email: "a@client.com", RolesAtReview: []string{"user"}}})
	if err != nil {
		t.Fatalf("Create in tenant A: %v", err)
	}

	if _, err := storeB.Get(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("tenant B reading tenant A's review = %v, want ErrNotFound", err)
	}
	list, err := storeB.List(ctx)
	if err != nil {
		t.Fatalf("List in tenant B: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("tenant B sees %d reviews, want 0 (isolation)", len(list))
	}
}
