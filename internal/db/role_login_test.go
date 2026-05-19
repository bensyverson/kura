package db

import (
	"context"
	"sync"
	"testing"
)

// TestConcurrentRoleLoginIsSerialized guards the advisory lock in
// grantRoleLogin. The component roles are cluster-global, so concurrent
// `ALTER ROLE … LOGIN PASSWORD` against the same role row races with
// "tuple concurrently updated" — which is exactly what made the integration
// suite flaky under parallel `go test ./...`. grantRoleLogin serializes the
// mutation with a transaction-scoped advisory lock; this test fires many
// concurrent grants and asserts none fail. Without the lock it fails
// reliably (most goroutines error), so it catches a regression that removes
// the serialization.
func TestConcurrentRoleLoginIsSerialized(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	if err := Migrate(ctx, env.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			if err := grantRoleLogin(ctx, "kura_api", "kura-test-role-pw"); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent role-login failed (advisory lock not serializing?): %v", err)
	}
}
