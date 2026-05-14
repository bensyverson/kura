package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

// kura serve must start, bind a real socket, serve its health endpoints,
// and shut down gracefully when its context is cancelled.
func TestServerServesHealthAndShutsDownGracefully(t *testing.T) {
	srv := New(Config{Addr: "127.0.0.1:0"})

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.Run(ctx) }()

	select {
	case <-srv.Ready():
	case err := <-errc:
		t.Fatalf("server exited before becoming ready: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("server never became ready")
	}

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get("http://" + srv.BoundAddr() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", path, resp.StatusCode)
		}
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Run returned error on graceful shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down within timeout after context cancel")
	}
}

// An unauthenticated request to a data route must be rejected before any
// business-logic handler runs.
func TestUnauthenticatedDataRouteRejectedBeforeBusinessLogic(t *testing.T) {
	srv := New(Config{Addr: "127.0.0.1:0"})

	req, _ := http.NewRequest(http.MethodGet, "/api/people/89", nil)
	rec := newRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for unauthenticated /api request", rec.status)
	}
}

// A request that does carry a credential is allowed past the auth gate
// (the skeleton has no data handlers yet, so it 404s rather than 401s).
func TestCredentialedDataRoutePassesAuthGate(t *testing.T) {
	srv := New(Config{Addr: "127.0.0.1:0"})

	req, _ := http.NewRequest(http.MethodGet, "/api/people/89", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := newRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.status == http.StatusUnauthorized {
		t.Errorf("credentialed /api request was rejected by the auth gate (status %d)", rec.status)
	}
}
