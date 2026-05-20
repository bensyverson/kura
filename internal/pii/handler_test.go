package pii

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The handler is the server side of the same contract ServiceDetector is
// the client of: a round trip through it must return what the wrapped
// Detector found, with offsets intact.
func TestHandlerRoundTripsWithServiceDetector(t *testing.T) {
	d := NewFakeDetector().Register("alice@example.com", CategoryEmail, 0.9)
	srv := httptest.NewServer(Handler(d))
	defer srv.Close()

	client := &ServiceDetector{endpoint: srv.URL, client: srv.Client()}
	const text = "write alice@example.com here"
	spans, err := client.Detect(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if got := text[spans[0].Offset : spans[0].Offset+spans[0].Length]; got != "alice@example.com" {
		t.Errorf("round-tripped span points at %q, want the email", got)
	}
}

// A body that is not a detect request is a 400, not a panic.
func TestHandlerRejectsBadBody(t *testing.T) {
	srv := httptest.NewServer(Handler(NewFakeDetector()))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}
