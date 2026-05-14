package pii

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFakeDetectorFindsRegisteredSpans(t *testing.T) {
	const text = "please contact alice@example.com today"
	d := NewFakeDetector().Register("alice@example.com", CategoryEmail, 0.97)

	spans, err := d.Detect(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Category != CategoryEmail {
		t.Errorf("category = %q, want %q", s.Category, CategoryEmail)
	}
	if got := text[s.Offset : s.Offset+s.Length]; got != "alice@example.com" {
		t.Errorf("span offset/length point at %q, want the email", got)
	}
	if s.Confidence != 0.97 {
		t.Errorf("confidence = %v, want 0.97", s.Confidence)
	}
}

func TestFakeDetectorFindsMultipleOccurrences(t *testing.T) {
	d := NewFakeDetector().Register("secret", CategorySecret, 1.0)
	spans, err := d.Detect(context.Background(), "secret and another secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
}

func TestFakeDetectorNoMatch(t *testing.T) {
	d := NewFakeDetector().Register("alice@example.com", CategoryEmail, 1.0)
	spans, err := d.Detect(context.Background(), "nothing sensitive here")
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 0 {
		t.Errorf("expected no spans, got %d", len(spans))
	}
}

func TestServiceDetectorParsesSpans(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req detectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("service got undecodable request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(detectResponse{Spans: []Span{
			{Category: CategoryEmail, Offset: 0, Length: 17, Confidence: 0.98},
		}})
	}))
	defer srv.Close()

	d := &ServiceDetector{endpoint: srv.URL, client: srv.Client()}
	spans, err := d.Detect(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 1 || spans[0].Category != CategoryEmail || spans[0].Confidence != 0.98 {
		t.Errorf("unexpected spans: %+v", spans)
	}
}

func TestServiceDetectorRejectsUnknownCategory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"spans":[{"category":"ssn","offset":0,"length":3,"confidence":1}]}`))
	}))
	defer srv.Close()

	d := &ServiceDetector{endpoint: srv.URL, client: srv.Client()}
	if _, err := d.Detect(context.Background(), "x"); err == nil {
		t.Error("expected an error for an unrecognized PII category")
	}
}

func TestServiceDetectorRejectsErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := &ServiceDetector{endpoint: srv.URL, client: srv.Client()}
	if _, err := d.Detect(context.Background(), "x"); err == nil {
		t.Error("expected an error for a 500 response")
	}
}
