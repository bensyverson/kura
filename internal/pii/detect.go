package pii

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Span is one detected occurrence of PII within a piece of text. Offset
// and Length are byte positions into the scanned string.
type Span struct {
	Category   Category `json:"category"`
	Offset     int      `json:"offset"`
	Length     int      `json:"length"`
	Confidence float64  `json:"confidence"`
}

// Detector scans text and reports the PII spans it contains. It is the
// narrow interface the core uses to reach the PII detection service; the
// detection service itself runs as a separate, internal-only process.
type Detector interface {
	Detect(ctx context.Context, text string) ([]Span, error)
}

// FakeDetector is an in-memory Detector for unit tests: it reports a span
// wherever a registered substring appears in the scanned text, so the
// core's tests never need the live detection service.
type FakeDetector struct {
	rules []fakeRule
}

type fakeRule struct {
	substring  string
	category   Category
	confidence float64
}

var _ Detector = (*FakeDetector)(nil)

// NewFakeDetector returns a FakeDetector with no rules.
func NewFakeDetector() *FakeDetector { return &FakeDetector{} }

// Register teaches the fake that substring is an occurrence of category.
// It returns the detector so registrations can be chained.
func (f *FakeDetector) Register(substring string, category Category, confidence float64) *FakeDetector {
	f.rules = append(f.rules, fakeRule{substring, category, confidence})
	return f
}

// Detect reports a span for every occurrence of every registered
// substring.
func (f *FakeDetector) Detect(_ context.Context, text string) ([]Span, error) {
	var spans []Span
	for _, r := range f.rules {
		base := 0
		for {
			i := strings.Index(text[base:], r.substring)
			if i < 0 {
				break
			}
			spans = append(spans, Span{
				Category:   r.category,
				Offset:     base + i,
				Length:     len(r.substring),
				Confidence: r.confidence,
			})
			base += i + len(r.substring)
		}
	}
	return spans, nil
}

// ServiceDetector is the real Detector: an HTTP client for the
// self-hosted PII detection service. The service wraps the OpenAI
// Privacy Filter model behind the narrow JSON contract documented in
// docs/concepts/pii.md.
type ServiceDetector struct {
	endpoint string
	client   *http.Client
}

var _ Detector = (*ServiceDetector)(nil)

// NewServiceDetector returns a ServiceDetector that posts scan requests
// to endpoint.
func NewServiceDetector(endpoint string) *ServiceDetector {
	return &ServiceDetector{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

type detectRequest struct {
	Text string `json:"text"`
}

type detectResponse struct {
	Spans []Span `json:"spans"`
}

// Detect posts text to the detection service and returns the spans it
// reports. A span carrying a category Kura does not recognize is a
// misconfigured service, and fails loudly rather than passing through.
func (d *ServiceDetector) Detect(ctx context.Context, text string) ([]Span, error) {
	body, err := json.Marshal(detectRequest{Text: text})
	if err != nil {
		return nil, fmt.Errorf("pii: encode detect request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("pii: build detect request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pii: call detection service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pii: detection service returned %s", resp.Status)
	}
	var out detectResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("pii: decode detection response: %w", err)
	}
	for _, s := range out.Spans {
		if !s.Category.Valid() {
			return nil, fmt.Errorf("pii: detection service returned unrecognized category %q", s.Category)
		}
	}
	return out.Spans, nil
}
