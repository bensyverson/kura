package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAnthropicProviderRequiresAPIKey(t *testing.T) {
	if _, err := NewAnthropicProvider(""); !errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("NewAnthropicProvider with empty key err = %v, want ErrMissingAPIKey", err)
	}
}

func TestAnthropicProviderNameIsAnthropic(t *testing.T) {
	p, err := NewAnthropicProvider("sk-test")
	if err != nil {
		t.Fatalf("NewAnthropicProvider: %v", err)
	}
	if p.Name() != "anthropic" {
		t.Errorf("Name() = %q, want %q", p.Name(), "anthropic")
	}
}

func TestAnthropicProviderCompleteSendsRequestAndParsesResponse(t *testing.T) {
	var gotKey, gotVersion string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"the answer"}],"usage":{"input_tokens":12,"output_tokens":3}}`))
	}))
	defer srv.Close()

	p, _ := NewAnthropicProvider("sk-test")
	p.baseURL = srv.URL
	p.client = srv.Client()

	resp, err := p.Complete(context.Background(), Request{Model: "claude-x", Prompt: "the question", MaxTokens: 256})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content != "the answer" {
		t.Errorf("resp.Content = %q, want %q", resp.Content, "the answer")
	}
	if resp.InputTokens != 12 || resp.OutputTokens != 3 {
		t.Errorf("resp tokens = (%d, %d), want (12, 3)", resp.InputTokens, resp.OutputTokens)
	}
	if gotKey != "sk-test" {
		t.Errorf("x-api-key header = %q, want %q", gotKey, "sk-test")
	}
	if gotVersion == "" {
		t.Error("anthropic-version header not set")
	}
	if gotBody["model"] != "claude-x" {
		t.Errorf("request body model = %v, want %q", gotBody["model"], "claude-x")
	}
	if gotBody["messages"] == nil {
		t.Error("request body has no messages")
	}
}

func TestAnthropicProviderCompleteServerErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p, _ := NewAnthropicProvider("sk-test")
	p.baseURL = srv.URL
	p.client = srv.Client()

	if _, err := p.Complete(context.Background(), Request{Model: "claude-x", Prompt: "q", MaxTokens: 16}); err == nil {
		t.Fatal("Complete against 500: want error, got nil")
	}
}
