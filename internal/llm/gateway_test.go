package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bensyverson/kura/internal/identity"
)

func testActor() identity.Principal {
	return identity.Principal{Type: identity.PrincipalService, ID: "kura-api"}
}

// dpaFor returns a DPAConfig with provider's DPA attested as on file.
func dpaFor(provider string) *DPAConfig {
	c := NewDPAConfig()
	c.Attest(provider)
	return c
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestDPAConfigReportsAttestedProviders(t *testing.T) {
	c := NewDPAConfig()
	if c.OnFile("anthropic") {
		t.Error("OnFile = true before any attestation, want false")
	}
	c.Attest("anthropic")
	if !c.OnFile("anthropic") {
		t.Error("OnFile = false after Attest, want true")
	}
	if c.OnFile("openai") {
		t.Error("OnFile for un-attested provider = true, want false")
	}
}

func TestNewGatewayFailsClosedWhenDPANotOnFile(t *testing.T) {
	provider := &FakeProvider{ProviderName: "anthropic"}
	_, err := NewGateway(provider, NewMemLog(), NewDPAConfig())
	if !errors.Is(err, ErrDPANotOnFile) {
		t.Fatalf("NewGateway without DPA err = %v, want ErrDPANotOnFile", err)
	}
}

func TestNewGatewaySucceedsWhenDPAOnFile(t *testing.T) {
	provider := &FakeProvider{ProviderName: "anthropic"}
	g, err := NewGateway(provider, NewMemLog(), dpaFor("anthropic"))
	if err != nil {
		t.Fatalf("NewGateway with DPA on file: %v", err)
	}
	if g == nil {
		t.Fatal("NewGateway returned nil gateway")
	}
}

func TestGatewayCallReturnsProviderResponse(t *testing.T) {
	provider := &FakeProvider{
		ProviderName: "anthropic",
		Response:     Response{Content: "the answer", InputTokens: 12, OutputTokens: 3},
	}
	g, _ := NewGateway(provider, NewMemLog(), dpaFor("anthropic"))

	resp, err := g.Call(context.Background(), testActor(), Request{Model: "claude-x", Prompt: "the question"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Content != "the answer" {
		t.Errorf("resp.Content = %q, want %q", resp.Content, "the answer")
	}
}

func TestGatewayCallRecordsMetadataAsHashesNotContents(t *testing.T) {
	log := NewMemLog()
	provider := &FakeProvider{
		ProviderName: "anthropic",
		Response:     Response{Content: "the answer", InputTokens: 12, OutputTokens: 3},
	}
	g, _ := NewGateway(provider, log, dpaFor("anthropic"))

	req := Request{Model: "claude-x", Prompt: "the question"}
	if _, err := g.Call(context.Background(), testActor(), req); err != nil {
		t.Fatalf("Call: %v", err)
	}

	records := log.Records()
	if len(records) != 1 {
		t.Fatalf("recorded %d call records, want 1", len(records))
	}
	rec := records[0]
	if rec.Principal.ID != "kura-api" {
		t.Errorf("record Principal.ID = %q, want %q", rec.Principal.ID, "kura-api")
	}
	if rec.Model != "claude-x" {
		t.Errorf("record Model = %q, want %q", rec.Model, "claude-x")
	}
	if rec.InputTokens != 12 || rec.OutputTokens != 3 {
		t.Errorf("record tokens = (%d, %d), want (12, 3)", rec.InputTokens, rec.OutputTokens)
	}
	if rec.Time.IsZero() {
		t.Error("record Time is zero, want a timestamp")
	}

	// The record carries hashes, never the contents themselves.
	if rec.PromptHash != sha256hex("the question") {
		t.Errorf("record PromptHash = %q, want sha256 of the prompt", rec.PromptHash)
	}
	if rec.ResponseHash != sha256hex("the answer") {
		t.Errorf("record ResponseHash = %q, want sha256 of the response", rec.ResponseHash)
	}
	if rec.PromptHash == "the question" || rec.ResponseHash == "the answer" {
		t.Error("record stored raw content where a hash was expected")
	}
}

func TestGatewayCallRejectsInvalidActor(t *testing.T) {
	log := NewMemLog()
	provider := &FakeProvider{ProviderName: "anthropic"}
	g, _ := NewGateway(provider, log, dpaFor("anthropic"))

	_, err := g.Call(context.Background(), identity.Principal{}, Request{Model: "claude-x", Prompt: "q"})
	if err == nil {
		t.Fatal("Call with invalid actor: want error, got nil")
	}
	if provider.Calls != 0 {
		t.Errorf("provider called %d times for an invalid actor, want 0", provider.Calls)
	}
	if len(log.Records()) != 0 {
		t.Errorf("rejected call recorded %d records, want 0", len(log.Records()))
	}
}

func TestGatewayCallRejectsEmptyModel(t *testing.T) {
	provider := &FakeProvider{ProviderName: "anthropic"}
	g, _ := NewGateway(provider, NewMemLog(), dpaFor("anthropic"))

	_, err := g.Call(context.Background(), testActor(), Request{Prompt: "q"})
	if !errors.Is(err, ErrEmptyModel) {
		t.Errorf("Call with empty model err = %v, want ErrEmptyModel", err)
	}
}

func TestGatewayCallPropagatesProviderError(t *testing.T) {
	log := NewMemLog()
	provider := &FakeProvider{ProviderName: "anthropic", Err: errors.New("provider down")}
	g, _ := NewGateway(provider, log, dpaFor("anthropic"))

	_, err := g.Call(context.Background(), testActor(), Request{Model: "claude-x", Prompt: "q"})
	if err == nil {
		t.Fatal("Call with failing provider: want error, got nil")
	}
	if len(log.Records()) != 0 {
		t.Errorf("failed provider call recorded %d records, want 0", len(log.Records()))
	}
}

// failingLog is a MetadataLog whose Record always errors.
type failingLog struct{}

func (failingLog) Record(context.Context, CallRecord) error {
	return errors.New("metadata log down")
}

func TestGatewayCallFailsClosedWhenMetadataLogFails(t *testing.T) {
	provider := &FakeProvider{
		ProviderName: "anthropic",
		Response:     Response{Content: "the answer", InputTokens: 1, OutputTokens: 1},
	}
	g, _ := NewGateway(provider, failingLog{}, dpaFor("anthropic"))

	resp, err := g.Call(context.Background(), testActor(), Request{Model: "claude-x", Prompt: "q"})
	if err == nil {
		t.Fatal("Call with failing metadata log: want error, got nil")
	}
	if resp.Content != "" {
		t.Errorf("Call with failing metadata log returned content %q, want empty — must fail closed", resp.Content)
	}
}
