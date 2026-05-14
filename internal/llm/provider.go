package llm

import "context"

// Request is a single completion request to an LLM provider. Prompt is
// the content sent to the model; it is hashed for the call record and
// never stored.
type Request struct {
	// Model is the provider-specific model identifier.
	Model string
	// Prompt is the user content sent to the model.
	Prompt string
	// MaxTokens bounds the response length. Providers (Anthropic among
	// them) require it.
	MaxTokens int
}

// Response is a completion result. Content is the model's output; it is
// hashed for the call record and never stored.
type Response struct {
	// Content is the model's text output.
	Content string
	// InputTokens and OutputTokens are the provider-reported usage.
	InputTokens  int
	OutputTokens int
}

// Provider is one LLM provider. The gateway depends only on this
// interface, so the AnthropicProvider and the FakeProvider are
// interchangeable and the core's tests need no network.
type Provider interface {
	// Name identifies the provider (e.g. "anthropic"). The gateway uses
	// it to check the provider's DPA is on file.
	Name() string
	// Complete runs one completion request.
	Complete(ctx context.Context, req Request) (Response, error)
}

// FakeProvider is an in-memory Provider for tests: it returns a canned
// Response (or Err) and records what it was called with.
type FakeProvider struct {
	ProviderName string
	Response     Response
	Err          error

	LastRequest Request
	Calls       int
}

// Name returns the configured provider name.
func (f *FakeProvider) Name() string { return f.ProviderName }

// Complete records the request and returns the canned Response or Err.
func (f *FakeProvider) Complete(_ context.Context, req Request) (Response, error) {
	f.Calls++
	f.LastRequest = req
	if f.Err != nil {
		return Response{}, f.Err
	}
	return f.Response, nil
}
