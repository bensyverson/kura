package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// anthropicAPIBaseURL is the public Anthropic API. Construction points
// the provider here; tests override AnthropicProvider.baseURL.
const anthropicAPIBaseURL = "https://api.anthropic.com"

// anthropicVersion is the Anthropic API version header value.
const anthropicVersion = "2023-06-01"

// AnthropicProvider is the production Provider: it calls Anthropic's
// Messages API. The default data flow is the client owning the Anthropic
// account, so the API key is the client's — supplied to the constructor,
// injected at runtime from the secrets manager, never baked in.
type AnthropicProvider struct {
	apiKey string

	// baseURL and client are the HTTP target. They default to the
	// public Anthropic API and a timeout-bounded client; tests override
	// them to point at a local server.
	baseURL string
	client  *http.Client
}

// NewAnthropicProvider returns an AnthropicProvider authenticating with
// apiKey. The key is required; an empty one means runtime injection did
// not happen.
func NewAnthropicProvider(apiKey string) (*AnthropicProvider, error) {
	if apiKey == "" {
		return nil, ErrMissingAPIKey
	}
	return &AnthropicProvider{
		apiKey:  apiKey,
		baseURL: anthropicAPIBaseURL,
		client:  &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// Name returns "anthropic".
func (p *AnthropicProvider) Name() string { return "anthropic" }

// anthropicMessage is one message in the Messages API request.
type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicRequest is the Messages API request body.
type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

// anthropicResponse is the subset of the Messages API response Kura uses.
type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// Complete runs one completion request against Anthropic's Messages API.
func (p *AnthropicProvider) Complete(ctx context.Context, req Request) (Response, error) {
	body, err := json.Marshal(anthropicRequest{
		Model:     req.Model,
		MaxTokens: req.MaxTokens,
		Messages:  []anthropicMessage{{Role: "user", Content: req.Prompt}},
	})
	if err != nil {
		return Response{}, fmt.Errorf("llm: encoding anthropic request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("llm: building anthropic request: %w", err)
	}
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)
	httpReq.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("llm: anthropic request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return Response{}, fmt.Errorf("llm: anthropic returned %s: %s", resp.Status, msg)
	}

	var parsed anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return Response{}, fmt.Errorf("llm: decoding anthropic response: %w", err)
	}

	var content strings.Builder
	for _, block := range parsed.Content {
		if block.Type == "text" {
			content.WriteString(block.Text)
		}
	}
	return Response{
		Content:      content.String(),
		InputTokens:  parsed.Usage.InputTokens,
		OutputTokens: parsed.Usage.OutputTokens,
	}, nil
}
