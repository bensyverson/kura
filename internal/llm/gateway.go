package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/bensyverson/kura/internal/identity"
)

// Errors returned by the LLM gateway.
var (
	// ErrDPANotOnFile is returned by NewGateway when the provider's data
	// processing agreement is not attested in the DPAConfig. It makes
	// startup fail closed: no gateway, no calls.
	ErrDPANotOnFile = errors.New("llm: provider DPA is not on file")
	// ErrEmptyModel is returned by Call when the request names no model.
	ErrEmptyModel = errors.New("llm: request model is empty")
	// ErrMissingDependency is returned by NewGateway when a required
	// collaborator is nil.
	ErrMissingDependency = errors.New("llm: gateway requires a provider, a metadata log, and a DPA config")
	// ErrMissingAPIKey is returned when an AnthropicProvider is
	// constructed without an API key. The key is injected at runtime
	// from the secrets manager; an empty one means that did not happen.
	ErrMissingAPIKey = errors.New("llm: anthropic API key is empty")
)

// Gateway is the thin gateway every LLM call goes through. It does three
// things and no more: it refuses to exist for a provider whose DPA is
// not on file, it records metadata for every call (hashes, never
// contents), and it fails closed if that metadata cannot be recorded.
// It holds no policy of its own — it is wiring around a Provider.
type Gateway struct {
	provider Provider
	log      MetadataLog
	dpa      *DPAConfig
	now      func() time.Time // injectable for tests
}

// NewGateway returns a Gateway for provider, recording call metadata to
// log. It performs the startup DPA check: if the controller's DPA is not
// on file for provider, it returns ErrDPANotOnFile and no gateway.
func NewGateway(provider Provider, log MetadataLog, dpa *DPAConfig) (*Gateway, error) {
	if provider == nil || log == nil || dpa == nil {
		return nil, ErrMissingDependency
	}
	if !dpa.OnFile(provider.Name()) {
		return nil, fmt.Errorf("%w: provider %q", ErrDPANotOnFile, provider.Name())
	}
	return &Gateway{provider: provider, log: log, dpa: dpa, now: time.Now}, nil
}

// Call runs req through the provider on behalf of actor. The actor must
// be a valid, authenticated principal. After the provider responds, Call
// records a metadata-only CallRecord — hashes of the prompt and
// response, never their contents — and fails closed if that record
// cannot be written: an LLM call Kura cannot log is one it does not
// return.
func (g *Gateway) Call(ctx context.Context, actor identity.Principal, req Request) (Response, error) {
	if err := actor.Valid(); err != nil {
		return Response{}, fmt.Errorf("llm: LLM access requires an authenticated principal: %w", err)
	}
	if req.Model == "" {
		return Response{}, ErrEmptyModel
	}

	resp, err := g.provider.Complete(ctx, req)
	if err != nil {
		return Response{}, fmt.Errorf("llm: provider call: %w", err)
	}

	rec := CallRecord{
		Time:         g.now(),
		Principal:    actor,
		Model:        req.Model,
		InputTokens:  resp.InputTokens,
		OutputTokens: resp.OutputTokens,
		PromptHash:   hashContent(req.Prompt),
		ResponseHash: hashContent(resp.Content),
	}
	if err := g.log.Record(ctx, rec); err != nil {
		return Response{}, fmt.Errorf("llm: recording call metadata: %w", err)
	}
	return resp, nil
}

// hashContent returns the SHA-256 hex digest of s.
func hashContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
