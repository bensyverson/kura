package server

import (
	"errors"
	"net/http"

	"github.com/bensyverson/kura/internal/llm"
)

// registerLLMRoute mounts the LLM gateway endpoint. It is always mounted,
// even when the gateway is nil: a nil gateway means the startup DPA check
// did not pass, and the handler then answers 503 — a reported
// "unavailable" — rather than letting the route 404 as though the feature
// never existed.
func (s *Server) registerLLMRoute() {
	s.registerLLM("POST /api/llm", s.cfg.LLM)
}

// llmHandler brokers a completion request through the core LLM gateway.
// It is a gatedRoute: the LLM gateway is the LLM call's core enforcement,
// the way gate.Gate is the data path's. The gateway will not even exist
// for a provider whose DPA is not on file, and it metadata-logs every
// call it does make — so routing through it is what makes the DPA check
// and the contents-never logging structural rather than a courtesy the
// handler could forget.
type llmHandler struct {
	gateway *llm.Gateway
}

func (*llmHandler) gatedThroughCore() {}

// registerLLM mounts the LLM route under /api/. Like the data and admin
// registrars it produces a gatedRoute — an *llmHandler — so the route
// delegates to core enforcement by construction; apiRoutes cannot hold a
// handler that does not.
func (s *Server) registerLLM(pattern string, gateway *llm.Gateway) {
	if s.apiRoutes == nil {
		s.apiRoutes = make(map[string]gatedRoute)
	}
	s.apiRoutes[pattern] = &llmHandler{gateway: gateway}
}

// llmRequest is the body of POST /api/llm.
type llmRequest struct {
	Model     string `json:"model"`
	Prompt    string `json:"prompt"`
	MaxTokens int    `json:"max_tokens"`
}

// llmResponse is the body POST /api/llm returns: the model's output and
// the provider-reported token usage. The prompt and the response content
// are never echoed into any log — only this live response carries them,
// and only back to the caller that sent the prompt.
type llmResponse struct {
	Content      string `json:"content"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
}

// ServeHTTP brokers one completion request. A nil gateway — the startup
// DPA check did not pass — refuses the request with 503 before anything
// else. Otherwise the request is run through the gateway, which records
// the call metadata and fails closed if it cannot; the handler only
// renders the outcome.
func (h *llmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.gateway == nil {
		http.Error(w, "llm gateway unavailable: no provider DPA on file", http.StatusServiceUnavailable)
		return
	}
	principal, ok := principalFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body llmRequest
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp, err := h.gateway.Call(r.Context(), principal, llm.Request{
		Model:     body.Model,
		Prompt:    body.Prompt,
		MaxTokens: body.MaxTokens,
	})
	if err != nil {
		writeLLMError(w, err)
		return
	}
	writeJSON(w, llmResponse{
		Content:      resp.Content,
		InputTokens:  resp.InputTokens,
		OutputTokens: resp.OutputTokens,
	})
}

// writeLLMError maps a gateway error to an HTTP status. A request naming
// no model is a client error; anything else — a provider failure, a
// metadata-log write that failed — is a 500: the gateway fails closed and
// returns no response, and the handler does not leak why past the status.
func writeLLMError(w http.ResponseWriter, err error) {
	if errors.Is(err, llm.ErrEmptyModel) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	http.Error(w, "internal error", http.StatusInternalServerError)
}
