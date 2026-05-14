package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/llm"
)

// llmServer builds a server wired with the given LLM gateway (which may
// be nil, standing in for a startup DPA check that failed). It returns
// the server and a token for an authenticated caller.
func llmServer(t *testing.T, gateway *llm.Gateway) (srv *Server, token string) {
	t.Helper()
	cfg, auth := testConfig(t, "127.0.0.1:0")
	cfg.LLM = gateway
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, err = auth.Issue(identity.Principal{
		Type:   identity.PrincipalConsultant,
		ID:     "alex@examplefirm.com",
		Email:  "alex@examplefirm.com",
		Domain: "examplefirm.com",
	}, time.Hour)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}
	return srv, token
}

// liveGateway builds a gateway over a FakeProvider with the DPA attested,
// returning it and the metadata log so a test can inspect what was
// recorded.
func liveGateway(t *testing.T, resp llm.Response) (*llm.Gateway, *llm.MemLog) {
	t.Helper()
	provider := &llm.FakeProvider{ProviderName: "anthropic", Response: resp}
	log := llm.NewMemLog()
	dpa := llm.NewDPAConfig()
	dpa.Attest(provider.Name())
	g, err := llm.NewGateway(provider, log, dpa)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return g, log
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// YSN: an LLM call made through the endpoint is metadata-logged — the
// metadata log gains a CallRecord carrying the principal, the model, the
// token counts, and SHA-256 hashes of the prompt and response, never
// their contents.
func TestLLMEndpointMetadataLogsCalls(t *testing.T) {
	gateway, log := liveGateway(t, llm.Response{Content: "the model reply", InputTokens: 11, OutputTokens: 7})
	srv, token := llmServer(t, gateway)

	rec := doReq(t, srv, http.MethodPost, "/api/llm", token,
		`{"model":"claude-opus-4-7","prompt":"the secret prompt","max_tokens":256}`)
	if rec.status != http.StatusOK {
		t.Fatalf("POST /api/llm: status = %d, want 200; body %s", rec.status, rec.body.String())
	}

	var body struct {
		Content      string `json:"content"`
		InputTokens  int    `json:"input_tokens"`
		OutputTokens int    `json:"output_tokens"`
	}
	if err := json.Unmarshal(rec.body.Bytes(), &body); err != nil {
		t.Fatalf("decoding llm body %q: %v", rec.body.String(), err)
	}
	if body.Content != "the model reply" || body.InputTokens != 11 || body.OutputTokens != 7 {
		t.Errorf("response body = %+v, want the provider's reply and token counts", body)
	}

	records := log.Records()
	if len(records) != 1 {
		t.Fatalf("metadata log has %d records, want exactly 1 per call", len(records))
	}
	got := records[0]
	if got.Principal.ID != "alex@examplefirm.com" {
		t.Errorf("logged principal = %q, want the calling consultant", got.Principal.ID)
	}
	if got.Model != "claude-opus-4-7" {
		t.Errorf("logged model = %q, want claude-opus-4-7", got.Model)
	}
	if got.InputTokens != 11 || got.OutputTokens != 7 {
		t.Errorf("logged tokens = %d/%d, want 11/7", got.InputTokens, got.OutputTokens)
	}
	if got.PromptHash != sha256hex("the secret prompt") {
		t.Errorf("logged prompt hash = %q, want the SHA-256 of the prompt", got.PromptHash)
	}
	if got.ResponseHash != sha256hex("the model reply") {
		t.Errorf("logged response hash = %q, want the SHA-256 of the response", got.ResponseHash)
	}
}

// yKz: when the startup DPA check failed there is no gateway, and the
// endpoint refuses to serve — a consistent 503, not a 404 that would
// make the endpoint look as though it never existed.
func TestLLMEndpointRefusesWhenGatewayUnavailable(t *testing.T) {
	// A nil gateway is what serveConfig leaves behind when NewGateway
	// returned ErrDPANotOnFile at startup.
	srv, token := llmServer(t, nil)

	rec := doReq(t, srv, http.MethodPost, "/api/llm", token,
		`{"model":"claude-opus-4-7","prompt":"hello","max_tokens":256}`)
	if rec.status != http.StatusServiceUnavailable {
		t.Errorf("POST /api/llm with no gateway: status = %d, want 503", rec.status)
	}
}

// An unauthenticated request never reaches the gateway — requireAuth
// rejects it first, like every other /api route.
func TestLLMEndpointRequiresAuth(t *testing.T) {
	gateway, _ := liveGateway(t, llm.Response{Content: "reply"})
	srv, _ := llmServer(t, gateway)

	rec := doReq(t, srv, http.MethodPost, "/api/llm", "",
		`{"model":"claude-opus-4-7","prompt":"hello","max_tokens":256}`)
	if rec.status != http.StatusUnauthorized {
		t.Errorf("POST /api/llm unauthenticated: status = %d, want 401", rec.status)
	}
}

// A malformed body and a request naming no model are both client errors.
func TestLLMEndpointRejectsBadRequest(t *testing.T) {
	gateway, _ := liveGateway(t, llm.Response{Content: "reply"})
	srv, token := llmServer(t, gateway)

	if rec := doReq(t, srv, http.MethodPost, "/api/llm", token, `{not json`); rec.status != http.StatusBadRequest {
		t.Errorf("POST /api/llm with malformed body: status = %d, want 400", rec.status)
	}
	if rec := doReq(t, srv, http.MethodPost, "/api/llm", token, `{"prompt":"hello","max_tokens":256}`); rec.status != http.StatusBadRequest {
		t.Errorf("POST /api/llm with no model: status = %d, want 400", rec.status)
	}
}

// The LLM route is a gated route — it goes through the core LLM gateway,
// so the DPA check and metadata logging are enforced by construction,
// exactly like the data and admin routes go through the core gate.
func TestLLMRouteIsGated(t *testing.T) {
	gateway, _ := liveGateway(t, llm.Response{Content: "reply"})
	srv, _ := llmServer(t, gateway)

	h, ok := srv.apiRoutes["POST /api/llm"]
	if !ok {
		t.Fatal("LLM route is not registered")
	}
	if _, gated := h.(gatedRoute); !gated {
		t.Errorf("LLM route is %T, not a gatedRoute", h)
	}
}
