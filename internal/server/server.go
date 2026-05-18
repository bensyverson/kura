// Package server is the HTTP API: Kura's only public surface. It is a
// thin adapter over the core enforcement library — it does routing,
// middleware, and graceful lifecycle, and delegates every policy
// decision, audit write, and masking rule to internal/gate. No HTML and
// no dashboard pages: a remote attacker sees just the JSON API plus the
// OAuth callback.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/llm"
)

// defaultShutdownTimeout bounds how long Run waits for in-flight requests
// to finish once its context is cancelled.
const defaultShutdownTimeout = 10 * time.Second

// defaultTokenTTL is the lifetime of the Kura tokens the OAuth callback
// mints when Config.TokenTTL is unset.
const defaultTokenTTL = 12 * time.Hour

// ErrMissingDependency is returned by New when a required enforcement
// collaborator is nil. A server that cannot resolve a token, record an
// audit event, run a request through the core gate, read a record, or
// manage the authorized-user list must not come into existence.
var ErrMissingDependency = errors.New("server: requires an authenticator, an audit recorder, a google authenticator, the core gate, a record store, a user store, an IdP directory, and an audit store")

// Config is the wiring a Server needs. Addr and the enforcement
// collaborators (Auth, Recorder, Google) are required; the rest have
// working defaults.
type Config struct {
	// Addr is the TCP address to bind, in host:port form. ":0" binds an
	// arbitrary free port — useful in tests, where BoundAddr then reports
	// the chosen one.
	Addr string
	// Logger receives one structured line per request. Defaults to a text
	// logger on stderr — request logs are operational telemetry, not
	// program output.
	Logger *slog.Logger
	// ShutdownTimeout bounds graceful shutdown. Defaults to 10s.
	ShutdownTimeout time.Duration

	// Auth resolves a request's bearer token to a principal and mints
	// the tokens the OAuth callback hands back. Required.
	Auth *identity.Authenticator
	// Recorder is the audit write side. Every authentication — at the
	// OAuth callback and at the per-request auth gate — funnels through
	// it. Required.
	Recorder *audit.Recorder
	// Google performs the Google side of the OAuth flow. Required.
	Google IdentityProvider
	// Gate is the core enforcement entrypoint. Every data route is a thin
	// binding over Gate.Access or Gate.List — the server holds no other
	// way to read a record. Required.
	Gate *gate.Gate
	// Records is the storage seam the data-route bindings read through.
	// The gate owns enforcement; Records just supplies the raw bytes.
	// Required.
	Records data.RecordStore
	// Users is the authorized-user list and role assignments — the
	// surface the admin endpoints manage. It is the same store that
	// resolves roles for the Gate, so management and enforcement never
	// drift onto separate copies. Required.
	Users data.UserStore
	// IdP reports identity-provider account status, so the admin
	// endpoints can surface a mismatch — a suspended account still
	// holding a role. Required.
	IdP identity.Directory
	// Audit is the read seam over the audit subsystem — the same store the
	// Recorder (and the Gate's recorder) write to. The audit query and
	// stream endpoints read through it. Required: wiring it to a store
	// other than the one being written to would serve a stale or empty
	// log, so the deployment passes one store to all three. Required.
	Audit audit.Store
	// LLM is the core LLM gateway the /api/llm endpoint brokers calls
	// through. Unlike the other collaborators it is optional: the gateway
	// fails closed at construction for a provider whose DPA is not on
	// file, so a nil LLM means the startup DPA check did not pass. The
	// endpoint is still mounted in that case — it answers 503, a reported
	// "unavailable", rather than vanishing into a 404.
	LLM *llm.Gateway
	// Trust maps a verified IdP tenant to a Kura principal type. A
	// zero Trust trusts no tenant — fail-closed, but useless.
	Trust identity.TenantTrust
	// TokenTTL is the lifetime of tokens minted at the OAuth callback.
	// Defaults to 12h.
	TokenTTL time.Duration
}

// Server is the HTTP API server. Construct it with New, then call Run.
type Server struct {
	cfg   Config
	oauth *oauthHandler
	http  *http.Server

	// apiRoutes is every handler mounted under /api/, keyed by pattern —
	// the manifest-driven data routes and the admin routes alike. Its
	// value type is gatedRoute, not http.Handler: only a handler that
	// delegates to the core gate can be stored here, so a route that
	// bypasses the gate cannot be registered. registerData,
	// registerListData, and registerAdmin are the only writers; the
	// architectural test asserts the invariant a second time, with teeth.
	apiRoutes map[string]gatedRoute

	ready     chan struct{} // closed once the listener is bound
	readyOnce sync.Once

	mu        sync.Mutex
	boundAddr string
}

// New assembles a Server from cfg, filling in defaults for any unset
// optional field. It returns ErrMissingDependency if a required
// enforcement collaborator is nil. It does not bind a socket — Run does
// that.
func New(cfg Config) (*Server, error) {
	if cfg.Auth == nil || cfg.Recorder == nil || cfg.Google == nil ||
		cfg.Gate == nil || cfg.Records == nil || cfg.Users == nil || cfg.IdP == nil ||
		cfg.Audit == nil {
		return nil, ErrMissingDependency
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = defaultShutdownTimeout
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = defaultTokenTTL
	}
	s := &Server{
		cfg:   cfg,
		oauth: newOAuthHandler(cfg.Google, cfg.Trust, cfg.Auth, cfg.Recorder, cfg.TokenTTL, cfg.Logger),
		ready: make(chan struct{}),
	}
	s.http = &http.Server{}
	s.registerEntityRoutes()
	s.registerAdminRoutes()
	s.registerAuditRoutes()
	s.registerLLMRoute()
	s.registerWhoami()
	return s, nil
}

// Handler builds the routing tree. Health and OAuth endpoints are open —
// a load balancer must reach health without a credential, and the OAuth
// endpoints are how a caller acquires one in the first place. Everything
// under /api/ is wrapped in requireAuth, so no data route can be reached
// before authentication; each data route is itself a gatedHandler, so no
// data response can be served without passing through the core gate. The
// whole tree is wrapped in requestLogger and withClientIP.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// OAuth: the public sign-in endpoints. /oauth/login sends the
	// browser to Google; /oauth/callback is where Google sends it back,
	// and the only point that mints a Kura token.
	mux.HandleFunc("GET /oauth/login", s.oauth.login)
	mux.HandleFunc("GET /oauth/callback", s.oauth.callback)

	// API routes — manifest-driven data routes and admin routes. Each is
	// a gatedRoute, so it delegates to the core gate; there is no other
	// path onto this subtree. An authenticated request to an
	// unregistered /api path 404s; an unauthenticated one is rejected by
	// requireAuth before it reaches any handler.
	api := http.NewServeMux()
	for pattern, h := range s.apiRoutes {
		api.Handle(pattern, h)
	}
	api.Handle("/api/", http.NotFoundHandler())
	mux.Handle("/api/", requireAuth(s.cfg.Auth, s.cfg.Recorder, s.cfg.Logger, api))

	return requestLogger(s.cfg.Logger, withClientIP(mux))
}

// Run binds the listener and serves until ctx is cancelled, then shuts
// down gracefully within ShutdownTimeout. It returns nil on a clean
// shutdown; a bind failure or an unclean shutdown is returned as an
// error.
func (s *Server) Run(ctx context.Context) error {
	// Build the routing tree now, so any data routes registered after New
	// are mounted. Handler is idempotent and the server has not served a
	// request yet.
	s.http.Handler = s.Handler()

	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		s.readyOnce.Do(func() { close(s.ready) })
		return err
	}
	s.mu.Lock()
	s.boundAddr = ln.Addr().String()
	s.mu.Unlock()
	s.cfg.Logger.Info("http server listening", "addr", s.boundAddr)
	s.readyOnce.Do(func() { close(s.ready) })

	serveErr := make(chan error, 1)
	go func() { serveErr <- s.http.Serve(ln) }()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		s.cfg.Logger.Info("http server shutting down")
		return s.http.Shutdown(shutdownCtx)
	}
}

// Ready returns a channel that is closed once Run has bound its listener
// (or failed to). A caller that needs the bound address waits on it
// first.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// BoundAddr reports the address the listener actually bound, which
// differs from Config.Addr when the port was ":0". It is only meaningful
// after Ready is closed.
func (s *Server) BoundAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.boundAddr
}
