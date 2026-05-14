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
)

// defaultShutdownTimeout bounds how long Run waits for in-flight requests
// to finish once its context is cancelled.
const defaultShutdownTimeout = 10 * time.Second

// Config is the wiring a Server needs. Only Addr is required; the rest
// have working defaults so a caller can stand up a server with one field.
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
}

// Server is the HTTP API server. Construct it with New, then call Run.
type Server struct {
	cfg  Config
	http *http.Server

	ready     chan struct{} // closed once the listener is bound
	readyOnce sync.Once

	mu        sync.Mutex
	boundAddr string
}

// New assembles a Server from cfg, filling in defaults for any unset
// field. It does not bind a socket — Run does that.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = defaultShutdownTimeout
	}
	s := &Server{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
	s.http = &http.Server{Handler: s.Handler()}
	return s
}

// Handler builds the routing tree. Health endpoints are open — a load
// balancer must reach them without a credential. Everything under /api/
// is wrapped in requireAuth, so no data route can be reached before
// authentication. The whole tree is wrapped in requestLogger.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Data routes. The skeleton declares the subtree and its auth gate;
	// the actual endpoints land in later phases. Until then an
	// authenticated request to an unknown /api path 404s — but an
	// unauthenticated one is rejected here, before it ever reaches a
	// handler.
	mux.Handle("/api/", requireAuth(http.NotFoundHandler()))

	return requestLogger(s.cfg.Logger, mux)
}

// Run binds the listener and serves until ctx is cancelled, then shuts
// down gracefully within ShutdownTimeout. It returns nil on a clean
// shutdown; a bind failure or an unclean shutdown is returned as an
// error.
func (s *Server) Run(ctx context.Context) error {
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
