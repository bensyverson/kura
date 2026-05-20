// Package dashboard is the local web dashboard: a loopback-bound HTTP
// server that an admin runs on their own machine with `kura dashboard`.
// It is a thin presentation adapter — it makes no policy, audit, or
// masking decision. Every byte of data it renders is fetched from the
// remote kura serve over its JSON API, server-side, with the operator's
// cached `kura login` token. The browser talks only to loopback and
// never holds the token (the backend-for-frontend model), and the
// dashboard never touches a database directly.
//
// Running locally keeps the whole web attack surface — XSS, CSRF,
// sessions, templates — off the public internet, which matters because
// the data browser renders client PII. Server-side rendering of that PII
// is safe precisely because the server is the admin's own localhost, not
// a shared host.
//
// The visual design system every page must follow is DESIGN.md in this
// directory (the design.md token format). Read it before adding a page.
package dashboard

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bensyverson/kura/internal/identity"
)

// defaultShutdownTimeout bounds how long Run waits for in-flight requests
// to finish once its context is cancelled.
const defaultShutdownTimeout = 10 * time.Second

// ErrMissingDependency is returned by New when the wiring is incomplete.
// A dashboard with no remote API to read from, or no way to obtain the
// cached token, cannot serve a single page and must not come into being.
var ErrMissingDependency = errors.New("dashboard: requires a remote API URL and a token source")

// ErrNotAuthenticated marks "the caller has no usable session" — either
// no cached credential or a remote 401/403. The handlers turn it into
// the sign-in page rather than surfacing an error, so an operator who
// has not run `kura login` (or whose token expired) gets a clear prompt.
var ErrNotAuthenticated = errors.New("dashboard: not authenticated (run `kura login`)")

// TokenSource yields the cached bearer token for the remote API. It is
// read per request so a fresh `kura login` is picked up without a
// dashboard restart. An error means no usable credential, which the
// client maps to ErrNotAuthenticated.
type TokenSource interface {
	Token() (string, error)
}

// Config is the wiring a Server needs. RemoteURL and Tokens are
// required; the rest have working defaults.
type Config struct {
	// Addr is the loopback TCP address to bind, in host:port form. ":0"
	// or "127.0.0.1:0" binds an arbitrary free port — useful in tests,
	// where BoundAddr then reports the chosen one.
	Addr string
	// RemoteURL is the base URL of the remote kura serve the dashboard
	// reads through. Required.
	RemoteURL string
	// Tokens supplies the cached bearer token per request. Required.
	Tokens TokenSource
	// Client is the HTTP client used for remote calls. Defaults to
	// http.DefaultClient.
	Client *http.Client
	// Logger receives operational lines. Defaults to a text logger on
	// stderr.
	Logger *slog.Logger
	// ShutdownTimeout bounds graceful shutdown. Defaults to 10s.
	ShutdownTimeout time.Duration
	// OnListen, if set, is called once with the dashboard's local URL
	// after the listener binds — the seam the CLI uses to open a browser.
	OnListen func(localURL string)
}

// Server is the local dashboard. Construct it with New, then call Run.
type Server struct {
	cfg    Config
	api    *apiClient
	tmpl   map[string]*template.Template
	static http.Handler
	http   *http.Server

	ready     chan struct{}
	readyOnce sync.Once
	mu        sync.Mutex
	boundAddr string
}

// New assembles a Server from cfg, filling defaults for unset optional
// fields and parsing the embedded templates. It returns
// ErrMissingDependency when RemoteURL or Tokens is unset. It does not
// bind a socket — Run does that.
func New(cfg Config) (*Server, error) {
	if cfg.RemoteURL == "" || cfg.Tokens == nil {
		return nil, ErrMissingDependency
	}
	if cfg.Client == nil {
		cfg.Client = http.DefaultClient
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = defaultShutdownTimeout
	}

	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg: cfg,
		api: &apiClient{
			base:   strings.TrimRight(cfg.RemoteURL, "/"),
			tokens: cfg.Tokens,
			http:   cfg.Client,
		},
		tmpl:   tmpl,
		static: http.StripPrefix("/static/", http.FileServerFS(sub)),
		ready:  make(chan struct{}),
	}
	s.http = &http.Server{}
	return s, nil
}

// Handler builds the routing tree. The whole tree is wrapped in the
// loopback-only guard: a request bearing a non-loopback Host is refused
// before it reaches any page, which is the cheap first defense against a
// remote web page reaching this local server (DNS-rebinding / CSRF).
//
// The overview is the one live page in the skeleton; the other nav
// targets are wired as routes (real paths, not query strings) and render
// a placeholder until their own build lands.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", s.static)
	mux.HandleFunc("GET /{$}", s.handleIndex)

	// The Users & roles page is built: it reads server-side and accepts
	// state-changing form posts (POST-redirect-GET, same-origin guarded).
	mux.HandleFunc("GET /users", s.handleUsers)
	mux.HandleFunc("POST /users", s.handleAddUser)
	mux.HandleFunc("POST /users/roles", s.handleRoles)
	mux.HandleFunc("POST /users/deactivate", s.handleDeactivate)

	// The Cedar structured viewer is built: a read-only render of the
	// policy IR.
	mux.HandleFunc("GET /policy", s.handlePolicy)

	// The Audit log viewer is built: a filtered, paginated read over the
	// remote audit endpoint.
	mux.HandleFunc("GET /audit", s.handleAudit)

	// The Data browser is built: a manifest-driven, masked read over the
	// remote entity routes — an index, per-entity lists, and record detail.
	mux.HandleFunc("GET /data", s.handleDataIndex)
	mux.HandleFunc("GET /data/{entity}", s.handleDataList)
	mux.HandleFunc("GET /data/{entity}/{id}", s.handleDataRecord)

	// The Programmatic-access page is built: static reference for the CLI,
	// HTTP API, and MCP surfaces plus the token-issuance flow.
	mux.HandleFunc("GET /help", s.handleHelp)

	built := map[string]bool{"/": true, "/users": true, "/policy": true, "/audit": true, "/data": true, "/help": true}
	for _, link := range navLinks {
		if built[link.Path] {
			continue
		}
		mux.HandleFunc("GET "+link.Path, s.handlePlaceholder(link.Label, link.Path))
	}
	return s.loopbackOnly(mux)
}

// handleIndex renders the overview: it reads the caller's identity and
// the landscape briefing from the remote API and renders both
// server-side. A missing or expired session lands on the sign-in prompt;
// an unreachable remote lands on the error page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	principal, err := s.api.whoami(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/", err)
		return
	}
	overview, err := s.api.overview(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/", err)
		return
	}
	s.render(w, http.StatusOK, "index", pageData{
		Title:     "Overview",
		Nav:       navFor("/"),
		Principal: &principal,
		Overview:  &overview,
	})
}

// handlePlaceholder renders a not-yet-built page through the shared
// chrome. It still authenticates — every page proves the session — so an
// unauthenticated visitor to any route gets the sign-in prompt.
func (s *Server) handlePlaceholder(label, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, err := s.api.whoami(r.Context())
		if err != nil {
			s.renderAuthOrError(w, path, err)
			return
		}
		s.render(w, http.StatusOK, "placeholder", pageData{
			Title:     label,
			Nav:       navFor(path),
			Principal: &principal,
		})
	}
}

// renderAuthOrError routes a fetch error to the right page: the sign-in
// prompt for an authentication problem, the error page otherwise.
func (s *Server) renderAuthOrError(w http.ResponseWriter, active string, err error) {
	if errors.Is(err, ErrNotAuthenticated) {
		s.render(w, http.StatusOK, "signin", pageData{Title: "Sign in", Nav: navFor(active)})
		return
	}
	s.cfg.Logger.Error("dashboard: remote read failed", "err", err)
	s.render(w, http.StatusBadGateway, "error", pageData{
		Title: "Server unreachable",
		Nav:   navFor(active),
		Body:  err.Error(),
	})
}

// render executes a page template through the base layout into a buffer
// first, so a template error becomes a clean 500 rather than a
// half-written 200.
func (s *Server) render(w http.ResponseWriter, status int, page string, data pageData) {
	t, ok := s.tmpl[page]
	if !ok {
		s.cfg.Logger.Error("dashboard: unknown page template", "page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		s.cfg.Logger.Error("dashboard: rendering page", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// loopbackOnly refuses any request whose Host is not a loopback address.
func (s *Server) loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			http.Error(w, "forbidden: the dashboard accepts loopback requests only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopbackHost reports whether a request Host header names a loopback
// target — an IP in 127.0.0.0/8 or ::1, or the name "localhost". The
// port, if present, is ignored.
func isLoopbackHost(host string) bool {
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Run binds the loopback listener and serves until ctx is cancelled,
// then shuts down gracefully within ShutdownTimeout. A bind failure or
// an unclean shutdown is returned as an error; a clean shutdown is nil.
func (s *Server) Run(ctx context.Context) error {
	s.http.Handler = s.Handler()

	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		s.readyOnce.Do(func() { close(s.ready) })
		return err
	}
	s.mu.Lock()
	s.boundAddr = ln.Addr().String()
	s.mu.Unlock()
	s.cfg.Logger.Info("dashboard listening", "addr", s.boundAddr, "remote", s.cfg.RemoteURL)
	s.readyOnce.Do(func() { close(s.ready) })
	if s.cfg.OnListen != nil {
		s.cfg.OnListen("http://" + s.boundAddr + "/")
	}

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
		s.cfg.Logger.Info("dashboard shutting down")
		return s.http.Shutdown(shutdownCtx)
	}
}

// Ready returns a channel closed once Run has bound its listener (or
// failed to). A caller that needs the bound address waits on it first.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// BoundAddr reports the address the listener actually bound, meaningful
// only after Ready is closed. It differs from Config.Addr when the port
// was zero.
func (s *Server) BoundAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.boundAddr
}

// pageData is the view model every page renders against. Body carries
// page-specific content (a message string today).
type pageData struct {
	Title      string
	Nav        []navItem
	Principal  *identity.Principal
	Overview   *overviewData
	Users      *usersView
	Policy     *policyView
	Audit      *auditView
	DataIndex  *dataIndexView
	DataList   *dataListView
	DataRecord *dataRecordView
	Help       *helpView
	Body       any
}

// navItem is one primary-navigation link. Active marks the current page.
type navItem struct {
	Label  string
	Path   string
	Active bool
}

// navLinks is the dashboard's primary navigation — one entry per Phase 4
// page. Paths are real routes (logical pages are paths, not query
// strings); query strings are reserved for search, sort, and pagination
// within a page.
var navLinks = []navItem{
	{Label: "Overview", Path: "/"},
	{Label: "Users & roles", Path: "/users"},
	{Label: "Access review", Path: "/reviews"},
	{Label: "Data browser", Path: "/data"},
	{Label: "Audit log", Path: "/audit"},
	{Label: "Policy", Path: "/policy"},
	{Label: "Programmatic access", Path: "/help"},
}

// navFor returns a copy of navLinks with the entry matching active
// marked Active, so the template can render the current-page state
// without mutating the shared slice.
func navFor(active string) []navItem {
	out := make([]navItem, len(navLinks))
	copy(out, navLinks)
	for i := range out {
		out[i].Active = out[i].Path == active
	}
	return out
}
