package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/data"
	"github.com/bensyverson/kura/internal/db"
	"github.com/bensyverson/kura/internal/gate"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/jobs"
	"github.com/bensyverson/kura/internal/llm"
	"github.com/bensyverson/kura/internal/manifest"
	"github.com/bensyverson/kura/internal/pii"
	"github.com/bensyverson/kura/internal/review"
	"github.com/bensyverson/kura/internal/server"
	"github.com/spf13/cobra"
)

// oidcDiscoveryTimeout bounds the OIDC discovery and JWKS fetch that
// happen during serveConfig when KURA_IDP=oidc. An unreachable issuer
// must fail the operator's startup quickly, not hang.
const oidcDiscoveryTimeout = 15 * time.Second

// dbStartupTimeout bounds the connect-and-migrate that happens during
// serveConfig when KURA_DATABASE_URL is set. An unreachable database must
// fail the operator's startup quickly, not hang.
const dbStartupTimeout = 30 * time.Second

// defaultServeAddr binds loopback only. Caddy terminates TLS in front of
// the server and proxies to it on the same host (Phase 6), so the server
// itself never needs a public-facing socket.
const defaultServeAddr = "127.0.0.1:8080"

// newServeCmd builds `kura serve`: the thin adapter that parses the bind
// address, assembles the server's dependencies from the environment,
// wires up signal-driven shutdown, and hands off to internal/server. All
// routing, middleware, and lifecycle logic lives there; this file is
// wiring only.
func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the remote HTTP API server (the only public surface)",
		Long: `Run the remote HTTP API server.

Configuration is read from the environment:

  KURA_SIGNING_SECRET        secret for signing identity tokens (required)
  KURA_IDP                   identity provider family: google, microsoft, or
                             oidc. Selects which set of IdP variables below
                             are required (required)
  KURA_GOOGLE_CLIENT_ID      Google OAuth client ID (required when
                             KURA_IDP=google)
  KURA_GOOGLE_CLIENT_SECRET  Google OAuth client secret (required when
                             KURA_IDP=google)
  KURA_GOOGLE_DIRECTORY_CREDENTIALS
                             path to the service-account JSON key for
                             the Admin SDK Directory client; powers
                             IdP-mismatch detection (required when
                             KURA_IDP=google)
  KURA_GOOGLE_DIRECTORY_SUBJECT
                             Workspace admin email the directory
                             service account impersonates (required
                             when KURA_IDP=google)
  KURA_MICROSOFT_TENANT_ID   Microsoft Entra Directory (tenant) ID, or
                             "common" for multi-tenant (required when
                             KURA_IDP=microsoft)
  KURA_MICROSOFT_CLIENT_ID   Microsoft Entra app Application (client) ID
                             (required when KURA_IDP=microsoft)
  KURA_MICROSOFT_CLIENT_SECRET Microsoft Entra app client secret value
                             (required when KURA_IDP=microsoft)
  KURA_OIDC_ISSUER_URL       OIDC issuer URL — discovery happens at
                             <URL>/.well-known/openid-configuration
                             (required when KURA_IDP=oidc)
  KURA_OIDC_CLIENT_ID        OIDC client ID issued by the IdP (required
                             when KURA_IDP=oidc)
  KURA_OIDC_CLIENT_SECRET    OIDC client secret issued by the IdP
                             (required when KURA_IDP=oidc)
  KURA_OAUTH_REDIRECT_URL    OAuth redirect URI registered with the IdP.
                             Defaults to <KURA_PUBLIC_URL>/oauth/callback;
                             override when a proxy terminates at a path
                             other than the public root
  KURA_PUBLIC_URL            the server's public base URL, e.g.
                             https://kura.client.example (required)
  KURA_FIRM_DOMAIN           the consulting firm's Workspace domain;
                             humans on it are Consultants (required)
  KURA_DIRECTORY             set to "none" to disable IdP-mismatch
                             detection: the directory becomes a no-op that
                             reports every account active and never dials
                             out. Use it for a deployment without
                             directory-API access, or the offline dev
                             instance. When unset, the directory is the one
                             paired with KURA_IDP
  KURA_PII_DETECTOR_URL      base URL of the self-hosted PII detection
                             service (required)
  KURA_CLIENT_DOMAINS        comma-separated client Workspace domains;
                             humans on them are Users
  KURA_ADMIN_EMAILS          comma-separated client-domain emails granted
                             the elevated Admin principal type
  KURA_ANTHROPIC_API_KEY     Anthropic API key for the LLM gateway; unset
                             leaves the /api/llm endpoint unavailable (503)
  KURA_ANTHROPIC_DPA_ON_FILE set truthy to attest the controller's DPA is
                             on file for Anthropic; without it the startup
                             DPA check fails and /api/llm refuses to serve
  KURA_DATABASE_URL          Postgres connection DSN (TLS required). When
                             set, the server reads/writes through the
                             Postgres record and user stores and runs
                             pending migrations at startup. When unset, the
                             server keeps records and users in memory — the
                             credential-less dev/bare path
  KURA_DB_TENANT_ID          tenant id the Postgres stores scope their
                             row-level security to (required when
                             KURA_DATABASE_URL is set)
  KURA_RECORD_ENCRYPTION_KEY app-managed key the Postgres record store
                             decrypts encrypted fields with (required when
                             KURA_DATABASE_URL is set)
  KURA_MANIFEST_PATH         path to the schema manifest file. When set,
                             the gate enforces against it and the API grows
                             a data route per declared entity; an invalid
                             manifest fails startup. When unset, the gate
                             runs on an empty manifest and no data routes
                             are generated — the bare dev case`,
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := cmd.Flags().GetString("addr")
			if err != nil {
				return err
			}
			cfg, err := serveConfig(addr, os.Getenv)
			if err != nil {
				return err
			}
			srv, err := server.New(cfg)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return srv.Run(ctx)
		},
	}
	cmd.Flags().String("addr", defaultServeAddr, "TCP address to bind, in host:port form")
	return cmd
}

// serveConfig assembles the server configuration from the environment.
// getenv is injected so the wiring is testable without touching the
// process environment. A missing required variable is a loud error — a
// server that cannot sign a token or broker sign-in must not start.
func serveConfig(addr string, getenv func(string) string) (server.Config, error) {
	required := func(key string) (string, error) {
		if v := getenv(key); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("serve: required environment variable %s is not set", key)
	}

	secret, err := required("KURA_SIGNING_SECRET")
	if err != nil {
		return server.Config{}, err
	}
	publicURL, err := required("KURA_PUBLIC_URL")
	if err != nil {
		return server.Config{}, err
	}
	firmDomain, err := required("KURA_FIRM_DOMAIN")
	if err != nil {
		return server.Config{}, err
	}
	detectorURL, err := required("KURA_PII_DETECTOR_URL")
	if err != nil {
		return server.Config{}, err
	}

	redirectURL := getenv("KURA_OAUTH_REDIRECT_URL")
	if redirectURL == "" {
		redirectURL = strings.TrimRight(publicURL, "/") + "/oauth/callback"
	}

	idp, err := buildIdP(getenv, redirectURL)
	if err != nil {
		return server.Config{}, err
	}

	dir, err := buildDirectory(getenv)
	if err != nil {
		return server.Config{}, err
	}

	auth := identity.NewAuthenticator([]byte(secret))
	// MemStore is the v1 audit backing for kura serve: the DB-backed
	// audit store is a later, separate build-plan task. Until it lands,
	// the server audits to memory. The same store backs the recorder (so
	// the gate writes to it) and is the server's audit read seam (so the
	// /api/audit endpoints read the same log) — one store, no drift.
	auditStore := audit.NewMemStore()
	recorder := audit.NewRecorder(auditStore)

	// records, writer, and users come from buildStores: Postgres-backed
	// when KURA_DATABASE_URL is configured, in-memory otherwise. records and
	// writer are the same store under its read and write interfaces. The
	// same user store both resolves roles for the gate and is the admin
	// endpoints' management surface, so enforcement and management never
	// drift.
	records, writer, users, err := buildStores(getenv)
	if err != nil {
		return server.Config{}, err
	}

	m, err := buildManifest(getenv)
	if err != nil {
		return server.Config{}, err
	}

	g, err := buildGate(auth, recorder, users, detectorURL, m)
	if err != nil {
		return server.Config{}, err
	}

	return server.Config{
		Addr:     addr,
		Auth:     auth,
		Recorder: recorder,
		Audit:    auditStore,
		Google:   idp,
		Gate:     g,
		// LLM is optional: buildLLMGateway returns nil when the provider
		// is not configured or its DPA is not on file, and the /api/llm
		// endpoint then answers 503. A failed DPA check disables the LLM
		// endpoint; it does not stop the server.
		LLM: buildLLMGateway(getenv),
		// Records, Writer, and Users are selected by buildStores from the
		// environment: the Postgres-backed stores when KURA_DATABASE_URL is
		// set, the in-memory stores otherwise. Records and Writer are the
		// same store under its read and write interfaces.
		Records: records,
		Writer:  writer,
		Users:   users,
		// IdP is the vendor Directory paired with the sign-in IdP:
		// googleDirectory for Google, microsoftDirectory for Entra,
		// noopDirectory for generic OIDC (no portable directory API).
		// buildDirectory picks the implementation from KURA_IDP.
		IdP: dir,
		// Jobs is the async-jobs ledger and worker. The Postgres-backed
		// store is its own build-plan task; until it lands, kura serve
		// uses MemStore — restart-survivability gets exercised by the
		// internal/jobs integration tests rather than at this surface.
		// No kinds are registered here; the build-plan tasks that
		// produce long-running operations (backup/restore) will call
		// Jobs.Register before Run.
		Jobs: jobs.NewManager(jobs.NewMemStore()),
		// MemStore is the v1 backing for access-review artifacts. The
		// Postgres-backed review.Store is integration-tested in
		// internal/review; until the dev-bringup wiring selects it, kura
		// serve keeps reviews in memory like the other stores.
		Reviews: review.NewMemStore(),
		Trust: identity.TenantTrust{
			FirmTenant:    firmDomain,
			ClientTenants: splitList(getenv("KURA_CLIENT_DOMAINS")),
			AdminEmails:   splitList(getenv("KURA_ADMIN_EMAILS")),
		},
	}, nil
}

// buildStores selects the record and user stores from the environment.
// With KURA_DATABASE_URL set it opens the configured Postgres database,
// runs any pending migrations against it, and returns the Postgres-backed
// stores; the companion KURA_DB_TENANT_ID and KURA_RECORD_ENCRYPTION_KEY
// are then required, and a non-TLS DSN is refused. With no database URL it
// returns the in-memory stores — the credential-less dev/bare path — so a
// server with no DB configured behaves exactly as before. Both stores
// share one pool: the user store also resolves roles for the gate, so a
// single connection serves enforcement and management alike.
func buildStores(getenv func(string) string) (data.RecordStore, data.RecordWriter, data.UserStore, error) {
	dsn := getenv("KURA_DATABASE_URL")
	if dsn == "" {
		mem := data.NewMemStore()
		return mem, mem, data.NewMemUserStore(), nil
	}

	required := func(key string) (string, error) {
		if v := getenv(key); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("serve: required environment variable %s is not set (required when KURA_DATABASE_URL is set)", key)
	}
	tenantID, err := required("KURA_DB_TENANT_ID")
	if err != nil {
		return nil, nil, nil, err
	}
	encKey, err := required("KURA_RECORD_ENCRYPTION_KEY")
	if err != nil {
		return nil, nil, nil, err
	}

	// Open validates the DSN — refusing any non-TLS connection — before the
	// pool is created. The pool is lazy, so the first real connection (and
	// any unreachable-host failure) happens during Migrate below.
	pool, err := db.Open(dsn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("serve: opening database: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbStartupTimeout)
	defer cancel()
	if err := db.Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, nil, fmt.Errorf("serve: running migrations: %w", err)
	}

	pg, err := data.NewPostgresStore(pool, tenantID, encKey)
	if err != nil {
		pool.Close()
		return nil, nil, nil, fmt.Errorf("serve: building record store: %w", err)
	}
	users, err := data.NewPostgresUserStore(pool, tenantID)
	if err != nil {
		pool.Close()
		return nil, nil, nil, fmt.Errorf("serve: building user store: %w", err)
	}
	return pg, pg, users, nil
}

// buildManifest loads the schema manifest the gate enforces against and
// the server projects data routes from. KURA_MANIFEST_PATH points at the
// manifest file in the deployment repo (dec-policy-apply: the production
// source is that repo). When the variable is unset the gate runs on an
// empty manifest — the bare dev case, valid because no entities simply
// means no data routes. A configured-but-unloadable manifest (missing,
// malformed, or invalid) is a loud startup failure: the Cedar policy is
// built from the manifest, so an unusable manifest must not yield a
// silently-empty policy.
func buildManifest(getenv func(string) string) (*manifest.Manifest, error) {
	path := getenv("KURA_MANIFEST_PATH")
	if path == "" {
		return &manifest.Manifest{Version: "1"}, nil
	}
	m, err := manifest.ParseFile(path)
	if err != nil {
		return nil, fmt.Errorf("serve: loading manifest: %w", err)
	}
	return m, nil
}

// buildGate assembles the core enforcement gate the server delegates
// every data read to. The Cedar policy is built from the loaded manifest m
// (buildManifest), so the entities the manifest declares are exactly the
// ones the gate authorizes and the server routes. The PII detector, the
// authenticator, and the role-resolving user store are real, and the
// recorder is shared with the server so authentication and access land
// in one audit log.
func buildGate(auth *identity.Authenticator, recorder *audit.Recorder, roles gate.RoleResolver, detectorURL string, m *manifest.Manifest) (*gate.Gate, error) {
	evaluator, err := cedar.NewEvaluator(cedar.DefaultPolicy(m))
	if err != nil {
		return nil, fmt.Errorf("serve: building authorization evaluator: %w", err)
	}
	scanner := pii.NewScanner(pii.NewServiceDetector(detectorURL))
	return gate.New(auth, evaluator, roles, m, scanner, recorder)
}

// buildIdP picks an IdentityProvider implementation by KURA_IDP and
// hydrates it from the corresponding family of environment variables.
// KURA_IDP is required — a deployment with an unset selector fails
// startup rather than silently falling through to a default.
//
// "google" wires the Google IdP from KURA_GOOGLE_*.
//
// "oidc" wires the generic OIDC IdP from KURA_OIDC_*. Discovery and
// the JWKS fetch happen here, so this branch makes a network call
// against KURA_OIDC_ISSUER_URL bounded by oidcDiscoveryTimeout — an
// unreachable issuer fails serve startup loudly rather than hanging.
//
// "microsoft" wires the Microsoft Entra IdP from KURA_MICROSOFT_*.
// Like the OIDC branch this performs network discovery, against
// https://login.microsoftonline.com/<tenant>/v2.0.
//
// All branches share redirectURL — the OAuth redirect URI is a
// property of the deployment, not the IdP family, so it is computed
// once by serveConfig.
func buildIdP(getenv func(string) string, redirectURL string) (server.IdentityProvider, error) {
	kind := strings.ToLower(strings.TrimSpace(getenv("KURA_IDP")))
	if kind == "" {
		return nil, fmt.Errorf("serve: required environment variable KURA_IDP is not set (expected one of: google, microsoft, oidc)")
	}
	required := func(key string) (string, error) {
		if v := getenv(key); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("serve: required environment variable %s is not set", key)
	}
	switch kind {
	case "google":
		clientID, err := required("KURA_GOOGLE_CLIENT_ID")
		if err != nil {
			return nil, err
		}
		clientSecret, err := required("KURA_GOOGLE_CLIENT_SECRET")
		if err != nil {
			return nil, err
		}
		return server.NewGoogleIdP(server.GoogleConfig{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
		}), nil
	case "microsoft":
		tenantID, err := required("KURA_MICROSOFT_TENANT_ID")
		if err != nil {
			return nil, err
		}
		clientID, err := required("KURA_MICROSOFT_CLIENT_ID")
		if err != nil {
			return nil, err
		}
		clientSecret, err := required("KURA_MICROSOFT_CLIENT_SECRET")
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
		defer cancel()
		return server.NewMicrosoftIdP(ctx, server.MicrosoftConfig{
			TenantID:     tenantID,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
		})
	case "oidc":
		issuerURL, err := required("KURA_OIDC_ISSUER_URL")
		if err != nil {
			return nil, err
		}
		clientID, err := required("KURA_OIDC_CLIENT_ID")
		if err != nil {
			return nil, err
		}
		clientSecret, err := required("KURA_OIDC_CLIENT_SECRET")
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
		defer cancel()
		return server.NewOIDCIdP(ctx, server.OIDCConfig{
			IssuerURL:    issuerURL,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
		})
	default:
		return nil, fmt.Errorf("serve: KURA_IDP=%q is not a recognized identity provider (expected one of: google, microsoft, oidc)", kind)
	}
}

// buildDirectory picks an identity.Directory implementation by KURA_IDP
// and hydrates it from the corresponding family of environment
// variables, in parallel with buildIdP.
//
// "google" wires googleDirectory from KURA_GOOGLE_DIRECTORY_CREDENTIALS
// (a service-account JSON file path) and KURA_GOOGLE_DIRECTORY_SUBJECT
// (the Workspace admin email the service account impersonates). Both
// are required: the Admin SDK refuses anonymous calls.
//
// "microsoft" wires microsoftDirectory from the same KURA_MICROSOFT_*
// client credentials the IdP uses — the Graph directory client runs
// as the application, against the same Entra tenant.
//
// "oidc" wires the noop directory: generic OIDC has no standard
// directory API, so IdP-mismatch detection is unavailable on this path
// (the endpoint serves a consistent empty result rather than a
// transport error).
func buildDirectory(getenv func(string) string) (identity.Directory, error) {
	// KURA_DIRECTORY=none opts out of IdP-mismatch detection entirely,
	// independent of the sign-in IdP: the noop directory reports every
	// account active and never dials out. It is the path for a deployment
	// without directory-API access — and the offline dev instance, where
	// no real Workspace/Entra directory is reachable.
	if strings.ToLower(strings.TrimSpace(getenv("KURA_DIRECTORY"))) == "none" {
		return server.NewNoopDirectory(), nil
	}

	kind := strings.ToLower(strings.TrimSpace(getenv("KURA_IDP")))
	required := func(key string) (string, error) {
		if v := getenv(key); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("serve: required environment variable %s is not set", key)
	}
	switch kind {
	case "google":
		credsFile, err := required("KURA_GOOGLE_DIRECTORY_CREDENTIALS")
		if err != nil {
			return nil, err
		}
		subject, err := required("KURA_GOOGLE_DIRECTORY_SUBJECT")
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
		defer cancel()
		return server.NewGoogleDirectory(ctx, server.GoogleDirectoryConfig{
			CredentialsFile: credsFile,
			Subject:         subject,
		})
	case "microsoft":
		tenantID, err := required("KURA_MICROSOFT_TENANT_ID")
		if err != nil {
			return nil, err
		}
		clientID, err := required("KURA_MICROSOFT_CLIENT_ID")
		if err != nil {
			return nil, err
		}
		clientSecret, err := required("KURA_MICROSOFT_CLIENT_SECRET")
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
		defer cancel()
		return server.NewMicrosoftDirectory(ctx, server.MicrosoftDirectoryConfig{
			TenantID:     tenantID,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		})
	case "oidc":
		return server.NewNoopDirectory(), nil
	default:
		// buildIdP has already rejected this case; reach here only via
		// an unset KURA_IDP, which buildIdP also rejects.
		return nil, fmt.Errorf("serve: KURA_IDP=%q is not a recognized identity provider", kind)
	}
}

// buildLLMGateway assembles the core LLM gateway the /api/llm endpoint
// brokers calls through, or returns nil when it cannot — in which case
// the endpoint answers 503 and the rest of the server runs unaffected.
//
// It returns nil in three cases, all "the LLM endpoint is unavailable":
// no Anthropic API key (nothing to authenticate the provider with), an
// otherwise-unbuildable provider, and — the startup DPA check — the
// controller's DPA not attested on file for the provider, which is what
// KURA_ANTHROPIC_DPA_ON_FILE records. NewGateway fails closed on that
// last case by construction; this wiring just surfaces nil rather than
// crashing the server.
//
// The API key is read from the environment here, matching how the other
// v1 secrets are wired; the secrets-manager injection path is its own
// build-plan task. MemLog is the v1 metadata-log backing, like MemStore
// is for audit.
func buildLLMGateway(getenv func(string) string) *llm.Gateway {
	apiKey := getenv("KURA_ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil
	}
	provider, err := llm.NewAnthropicProvider(apiKey)
	if err != nil {
		return nil
	}
	dpa := llm.NewDPAConfig()
	if isTruthy(getenv("KURA_ANTHROPIC_DPA_ON_FILE")) {
		dpa.Attest(provider.Name())
	}
	gateway, err := llm.NewGateway(provider, llm.NewMemLog(), dpa)
	if err != nil {
		// ErrDPANotOnFile lands here: the startup DPA check failed, so
		// there is no gateway and the endpoint will refuse to serve.
		return nil
	}
	return gateway
}

// isTruthy reports whether an environment variable's value is an
// affirmative — the attestation flags are set, not parsed.
func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// splitList parses a comma-separated environment variable into a
// trimmed, non-empty slice.
func splitList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
