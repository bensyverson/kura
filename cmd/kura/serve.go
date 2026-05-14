package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/bensyverson/kura/internal/audit"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/server"
	"github.com/spf13/cobra"
)

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
  KURA_GOOGLE_CLIENT_ID      Google OAuth client ID (required)
  KURA_GOOGLE_CLIENT_SECRET  Google OAuth client secret (required)
  KURA_PUBLIC_URL            the server's public base URL, e.g.
                             https://kura.client.example (required)
  KURA_FIRM_DOMAIN           the consulting firm's Workspace domain;
                             humans on it are Consultants (required)
  KURA_CLIENT_DOMAINS        comma-separated client Workspace domains;
                             humans on them are Users
  KURA_ADMIN_EMAILS          comma-separated client-domain emails granted
                             the elevated Admin principal type`,
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
	clientID, err := required("KURA_GOOGLE_CLIENT_ID")
	if err != nil {
		return server.Config{}, err
	}
	clientSecret, err := required("KURA_GOOGLE_CLIENT_SECRET")
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

	google := server.NewGoogleAuthenticator(server.GoogleConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  strings.TrimRight(publicURL, "/") + "/oauth/callback",
	})

	return server.Config{
		Addr: addr,
		Auth: identity.NewAuthenticator([]byte(secret)),
		// MemStore is the v1 audit backing for kura serve: the
		// DB-backed audit store is a later, separate build-plan task.
		// Until it lands, the server audits to memory.
		Recorder: audit.NewRecorder(audit.NewMemStore()),
		Google:   google,
		Trust: identity.DomainTrust{
			FirmDomain:    firmDomain,
			ClientDomains: splitList(getenv("KURA_CLIENT_DOMAINS")),
			AdminEmails:   splitList(getenv("KURA_ADMIN_EMAILS")),
		},
	}, nil
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
