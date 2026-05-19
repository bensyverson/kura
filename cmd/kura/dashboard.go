package main

import (
	"fmt"
	"os/signal"
	"syscall"

	"github.com/bensyverson/kura/internal/dashboard"
	"github.com/spf13/cobra"
)

// defaultDashboardAddr binds loopback only. The dashboard is a local web
// app — its whole point is that the webapp attack surface never reaches a
// public host — so it must never bind a public-facing socket.
const defaultDashboardAddr = "127.0.0.1:7878"

// newDashboardCmd builds `kura dashboard`: the thin adapter that resolves
// the remote server, wires the cached-token source, and hands off to
// internal/dashboard. The local HTTP server, server-side rendering, and
// remote API client all live there; this file is wiring only.
func newDashboardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Run the local web dashboard (loopback-bound HTTP client of the remote API)",
		Long: `Run the local web dashboard.

The dashboard runs on your own machine, bound to loopback, and is itself
an HTTP client of the remote ` + "`kura serve`" + ` — exactly like the CLI.
Running it locally keeps the whole web attack surface (XSS, CSRF,
sessions) off the public internet; the remote server stays API-only.

It reads through the remote JSON API server-side using the token cached
by ` + "`kura login`" + `; that token never reaches the browser, and the
dashboard never touches a database directly. Resolve the remote with
--server, --client, or a prior ` + "`kura login`" + `.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			addr, err := cmd.Flags().GetString("addr")
			if err != nil {
				return err
			}
			noBrowser, err := cmd.Flags().GetBool("no-browser")
			if err != nil {
				return err
			}
			server, err := resolveServerFromFlags(cmd, "dashboard")
			if err != nil {
				return err
			}

			cfg := dashboard.Config{
				Addr:      addr,
				RemoteURL: server,
				Tokens:    cachedTokenSource{},
				OnListen: func(localURL string) {
					fmt.Fprintf(cmd.OutOrStdout(), "Dashboard running at %s (reading %s)\nPress Ctrl-C to stop.\n", localURL, server)
					if !noBrowser {
						_ = openSystemBrowser(localURL)
					}
				},
			}

			srv, err := dashboard.New(cfg)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return srv.Run(ctx)
		},
	}
	cmd.Flags().String("addr", defaultDashboardAddr, "loopback TCP address to bind, in host:port form")
	cmd.Flags().Bool("no-browser", false, "do not open a browser window on startup")
	return cmd
}

// cachedTokenSource reads the bearer token `kura login` cached. It is
// read per request, so a fresh login is picked up without restarting the
// dashboard. An absent cache is an error the dashboard renders as its
// sign-in prompt.
type cachedTokenSource struct{}

// Token loads the cached bearer token, ignoring the cached server URL —
// the dashboard already resolved the remote URL through the flag layer.
func (cachedTokenSource) Token() (string, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return "", err
	}
	_, token, err := cache.load()
	if err != nil {
		return "", err
	}
	return token, nil
}

// compile-time assertion that the wiring satisfies the package contract.
var _ dashboard.TokenSource = cachedTokenSource{}
