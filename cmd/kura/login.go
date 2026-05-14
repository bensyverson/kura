package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// loginTimeout bounds how long `kura login` waits for the browser
// sign-in to come back before giving up.
const loginTimeout = 5 * time.Minute

// newLoginCmd builds `kura login`: the thin adapter that runs the
// loopback-handoff OAuth flow against a remote kura serve and caches the
// short-lived token it gets back. The flow itself — and the trust
// decision behind the token — lives on the server; this is wiring.
func newLoginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in via OAuth and cache a short-lived token",
		Long: `Sign in to a remote kura serve via Google OAuth.

login opens your browser to the server's sign-in endpoint, waits on a
local loopback address for the server to hand back a short-lived token,
and caches that token for subsequent kura commands.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			serverURL, err := cmd.Flags().GetString("server")
			if err != nil {
				return err
			}
			if serverURL == "" {
				return errors.New("login: --server is required")
			}

			cache, err := defaultTokenCache()
			if err != nil {
				return err
			}

			flow := &loginFlow{
				serverURL:   serverURL,
				openBrowser: openSystemBrowser,
				out:         cmd.OutOrStdout(),
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), loginTimeout)
			defer cancel()

			token, err := flow.run(ctx)
			if err != nil {
				return err
			}
			if err := cache.save(serverURL, token); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Signed in. Token cached.")
			return nil
		},
	}
	cmd.Flags().String("server", "", "base URL of the remote kura serve to sign in to")
	return cmd
}

// loginFlow runs one loopback-handoff sign-in. openBrowser is injected
// so tests can drive the server callback directly instead of launching a
// real browser.
type loginFlow struct {
	serverURL   string
	openBrowser func(string) error
	out         io.Writer
}

// loginOutcome is what the loopback callback handler reports back to run.
type loginOutcome struct {
	token string
	err   error
}

// run performs the flow: it binds a loopback listener, sends the browser
// to the server's /oauth/login with that listener as the redirect
// target, and waits for the server to redirect back with a token. The
// CLI-generated state is round-tripped through the server and verified
// on return — a callback bearing a foreign state is rejected, so the
// loopback listener cannot be tricked into accepting an injected token.
func (f *loginFlow) run(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("login: binding loopback listener: %w", err)
	}
	defer ln.Close()

	state, err := randomState()
	if err != nil {
		return "", fmt.Errorf("login: generating state: %w", err)
	}

	loopbackURL := (&url.URL{
		Scheme:   "http",
		Host:     ln.Addr().String(),
		Path:     "/callback",
		RawQuery: url.Values{"state": {state}}.Encode(),
	}).String()

	outcome := make(chan loginOutcome, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			outcome <- loginOutcome{err: errors.New("login: callback state did not match — refusing a possibly injected token")}
			return
		}
		token := q.Get("token")
		if token == "" {
			http.Error(w, "no token", http.StatusBadRequest)
			outcome <- loginOutcome{err: errors.New("login: server callback delivered no token")}
			return
		}
		io.WriteString(w, loginSuccessPage)
		outcome <- loginOutcome{token: token}
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	launchURL := strings.TrimRight(f.serverURL, "/") + "/oauth/login?redirect=" + url.QueryEscape(loopbackURL)
	fmt.Fprintf(f.out, "Opening your browser to sign in.\nIf it does not open, visit:\n\n  %s\n\n", launchURL)
	if err := f.openBrowser(launchURL); err != nil {
		fmt.Fprintf(f.out, "Could not open a browser automatically (%v); open the URL above by hand.\n", err)
	}

	select {
	case res := <-outcome:
		return res.token, res.err
	case <-ctx.Done():
		return "", fmt.Errorf("login: timed out waiting for the browser sign-in to complete: %w", ctx.Err())
	}
}

// loginSuccessPage is the minimal page the loopback handler shows in the
// browser once the token is in hand.
const loginSuccessPage = `<!doctype html><title>kura</title>
<body style="font-family:system-ui;margin:4rem">
<h1>Signed in to kura</h1><p>You can close this tab and return to your terminal.</p>`

// cachedCredential is the on-disk shape of a cached login: which server
// it is for, and the short-lived token itself.
type cachedCredential struct {
	Server string `json:"server"`
	Token  string `json:"token"`
}

// tokenCache is the CLI-side store for the token `kura login` obtains.
// It is adapter plumbing — file I/O under the user's config dir — not
// part of the core token model.
type tokenCache struct {
	dir string
}

// defaultTokenCache returns the token cache rooted under the user's
// OS-conventional config directory.
func defaultTokenCache() (tokenCache, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return tokenCache{}, fmt.Errorf("login: locating config directory: %w", err)
	}
	return tokenCache{dir: filepath.Join(base, "kura")}, nil
}

// path is the credential file's location.
func (c tokenCache) path() string {
	return filepath.Join(c.dir, "credentials.json")
}

// save writes the token for serverURL, owner-readable only.
func (c tokenCache) save(serverURL, token string) error {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("login: creating credential directory: %w", err)
	}
	data, err := json.Marshal(cachedCredential{Server: serverURL, Token: token})
	if err != nil {
		return fmt.Errorf("login: encoding credential: %w", err)
	}
	if err := os.WriteFile(c.path(), data, 0o600); err != nil {
		return fmt.Errorf("login: writing credential: %w", err)
	}
	return nil
}

// load reads the cached server URL and token. A missing cache is an
// error — the caller has not run `kura login`.
func (c tokenCache) load() (serverURL, token string, err error) {
	data, err := os.ReadFile(c.path())
	if err != nil {
		return "", "", fmt.Errorf("login: no cached credential (run `kura login`): %w", err)
	}
	var cred cachedCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return "", "", fmt.Errorf("login: cached credential is corrupt: %w", err)
	}
	return cred.Server, cred.Token, nil
}

// openSystemBrowser launches the OS browser at target. It returns once
// the browser is launched; it does not wait for it to close.
func openSystemBrowser(target string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{target}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", target}
	default:
		name, args = "xdg-open", []string{target}
	}
	return exec.Command(name, args...).Start()
}

// randomState returns a cryptographically random, URL-safe state value
// for the loopback leg of the OAuth flow.
func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
