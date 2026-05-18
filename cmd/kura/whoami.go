package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/bensyverson/kura/internal/identity"
	"github.com/spf13/cobra"
)

// newWhoamiCmd builds `kura whoami`: the minimal self-identity read.
// In the default (remote) mode it GETs /api/whoami on the resolved
// server with the cached bearer token. In --local mode it skips the
// network and resolves the principal directly through the same
// identity.TenantTrust the server uses on the oauth callback.
//
// whoami exists in the CLI skeleton task to demonstrate one verb that
// runs in both modes against the same core behavior — TenantTrust is
// the shared piece. Phase 3 fills the rest of the verbs over the same
// scaffolding.
func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Print the principal the current session resolves to",
		Long: `Print the principal the current session resolves to.

Default mode: GET /api/whoami on the remote ` + "`kura serve`" + ` resolved by
--server / --client / the cached login, with the cached bearer token.

` + "`--local`" + ` mode: resolve the principal directly via
` + "`identity.TenantTrust`" + ` — the same code the server runs on the oauth
callback. --as <email> is required in --local mode; KURA_FIRM_DOMAIN,
KURA_CLIENT_DOMAINS, and KURA_ADMIN_EMAILS supply the trust set, the
same env the server reads.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			local, _ := cmd.Flags().GetBool("local")
			if local {
				return runWhoamiLocal(cmd)
			}
			return runWhoamiRemote(cmd)
		},
	}
}

// runWhoamiLocal resolves the principal directly. --as is the input;
// KURA_FIRM_DOMAIN / KURA_CLIENT_DOMAINS / KURA_ADMIN_EMAILS is the
// trust set the server would read. The tenant key is the post-@ part
// of --as — adequate for the Google-Workspace shape; deployments using
// Entra GUIDs or generic-OIDC issuer URLs as tenants will need to pass
// a full email whose domain matches a configured tenant entry.
func runWhoamiLocal(cmd *cobra.Command) error {
	as, _ := cmd.Flags().GetString("as")
	if as == "" {
		return clio.UsageError("whoami", "--local requires --as <email> (the principal to resolve)")
	}
	parts := strings.SplitN(as, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return clio.UsageError("whoami", "--as must be an email (got %q)", as)
	}
	trust := identity.TenantTrust{
		FirmTenant:    os.Getenv("KURA_FIRM_DOMAIN"),
		ClientTenants: splitList(os.Getenv("KURA_CLIENT_DOMAINS")),
		AdminEmails:   splitList(os.Getenv("KURA_ADMIN_EMAILS")),
	}
	if trust.FirmTenant == "" {
		return clio.UsageError("whoami", "--local requires KURA_FIRM_DOMAIN set on this box (the firm's IdP tenant — the same value `kura serve` reads)")
	}
	principal, err := trust.Principal(as, parts[1])
	if err != nil {
		// TenantTrust rejects a principal it cannot place — an unknown
		// tenant or an unknown identity. From the CLI's perspective
		// that's an auth failure: the caller is not who they say.
		return clio.AuthError("whoami", "%w", err)
	}
	return renderPrincipal(cmd, principal)
}

// runWhoamiRemote resolves the server URL through resolveServer, loads
// the cached bearer token, and GETs /api/whoami. The server's whoami
// handler reads the principal off the auth context — exactly the
// principal requireAuth resolved for the token — and returns it. The
// CLI renders the response unchanged.
func runWhoamiRemote(cmd *cobra.Command) error {
	server, err := resolveServerFromFlags(cmd, "whoami")
	if err != nil {
		return err
	}
	cache, err := defaultTokenCache()
	if err != nil {
		return err
	}
	_, token, err := cache.load()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, strings.TrimRight(server, "/")+"/api/whoami", nil)
	if err != nil {
		return clio.InternalError("whoami", "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Network-level failure: the server may or may not be there;
		// a retry might succeed. The agent should treat this as
		// transient, not as auth or input.
		return clio.TransientError("whoami", "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return classifyHTTPStatus("whoami", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var principal identity.Principal
	if err := json.NewDecoder(resp.Body).Decode(&principal); err != nil {
		return clio.InternalError("whoami", "decoding server response: %w", err)
	}
	return renderPrincipal(cmd, principal)
}

// classifyHTTPStatus maps a non-2xx HTTP response into the taxonomy.
// 401/403 → Auth, 404 → NotFound, 409/412 → Conflict, 5xx → Transient,
// everything else → Internal. The body is folded in so the caller sees
// the server's own message (already trimmed and length-bounded by the
// caller).
func classifyHTTPStatus(verb string, status int, body string) error {
	switch {
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return clio.AuthError(verb, "server returned %d: %s", status, body)
	case status == http.StatusNotFound:
		return clio.NotFoundError(verb, "server returned %d: %s", status, body)
	case status == http.StatusConflict, status == http.StatusPreconditionFailed:
		return clio.ConflictError(verb, "server returned %d: %s", status, body)
	case status >= 500:
		return clio.TransientError(verb, "server returned %d: %s", status, body)
	default:
		return clio.InternalError(verb, "server returned %d: %s", status, body)
	}
}

// resolveServerFromFlags wires the cobra flag layer into resolveServer:
// it loads the profiles file (missing-file-is-empty) and the cached
// credential, then applies the precedence rules. verb is the calling
// command's name, used to prefix any taxonomy errors that bubble up.
func resolveServerFromFlags(cmd *cobra.Command, verb string) (string, error) {
	serverFlag, _ := cmd.Flags().GetString("server")
	clientFlag, _ := cmd.Flags().GetString("client")

	path, err := defaultProfilesPath()
	if err != nil {
		return "", err
	}
	profs, err := loadProfilesFrom(path)
	if err != nil {
		return "", err
	}
	cache, err := defaultTokenCache()
	if err != nil {
		return "", err
	}
	cachedServer, _, _ := cache.load() // a missing cache is fine here; resolveServer handles empty

	return resolveServer(verb, serverInputs{
		flag:     serverFlag,
		client:   clientFlag,
		profiles: profs,
		cached:   cachedServer,
	})
}

// renderPrincipal writes the principal to stdout. --json emits a stable
// JSON object; the default is dense Markdown. The presentation goes
// through clio.Render so masking invariance (criterion tb7) is
// enforced by the shared layer rather than per-command custom code.
func renderPrincipal(cmd *cobra.Command, p identity.Principal) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	return clio.Render(cmd.OutOrStdout(), format, p, func(w io.Writer) error {
		fmt.Fprintf(w, "# %s\n\n", p.Email)
		fmt.Fprintf(w, "- type: %s\n", p.Type)
		fmt.Fprintf(w, "- tenant: %s\n", p.Tenant)
		fmt.Fprintf(w, "- id: %s\n", p.ID)
		return nil
	})
}
