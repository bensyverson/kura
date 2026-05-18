package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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
		return errors.New("whoami: --local requires --as <email> (the principal to resolve)")
	}
	parts := strings.SplitN(as, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return fmt.Errorf("whoami: --as must be an email (got %q)", as)
	}
	trust := identity.TenantTrust{
		FirmTenant:    os.Getenv("KURA_FIRM_DOMAIN"),
		ClientTenants: splitList(os.Getenv("KURA_CLIENT_DOMAINS")),
		AdminEmails:   splitList(os.Getenv("KURA_ADMIN_EMAILS")),
	}
	if trust.FirmTenant == "" {
		return errors.New("whoami: --local requires KURA_FIRM_DOMAIN set on this box (the firm's IdP tenant — the same value `kura serve` reads)")
	}
	principal, err := trust.Principal(as, parts[1])
	if err != nil {
		return fmt.Errorf("whoami: %w", err)
	}
	return renderPrincipal(cmd, principal)
}

// runWhoamiRemote resolves the server URL through resolveServer, loads
// the cached bearer token, and GETs /api/whoami. The server's whoami
// handler reads the principal off the auth context — exactly the
// principal requireAuth resolved for the token — and returns it. The
// CLI renders the response unchanged.
func runWhoamiRemote(cmd *cobra.Command) error {
	server, err := resolveServerFromFlags(cmd)
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
		return fmt.Errorf("whoami: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("whoami: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("whoami: server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var principal identity.Principal
	if err := json.NewDecoder(resp.Body).Decode(&principal); err != nil {
		return fmt.Errorf("whoami: decoding server response: %w", err)
	}
	return renderPrincipal(cmd, principal)
}

// resolveServerFromFlags wires the cobra flag layer into resolveServer:
// it loads the profiles file (missing-file-is-empty) and the cached
// credential, then applies the precedence rules.
func resolveServerFromFlags(cmd *cobra.Command) (string, error) {
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

	return resolveServer(serverInputs{
		flag:     serverFlag,
		client:   clientFlag,
		profiles: profs,
		cached:   cachedServer,
	})
}

// renderPrincipal writes the principal to stdout. --json emits a stable
// JSON object; the default is dense Markdown. Both render identically
// in terms of which fields are visible; output format is a presentation
// choice, never a data-visibility one.
func renderPrincipal(cmd *cobra.Command, p identity.Principal) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	if useJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "# %s\n\n", p.Email)
	fmt.Fprintf(cmd.OutOrStdout(), "- type: %s\n", p.Type)
	fmt.Fprintf(cmd.OutOrStdout(), "- tenant: %s\n", p.Tenant)
	fmt.Fprintf(cmd.OutOrStdout(), "- id: %s\n", p.ID)
	return nil
}
