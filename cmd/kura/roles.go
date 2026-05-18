package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/bensyverson/kura/internal/cedar"
	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/cobra"
)

// newRoleCmd builds the `kura role` verb tree: assign, revoke, list.
// assign/revoke take roles via repeated --role flags and emails as
// positional args; both are variadic and the per-user call is atomic at
// the data layer. list is read-only — policy authoring is a repo/PR
// activity, never an API mutation.
func newRoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Manage role assignments and inspect the effective policy",
		Long: `Manage role assignments on the authorized-user list.

assign/revoke are variadic in both roles and users — repeat --role for
each role, then list the emails as positional arguments. Each
per-user call is atomic at the data layer; the whole set of named
roles applies or none of them do, for that user.`,
	}
	cmd.AddCommand(newRoleAssignCmd())
	cmd.AddCommand(newRoleRevokeCmd())
	cmd.AddCommand(newRoleListCmd())
	return cmd
}

// newRoleAssignCmd builds `kura role assign --role <r>... <email>...`.
func newRoleAssignCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assign --role <role>... <email>...",
		Short: "Grant one or more roles to one or more users",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoleMutation(cmd, args, true)
		},
	}
	cmd.Flags().StringArray("role", nil, "role to assign (repeat for multiple roles)")
	return cmd
}

// newRoleRevokeCmd builds `kura role revoke --role <r>... <email>...`.
func newRoleRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke --role <role>... <email>...",
		Short: "Remove one or more roles from one or more users",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoleMutation(cmd, args, false)
		},
	}
	cmd.Flags().StringArray("role", nil, "role to revoke (repeat for multiple roles)")
	return cmd
}

// newRoleListCmd builds `kura role list`: render the effective
// authorization policy — the roles the deployment defines and the
// grants that attach permissions to them. Read-only by design: there
// is no write route on /api/policy, so there is no `kura role create`.
func newRoleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show the effective authorization policy (read-only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			server, err := resolveServerFromFlags(cmd, "role list")
			if err != nil {
				return err
			}
			policy, err := fetchPolicy(cmd, server)
			if err != nil {
				return err
			}
			return renderPolicy(cmd, policy)
		},
	}
}

// runRoleMutation is the shared body of assign/revoke. assign=true
// chooses the direction; the rest — flag parsing, validation, the
// per-user atomic call — is identical.
func runRoleMutation(cmd *cobra.Command, emails []string, assign bool) error {
	verb := "role revoke"
	if assign {
		verb = "role assign"
	}
	roles, _ := cmd.Flags().GetStringArray("role")
	if len(roles) == 0 {
		return clio.UsageError(verb, "at least one --role <role> is required")
	}
	if len(emails) == 0 {
		return clio.UsageError(verb, "at least one email is required")
	}
	server, err := resolveServerFromFlags(cmd, verb)
	if err != nil {
		return err
	}
	for _, email := range emails {
		if err := postRoles(cmd, server, verb, email, roles, assign); err != nil {
			return err
		}
	}
	action := "Granted"
	next := "`kura user list` to confirm the new role set."
	if !assign {
		action = "Revoked"
		next = "`kura user list` to confirm, or `kura user deactivate <email>` to strip every role at once."
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s role(s) %s on %d user(s): %s.\nNext: %s\n",
		action, strings.Join(roles, ", "), len(emails), strings.Join(emails, ", "), next)
	return nil
}

// postRoles issues one POST or DELETE on /api/users/{email}/roles. The
// per-user call is atomic at the data layer — the named role set
// applies or none of it does, for that user.
func postRoles(cmd *cobra.Command, server, verb, email string, roles []string, assign bool) error {
	method := http.MethodPost
	if !assign {
		method = http.MethodDelete
	}
	body, _ := json.Marshal(struct {
		Roles []string `json:"roles"`
	}{Roles: roles})
	target := strings.TrimRight(server, "/") + "/api/users/" + url.PathEscape(email) + "/roles"
	return doAdminMutation(cmd, verb, method, target, body)
}

// fetchPolicy GETs /api/policy. The server returns the cedar.Policy IR
// directly — the CLI is a presentation layer over it.
func fetchPolicy(cmd *cobra.Command, server string) (cedar.Policy, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return cedar.Policy{}, err
	}
	_, token, err := cache.load()
	if err != nil {
		return cedar.Policy{}, err
	}
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, strings.TrimRight(server, "/")+"/api/policy", nil)
	if err != nil {
		return cedar.Policy{}, clio.InternalError("role list", "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return cedar.Policy{}, clio.TransientError("role list", "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return cedar.Policy{}, classifyHTTPStatus("role list", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var p cedar.Policy
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return cedar.Policy{}, clio.InternalError("role list", "decoding server response: %w", err)
	}
	return p, nil
}

// renderPolicy writes the effective policy to stdout — JSON for
// machines, dense Markdown for humans. Both list the role table and
// the role→entity:action grants the policy resolves to.
func renderPolicy(cmd *cobra.Command, p cedar.Policy) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	return clio.Render(cmd.OutOrStdout(), format, p, func(w io.Writer) error {
		fmt.Fprintln(w, "# kura roles (effective policy)")
		fmt.Fprintln(w)
		if len(p.Roles) == 0 {
			fmt.Fprintln(w, "no roles defined — policy authoring is a repo activity (`internal/cedar`)")
			return nil
		}
		fmt.Fprintln(w, "## Roles")
		fmt.Fprintln(w)
		for _, r := range p.Roles {
			if r.Description != "" {
				fmt.Fprintf(w, "- **%s** — %s\n", r.Name, r.Description)
				continue
			}
			fmt.Fprintf(w, "- **%s**\n", r.Name)
		}
		if len(p.Grants) == 0 {
			return nil
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "## Grants")
		fmt.Fprintln(w)
		grants := append([]cedar.Grant(nil), p.Grants...)
		sort.Slice(grants, func(i, j int) bool {
			if grants[i].Role != grants[j].Role {
				return grants[i].Role < grants[j].Role
			}
			if grants[i].Entity != grants[j].Entity {
				return grants[i].Entity < grants[j].Entity
			}
			return grants[i].Action < grants[j].Action
		})
		for _, g := range grants {
			line := fmt.Sprintf("- **%s** may `%s` on `%s`", g.Role, g.Action, g.Entity)
			if len(g.VisiblePII) > 0 {
				cats := make([]string, len(g.VisiblePII))
				for i, c := range g.VisiblePII {
					cats[i] = string(c)
				}
				line += " — visible PII: " + strings.Join(cats, ", ")
			}
			fmt.Fprintln(w, line)
		}
		return nil
	})
}
