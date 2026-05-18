package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/bensyverson/kura/internal/data"
	"github.com/spf13/cobra"
)

// newUserCmd builds the `kura user` verb tree: list, add, show,
// deactivate. Mutations are variadic — `kura user add alex@x bob@x` —
// and idempotent end-to-end: each individual call is atomic at the
// data layer, re-running is a no-op, and the success ack teaches the
// agent the next move (role assignment).
func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage the authorized-user list",
		Long: `Manage the authorized-user list on the remote kura serve.

Add/deactivate are variadic and idempotent: pass any number of emails;
re-running with the same arguments is a no-op. Roles are managed
separately, via ` + "`kura role`" + ` — adding a user does not grant access.`,
	}
	cmd.AddCommand(newUserListCmd())
	cmd.AddCommand(newUserAddCmd())
	cmd.AddCommand(newUserShowCmd())
	cmd.AddCommand(newUserDeactivateCmd())
	return cmd
}

// newUserListCmd builds `kura user list`: GET /api/users, sorted by
// email, each user with its roles. The empty case is reported
// explicitly so an agent learns "no users" without grepping the body.
func newUserListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every authorized user with the roles they hold",
		RunE: func(cmd *cobra.Command, _ []string) error {
			server, err := resolveServerFromFlags(cmd, "user list")
			if err != nil {
				return err
			}
			users, err := fetchUsers(cmd, server, "user list")
			if err != nil {
				return err
			}
			return renderUsers(cmd, users)
		},
	}
}

// newUserAddCmd builds `kura user add <email>...`: variadic add to the
// authorized list. Each individual add is atomic and idempotent at the
// data layer; the success ack names the role-assignment verb so an
// agent doesn't have to guess the next step.
func newUserAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <email>...",
		Short: "Add one or more users to the authorized list",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return clio.UsageError("user add", "at least one email is required")
			}
			server, err := resolveServerFromFlags(cmd, "user add")
			if err != nil {
				return err
			}
			added := make([]string, 0, len(args))
			for _, email := range args {
				if err := postUser(cmd, server, email); err != nil {
					return err
				}
				added = append(added, email)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Added %d user(s): %s.\nNext: `kura role assign --role <role> %s` to grant access.\n",
				len(added), strings.Join(added, ", "), strings.Join(added, " "))
			return nil
		},
	}
}

// newUserShowCmd builds `kura user show <email>`: render one user's
// row of the authorized list. Implemented as a filtered list — there
// is no per-user server endpoint, and the list is small enough that a
// filter is cheaper than a new route.
func newUserShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <email>",
		Short: "Show a single authorized user and the roles they hold",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return clio.UsageError("user show", "exactly one email is required")
			}
			email := strings.ToLower(args[0])
			server, err := resolveServerFromFlags(cmd, "user show")
			if err != nil {
				return err
			}
			users, err := fetchUsers(cmd, server, "user show")
			if err != nil {
				return err
			}
			for _, u := range users {
				if strings.ToLower(u.Email) == email {
					return renderUsers(cmd, []data.User{u})
				}
			}
			return clio.NotFoundError("user show", "no such authorized user %q — run `kura user list` to see the menu", email)
		},
	}
}

// newUserDeactivateCmd builds `kura user deactivate <email>...`:
// variadic deactivate. Each call is a DELETE /api/users/{email}, which
// atomically strips every role on the server and leaves the user on
// the list for audit history. Idempotent: deactivating an
// already-deactivated user is a no-op.
func newUserDeactivateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deactivate <email>...",
		Short: "Revoke all roles from one or more users (auditable; keeps them on the list)",
		Long: `Revoke every role from each named user.

The user stays on the authorized list — deactivation is auditable
history, not a delete. To re-grant access, ` + "`kura role assign`" + ` —
adding the same user back with ` + "`kura user add`" + ` is a no-op.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return clio.UsageError("user deactivate", "at least one email is required")
			}
			server, err := resolveServerFromFlags(cmd, "user deactivate")
			if err != nil {
				return err
			}
			done := make([]string, 0, len(args))
			for _, email := range args {
				if err := deleteUser(cmd, server, email); err != nil {
					return err
				}
				done = append(done, email)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deactivated %d user(s): %s.\nNext: `kura user list` to confirm, or `kura role assign --role <role> <email>` to restore access.\n",
				len(done), strings.Join(done, ", "))
			return nil
		},
	}
}

// fetchUsers GETs /api/users with the cached bearer token and decodes
// the body. Errors are classified through the shared HTTP-status
// mapper, so an agent sees the same taxonomy across every verb.
func fetchUsers(cmd *cobra.Command, server, verb string) ([]data.User, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return nil, err
	}
	_, token, err := cache.load()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, strings.TrimRight(server, "/")+"/api/users", nil)
	if err != nil {
		return nil, clio.InternalError(verb, "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, clio.TransientError(verb, "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, classifyHTTPStatus(verb, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Users []data.User `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, clio.InternalError(verb, "decoding server response: %w", err)
	}
	return out.Users, nil
}

// postUser POSTs one email to /api/users. The server's AddUser is
// idempotent — a 204 the second time as well as the first.
func postUser(cmd *cobra.Command, server, email string) error {
	body, _ := json.Marshal(struct {
		Email string `json:"email"`
	}{Email: email})
	return doAdminMutation(cmd, "user add", http.MethodPost,
		strings.TrimRight(server, "/")+"/api/users", body)
}

// deleteUser DELETEs /api/users/{email}. Path-escaped so an `@` in the
// email goes through cleanly under Go's net/http routing.
func deleteUser(cmd *cobra.Command, server, email string) error {
	target := strings.TrimRight(server, "/") + "/api/users/" + url.PathEscape(email)
	return doAdminMutation(cmd, "user deactivate", http.MethodDelete, target, nil)
}

// doAdminMutation is the shared call shape behind every admin write a
// CLI verb makes: build a bearer-authenticated request, send it, and
// classify any non-2xx through the same taxonomy mapper. A 204
// (No Content) is the documented success for these endpoints.
func doAdminMutation(cmd *cobra.Command, verb, method, target string, body []byte) error {
	cache, err := defaultTokenCache()
	if err != nil {
		return err
	}
	_, token, err := cache.load()
	if err != nil {
		return err
	}
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(cmd.Context(), method, target, bodyReader)
	if err != nil {
		return clio.InternalError(verb, "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return clio.TransientError(verb, "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return classifyHTTPStatus(verb, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
}

// renderUsers writes the user list to stdout — JSON if --json is set,
// dense Markdown otherwise. Both formats show the same fields; the
// shared clio.Render layer enforces masking invariance for the CLI.
func renderUsers(cmd *cobra.Command, users []data.User) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	// Stable ordering so an agent can diff outputs across runs.
	sorted := append([]data.User(nil), users...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Email < sorted[j].Email })
	payload := struct {
		Users []data.User `json:"users"`
	}{Users: sorted}
	return clio.Render(cmd.OutOrStdout(), format, payload, func(w io.Writer) error {
		if len(sorted) == 0 {
			fmt.Fprintln(w, "# kura users")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "no users on the authorized list — add one with `kura user add <email>`")
			return nil
		}
		fmt.Fprintln(w, "# kura users")
		fmt.Fprintln(w)
		for _, u := range sorted {
			if len(u.Roles) == 0 {
				fmt.Fprintf(w, "- **%s** — no roles (deactivated; on the list for audit history)\n", u.Email)
				continue
			}
			fmt.Fprintf(w, "- **%s** — %s\n", u.Email, strings.Join(u.Roles, ", "))
		}
		return nil
	})
}
