package main

import (
	"fmt"
	"io"
	"sort"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/cobra"
)

// newProfileCmd builds the `kura profile` verb tree: list, add,
// remove. A consultant's laptop addresses N client servers; the
// profile commands manage that index without hand-editing the config
// file.
//
// The structural rule is that none of these verbs can take a
// credential-shaped flag — see TestProfileAddCommandHasNoCredentialFlags
// for the pin. Tokens are short-lived and come from `kura login`; they
// never live in a profile.
func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage client profiles (named server endpoints)",
		Long: `Manage the per-client profiles that --client <name> resolves to.

A profile is the pair (name, endpoint) — never a credential. Tokens
come from kura login and live in a separate, short-lived cache.`,
	}
	cmd.AddCommand(newProfileListCmd())
	cmd.AddCommand(newProfileAddCmd())
	cmd.AddCommand(newProfileRemoveCmd())
	return cmd
}

// newProfileListCmd builds `kura profile list`: enumerate every
// configured client and its endpoint. The empty case is reported
// explicitly, so an agent learns "no profiles" without grepping the
// filesystem.
func newProfileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every configured client profile",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := defaultProfilesPath()
			if err != nil {
				return err
			}
			profs, err := loadProfilesFrom(path)
			if err != nil {
				return err
			}
			useJSON, _ := cmd.Flags().GetBool("json")
			format := clio.FormatMarkdown
			if useJSON {
				format = clio.FormatJSON
			}
			return clio.Render(cmd.OutOrStdout(), format, profs, func(w io.Writer) error {
				return renderProfilesMarkdown(w, profs)
			})
		},
	}
}

// renderProfilesMarkdown writes the Markdown view of a profiles set —
// either an empty-state hint or a sorted list of (name, endpoint).
func renderProfilesMarkdown(w io.Writer, p *profiles) error {
	if len(p.Clients) == 0 {
		fmt.Fprintln(w, "# kura profiles")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "no profiles configured — add one with `kura profile add --name <n> --endpoint <URL>`")
		return nil
	}
	fmt.Fprintln(w, "# kura profiles")
	fmt.Fprintln(w)
	names := make([]string, 0, len(p.Clients))
	for n := range p.Clients {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "- **%s** — %s\n", n, p.Clients[n].Endpoint)
	}
	return nil
}

// newProfileAddCmd builds `kura profile add --name <n> --endpoint
// <URL>`. There is no credential flag, by design — see the package
// doc.
func newProfileAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new client profile",
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, _ := cmd.Flags().GetString("name")
			endpoint, _ := cmd.Flags().GetString("endpoint")
			if name == "" {
				return clio.UsageError("profile add", "--name <name> is required")
			}
			if endpoint == "" {
				return clio.UsageError("profile add", "--endpoint <URL> is required")
			}
			path, err := defaultProfilesPath()
			if err != nil {
				return err
			}
			profs, err := loadProfilesFrom(path)
			if err != nil {
				return err
			}
			if _, exists := profs.Clients[name]; exists {
				return clio.ConflictError("profile add", "client %q already exists — `kura profile remove --name %s` first if you want to replace it", name, name)
			}
			profs.Clients[name] = profileClient{Endpoint: endpoint}
			if err := saveProfilesTo(path, profs); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Added profile %q → %s.\nNext: `kura --client %s login` to cache a token, then `kura --client %s status`.\n", name, endpoint, name, name)
			return nil
		},
	}
	cmd.Flags().String("name", "", "client name (the value --client expects)")
	cmd.Flags().String("endpoint", "", "the kura serve URL for this client")
	return cmd
}

// newProfileRemoveCmd builds `kura profile remove --name <n>`. An
// unknown name surfaces the loader's enumerating NotFound error.
func newProfileRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a client profile",
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, _ := cmd.Flags().GetString("name")
			if name == "" {
				return clio.UsageError("profile remove", "--name <name> is required")
			}
			path, err := defaultProfilesPath()
			if err != nil {
				return err
			}
			profs, err := loadProfilesFrom(path)
			if err != nil {
				return err
			}
			if _, exists := profs.Clients[name]; !exists {
				// Surface the loader's enumerating "no such client"
				// error directly so the agent sees the menu inline.
				if _, lookupErr := profs.endpoint(name); lookupErr != nil {
					return lookupErr
				}
			}
			delete(profs.Clients, name)
			if err := saveProfilesTo(path, profs); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed profile %q.\n", name)
			return nil
		},
	}
	cmd.Flags().String("name", "", "client name to remove")
	return cmd
}
