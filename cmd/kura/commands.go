package main

import (
	"errors"

	"github.com/spf13/cobra"
)

// newStubCmd builds a placeholder command for a surface that is wired into
// the tree but not yet implemented. It fails loudly so no caller mistakes
// an unbuilt verb for a working one. Each stub is replaced by a real
// implementation in its own file as its build-plan phase lands.
func newStubCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New(cmd.Name() + ": not implemented yet")
		},
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "kura",
		Short:         "Provision and operate a secure, audited, PII-aware data store",
		Long:          rootLongHelp,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// The product surfaces (build plan phases 2, 4, 5, 7) and the core CLI
	// verbs (phase 3). All stubs for now; each phase replaces its own.
	cmd.AddCommand(newStubCmd("status", "Session opener: identity check and landscape briefing"))
	cmd.AddCommand(newServeCmd())
	cmd.AddCommand(newStubCmd("dashboard", "Run the local web dashboard (loopback-bound HTTP client)"))
	cmd.AddCommand(newStubCmd("mcp", "Run the MCP server (local stdio proxy by default)"))
	cmd.AddCommand(newStubCmd("login", "Sign in via OAuth and cache a short-lived token"))
	cmd.AddCommand(newStubCmd("init", "Materialize a per-client deployment scaffold"))
	cmd.AddCommand(newStubCmd("user", "Manage users"))
	cmd.AddCommand(newStubCmd("role", "Manage role assignments"))
	cmd.AddCommand(newStubCmd("query", "Query records (filtered, bounded, masked)"))
	cmd.AddCommand(newStubCmd("show", "Show a single record with related entities"))

	// Operations projected from the registry — the single source of
	// truth shared with MCP and agent-context. Stubs above are replaced
	// by registry entries as their build-plan phases land.
	for _, op := range buildRegistry().All() {
		cmd.AddCommand(cobraCommand(op))
	}

	return cmd
}

const rootLongHelp = `kura — the single binary for Kura, an open-source, auditable secure-data-store template.

One core, four faces: the core enforcement library (Cedar authorization, audit
logging, PII masking, field-level encryption) lives in internal/. The CLI,
` + "`kura serve`" + ` (HTTP API), ` + "`kura dashboard`" + ` (local web app), and
` + "`kura mcp`" + ` are thin adapters over it.

The CLI is remote-first: ` + "`kura <verb>`" + ` is by default an HTTP client of a
remote ` + "`kura serve`" + `. ` + "`--local`" + ` is the break-glass exception.

This is a skeleton build — every verb below is a stub. See the build plan in
project/ for what each phase delivers.`
