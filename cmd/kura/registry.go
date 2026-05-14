package main

import (
	"encoding/json"
	"io"

	"github.com/bensyverson/kura/internal/ops"
	"github.com/spf13/cobra"
)

// buildRegistry assembles the operations registry. Every Kura operation
// is declared here once; the CLI commands and `kura agent-context` are
// both projected from it. This is the proof-of-concept seed — operations
// are added here as their build-plan phases land, replacing the stub
// commands in commands.go.
func buildRegistry() *ops.Registry {
	r := &ops.Registry{}
	r.Register(ops.Operation{
		Name:    "agent-context",
		Summary: "Emit a versioned, machine-readable description of every operation",
		Handler: func(args []string, out io.Writer) error {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(r.Context())
		},
	})
	return r
}

// cobraCommand projects a registry Operation into a Cobra command. The
// cmd/ layer is wiring only — the Operation owns name, summary, args, and
// behavior.
func cobraCommand(op ops.Operation) *cobra.Command {
	return &cobra.Command{
		Use:   op.Name,
		Short: op.Summary,
		RunE: func(cmd *cobra.Command, args []string) error {
			return op.Handler(args, cmd.OutOrStdout())
		},
	}
}
