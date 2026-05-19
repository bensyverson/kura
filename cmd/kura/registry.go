package main

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/bensyverson/kura/internal/ops"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// buildRegistry assembles the operations registry. This is the typed
// operations seam shared with MCP; agent-context, by contrast, describes
// the CLI command tree directly from Cobra so it cannot drift from the
// real commands. Operations migrate into this registry over time as
// their build-plan phases land.
func buildRegistry(root *cobra.Command) *ops.Registry {
	r := &ops.Registry{}
	r.Register(ops.Operation{
		Name:    "agent-context",
		Summary: "Emit a versioned, machine-readable description of every operation",
		Handler: func(_ []string, out io.Writer) error {
			return emitAgentContext(root, out)
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

// agentContextDoc is the wire shape of `kura agent-context`. Agents pin
// to {version} and consume {global_flags, commands} to know the full
// surface without scraping help text.
type agentContextDoc struct {
	Version     string         `json:"version"`
	GlobalFlags []agentFlag    `json:"global_flags"`
	Commands    []agentCommand `json:"commands"`
}

type agentCommand struct {
	Name        string         `json:"name"`
	Summary     string         `json:"summary"`
	Flags       []agentFlag    `json:"flags,omitempty"`
	Subcommands []agentCommand `json:"subcommands,omitempty"`
}

type agentFlag struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Summary string `json:"summary"`
}

// emitAgentContext walks the live Cobra command tree rooted at root and
// writes a versioned JSON description of every command and flag. Because
// the document is generated from the running command tree, a new verb
// cannot land in commands.go without surfacing here.
func emitAgentContext(root *cobra.Command, out io.Writer) error {
	doc := agentContextDoc{
		Version:     ops.ContextVersion,
		GlobalFlags: collectFlags(root.PersistentFlags()),
		Commands:    collectCommands(root),
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// collectCommands returns the visible subcommands of parent in
// name-sorted order, recursing into each. Cobra's built-in help and
// completion commands and any hidden command are excluded — the document
// describes Kura's surface, not Cobra's plumbing.
func collectCommands(parent *cobra.Command) []agentCommand {
	subs := parent.Commands()
	out := make([]agentCommand, 0, len(subs))
	for _, c := range subs {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		out = append(out, agentCommand{
			Name:        c.Name(),
			Summary:     c.Short,
			Flags:       collectFlags(c.LocalFlags()),
			Subcommands: collectCommands(c),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// collectFlags walks a flag set and emits a name-sorted list of flags
// declared on that specific set; inherited persistent flags are skipped
// so they don't appear redundantly on every command — they belong in the
// document's global_flags block.
func collectFlags(fs *pflag.FlagSet) []agentFlag {
	var out []agentFlag
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		out = append(out, agentFlag{
			Name:    f.Name,
			Type:    f.Value.Type(),
			Summary: f.Usage,
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
