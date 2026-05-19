package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/spf13/cobra"
)

// agentContext is a local mirror of the JSON shape emitted by
// `kura agent-context`. It is intentionally redeclared here (rather than
// imported) so the tests can fail if the shape silently shifts.
type agentContext struct {
	Version     string             `json:"version"`
	GlobalFlags []agentContextFlag `json:"global_flags"`
	Commands    []agentContextCmd  `json:"commands"`
}

type agentContextCmd struct {
	Name        string             `json:"name"`
	Summary     string             `json:"summary"`
	Flags       []agentContextFlag `json:"flags,omitempty"`
	Subcommands []agentContextCmd  `json:"subcommands,omitempty"`
}

type agentContextFlag struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Summary string `json:"summary"`
}

func runAgentContext(t *testing.T) agentContext {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"agent-context"})
	if err := root.Execute(); err != nil {
		t.Fatalf("kura agent-context returned an error: %v", err)
	}
	var ctx agentContext
	if err := json.Unmarshal(out.Bytes(), &ctx); err != nil {
		t.Fatalf("agent-context output is not valid JSON: %v\n%s", err, out.String())
	}
	return ctx
}

// agent-context must carry a non-empty schema version; agents pin against
// it to detect incompatible shape changes.
func TestAgentContextCarriesVersion(t *testing.T) {
	ctx := runAgentContext(t)
	if ctx.Version == "" {
		t.Fatalf("agent-context JSON must carry a version")
	}
}

// Every command on the root, recursively, must appear in the
// agent-context document — this is the drift guard. We walk the live
// Cobra tree and confirm every command surfaces in the JSON, so a new
// verb cannot be added in commands.go without showing up here.
func TestAgentContextCoversEveryCobraCommand(t *testing.T) {
	root := newRootCmd()
	ctx := runAgentContext(t)

	cobraNames := collectCobraNames(root, "")
	jsonNames := collectAgentNames(ctx.Commands, "")

	for _, name := range cobraNames {
		if _, ok := jsonNames[name]; !ok {
			t.Errorf("agent-context is missing command %q (drift detected: %d cobra commands, %d in JSON)",
				name, len(cobraNames), len(jsonNames))
		}
	}
}

// Each command in the document must carry a non-empty summary so an
// agent has something to display without scraping --help text.
func TestAgentContextCommandsHaveSummaries(t *testing.T) {
	ctx := runAgentContext(t)
	var walk func(prefix string, cmds []agentContextCmd)
	walk = func(prefix string, cmds []agentContextCmd) {
		for _, c := range cmds {
			full := prefix + c.Name
			if c.Summary == "" {
				t.Errorf("command %q has no summary in agent-context", full)
			}
			walk(full+" ", c.Subcommands)
		}
	}
	walk("", ctx.Commands)
}

// Per-command flags must appear in the document. We assert a specific
// flag we know exists — `kura jobs get --wait` — to confirm flag
// enumeration is wired and surfaces the right metadata.
func TestAgentContextIncludesPerCommandFlags(t *testing.T) {
	ctx := runAgentContext(t)
	jobs := findCmd(ctx.Commands, "jobs")
	if jobs == nil {
		t.Fatalf("agent-context missing `jobs` command")
	}
	get := findCmd(jobs.Subcommands, "get")
	if get == nil {
		t.Fatalf("agent-context missing `jobs get` subcommand")
	}
	if !hasFlag(get.Flags, "wait") {
		t.Errorf("expected `jobs get` to expose --wait flag, got %+v", get.Flags)
	}
	if !hasFlag(get.Flags, "timeout") {
		t.Errorf("expected `jobs get` to expose --timeout flag, got %+v", get.Flags)
	}
}

// The root's persistent flags are the agent's state-carrying contract.
// They must surface as a top-level `global_flags` block so an agent does
// not have to walk every command looking for them.
func TestAgentContextIncludesGlobalFlags(t *testing.T) {
	ctx := runAgentContext(t)
	wantNames := []string{"server", "client", "as", "json", "local", "confirm"}
	for _, name := range wantNames {
		if !hasFlag(ctx.GlobalFlags, name) {
			t.Errorf("agent-context global_flags missing %q (got %+v)", name, ctx.GlobalFlags)
		}
	}
}

// Inherited persistent flags should NOT be duplicated on commands that
// only inherit them — they belong in `global_flags`. A command may still
// declare its own local flag with the same name (login does this to
// override --server), and that legitimate local declaration must appear.
// `whoami` is the canary: it declares no local flags, so its per-command
// `flags` slice should be empty.
func TestAgentContextDoesNotDuplicateGlobalFlagsPerCommand(t *testing.T) {
	ctx := runAgentContext(t)
	whoami := findCmd(ctx.Commands, "whoami")
	if whoami == nil {
		t.Fatalf("agent-context missing `whoami` command")
	}
	if hasFlag(whoami.Flags, "server") {
		t.Errorf("whoami should not carry inherited --server in its per-command flags (belongs in global_flags); got %+v", whoami.Flags)
	}
}

// The help and completion commands are Cobra-generated noise — they
// should be excluded so the document describes Kura's surface, not
// Cobra's plumbing.
func TestAgentContextExcludesHelpAndCompletion(t *testing.T) {
	ctx := runAgentContext(t)
	for _, c := range ctx.Commands {
		if c.Name == "help" || c.Name == "completion" {
			t.Errorf("agent-context should not include the Cobra %q command", c.Name)
		}
	}
}

func collectCobraNames(cmd *cobra.Command, prefix string) []string {
	var names []string
	for _, c := range cmd.Commands() {
		if c.Name() == "help" || c.Name() == "completion" || c.Hidden {
			continue
		}
		full := prefix + c.Name()
		names = append(names, full)
		names = append(names, collectCobraNames(c, full+" ")...)
	}
	return names
}

func collectAgentNames(cmds []agentContextCmd, prefix string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, c := range cmds {
		full := prefix + c.Name
		out[full] = struct{}{}
		for k := range collectAgentNames(c.Subcommands, full+" ") {
			out[k] = struct{}{}
		}
	}
	return out
}

func findCmd(cmds []agentContextCmd, name string) *agentContextCmd {
	for i := range cmds {
		if cmds[i].Name == name {
			return &cmds[i]
		}
	}
	return nil
}

func hasFlag(flags []agentContextFlag, name string) bool {
	for _, f := range flags {
		if f.Name == name {
			return true
		}
	}
	return false
}
