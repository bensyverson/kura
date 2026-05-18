package main

import (
	"testing"
)

// The root command must expose a stable, documented set of global flags
// — the agent contract for state-carrying. Every verb must inherit them,
// so they are persistent flags on the root rather than per-command.
func TestRootCommandExposesGlobalFlags(t *testing.T) {
	root := newRootCmd()
	want := []struct {
		name string
		kind string // "string" or "bool"
	}{
		{"server", "string"},
		{"client", "string"},
		{"as", "string"},
		{"json", "bool"},
		{"local", "bool"},
		{"confirm", "bool"},
	}
	for _, f := range want {
		flag := root.PersistentFlags().Lookup(f.name)
		if flag == nil {
			t.Errorf("root command is missing the --%s persistent flag", f.name)
			continue
		}
		if flag.Value.Type() != f.kind {
			t.Errorf("--%s is %s, want %s", f.name, flag.Value.Type(), f.kind)
		}
	}
}

// A subcommand must inherit the global flags — they are persistent. A
// caller running `kura whoami --server ...` must reach the same flag the
// root would see.
func TestSubcommandInheritsGlobalFlags(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"agent-context", "--server", "https://example.test", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("subcommand with global flags failed: %v", err)
	}
}
