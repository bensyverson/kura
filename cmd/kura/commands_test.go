package main

import (
	"bytes"
	"strings"
	"testing"
)

// The root command must expose a discoverable command tree: `kura --help`
// is the first thing an agent runs, and every product surface (serve,
// dashboard, mcp) plus the core CLI verbs must be visible there.
func TestRootHelpListsCommandTree(t *testing.T) {
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("kura --help returned an error: %v", err)
	}

	got := out.String()
	for _, verb := range []string{"status", "serve", "dashboard", "mcp", "login", "init"} {
		if !strings.Contains(got, verb) {
			t.Errorf("kura --help output is missing the %q command:\n%s", verb, got)
		}
	}
}

// Stub verbs must fail loudly rather than silently succeeding, so no
// caller mistakes an unimplemented surface for a working one. The test
// exercises the stub mechanism directly rather than naming a specific
// verb, so it stays valid as each phase replaces its own stub with a
// real command.
func TestStubVerbReportsNotImplemented(t *testing.T) {
	cmd := newStubCmd("example", "A surface wired into the tree but not yet built")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected stub verb to return an error, got nil")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("stub error should say %q, got: %v", "not implemented", err)
	}
}
