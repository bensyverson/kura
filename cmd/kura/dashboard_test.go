package main

import "testing"

// `kura dashboard` is wired into the command tree as the real command,
// not the not-implemented stub. The stub carries no flags; the real
// command carries --addr, so the flag's presence proves the wiring.
func TestDashboardCommandIsWired(t *testing.T) {
	root := newRootCmd()
	dash, _, err := root.Find([]string{"dashboard"})
	if err != nil {
		t.Fatalf("finding dashboard command: %v", err)
	}
	if dash.Name() != "dashboard" {
		t.Fatalf("found command %q, want dashboard", dash.Name())
	}
	if dash.Flags().Lookup("addr") == nil {
		t.Fatal("dashboard in the command tree is still the not-implemented stub (no --addr flag)")
	}
}

// The dashboard binds a loopback address by default, overridable with
// --addr.
func TestDashboardCommandHasAddrFlag(t *testing.T) {
	addr := newDashboardCmd().Flags().Lookup("addr")
	if addr == nil {
		t.Fatal("dashboard command has no --addr flag")
	}
	if addr.DefValue == "" {
		t.Error("--addr flag has no default value")
	}
}

// An operator can suppress the browser launch — useful for headless or
// remote-shell sessions where opening a browser is meaningless.
func TestDashboardCommandHasNoBrowserFlag(t *testing.T) {
	if newDashboardCmd().Flags().Lookup("no-browser") == nil {
		t.Fatal("dashboard command has no --no-browser flag")
	}
}
