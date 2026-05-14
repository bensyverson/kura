package main

import "testing"

// `kura serve` is wired into the command tree as the real command, not
// the not-implemented stub. The stub carries no flags; the real command
// carries --addr, so the flag's presence proves the wiring.
func TestServeCommandIsWired(t *testing.T) {
	root := newRootCmd()
	serve, _, err := root.Find([]string{"serve"})
	if err != nil {
		t.Fatalf("finding serve command: %v", err)
	}
	if serve.Name() != "serve" {
		t.Fatalf("found command %q, want serve", serve.Name())
	}
	if serve.Flags().Lookup("addr") == nil {
		t.Fatal("serve in the command tree is still the not-implemented stub (no --addr flag)")
	}
}

// `kura serve` exposes an --addr flag so an operator can choose the bind
// address.
func TestServeCommandHasAddrFlag(t *testing.T) {
	addr := newServeCmd().Flags().Lookup("addr")
	if addr == nil {
		t.Fatal("serve command has no --addr flag")
	}
	if addr.DefValue == "" {
		t.Error("--addr flag has no default value")
	}
}
