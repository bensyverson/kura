package main

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	withVersion := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: v}}, true
		}
	}
	noBuildInfo := func() (*debug.BuildInfo, bool) { return nil, false }

	tests := []struct {
		name          string
		ldflag        string
		readBuildInfo func() (*debug.BuildInfo, bool)
		want          string
	}{
		// An explicit ldflags-injected version (set by scripts/release.sh and
		// the release workflow) always wins.
		{"ldflags value wins", "v1.2.3", withVersion("v9.9.9"), "v1.2.3"},
		// `go install ...@vX` leaves the ldflag at its "dev" default but the
		// module version is embedded in the build info.
		{"falls back to build info for go install", "dev", withVersion("v0.5.0"), "v0.5.0"},
		// A plain `go build` from a checkout reports "(devel)" — not a real
		// version, so we keep the "dev" sentinel.
		{"devel build info is ignored", "dev", withVersion("(devel)"), "dev"},
		{"no build info", "dev", noBuildInfo, "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.ldflag, tt.readBuildInfo); got != tt.want {
				t.Errorf("resolveVersion(%q) = %q, want %q", tt.ldflag, got, tt.want)
			}
		})
	}
}

func TestVersionCommand(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })
	version = "v9.9.9"

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("kura version: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "v9.9.9" {
		t.Errorf("kura version printed %q, want %q", got, "v9.9.9")
	}
}
