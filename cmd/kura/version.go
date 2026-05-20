package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is the build version. It is injected at build time via
//
//	-ldflags "-X main.version=$(git describe --tags ...)"
//
// by scripts/release.sh and the release workflow. A plain `go build` leaves
// it at the "dev" default; `go install ...@vX` resolves it from the module
// build info instead. It is distinct from ops.ContextVersion, which is the
// agent-context document's schema version.
var version = "dev"

// resolveVersion picks the most authoritative version available: an explicit
// ldflags value wins; otherwise the module version embedded by
// `go install ...@vX` is used; otherwise the "dev" sentinel.
func resolveVersion(ldflag string, readBuildInfo func() (*debug.BuildInfo, bool)) string {
	if ldflag != "" && ldflag != "dev" {
		return ldflag
	}
	if bi, ok := readBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	if ldflag != "" {
		return ldflag
	}
	return "dev"
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the kura version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), resolveVersion(version, debug.ReadBuildInfo))
			return nil
		},
	}
}
