// Command kura is the single binary for Kura: an open-source, auditable
// secure-data-store template. It is one of four thin adapters over the
// core enforcement library in internal/ — see project/2026-05-14-architecture.md.
package main

import (
	"fmt"
	"os"

	"github.com/bensyverson/kura/internal/clio"
)

func main() {
	err := newRootCmd().Execute()
	if err != nil {
		// stdout is data, stderr is diagnostics — never interleave.
		// ExitCode walks errors.As, so a clio error wrapped by cobra
		// or fmt.Errorf still resolves to its taxonomy code.
		fmt.Fprintln(os.Stderr, "Error:", err.Error())
	}
	os.Exit(clio.ExitCode(err))
}
