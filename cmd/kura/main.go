// Command kura is the single binary for Kura: an open-source, auditable
// secure-data-store template. It is one of four thin adapters over the
// core enforcement library in internal/ — see project/2026-05-14-architecture.md.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err.Error())
		os.Exit(1)
	}
}
