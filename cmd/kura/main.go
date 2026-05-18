// Command kura is the single binary for Kura: an open-source, auditable
// secure-data-store template. It is one of four thin adapters over the
// core enforcement library in internal/ — see project/2026-05-14-architecture.md.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/bensyverson/kura/internal/clio"
)

func main() {
	// signal.NotifyContext propagates SIGINT/SIGTERM through cmd.Context()
	// to every running verb. The long-running ones — `kura tail` today,
	// `kura --wait <op>` later — read it to shut down cleanly on Ctrl-C;
	// the short-lived ones never see it fire.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := newRootCmd().ExecuteContext(ctx)
	if err != nil {
		// stdout is data, stderr is diagnostics — never interleave.
		// ExitCode walks errors.As, so a clio error wrapped by cobra
		// or fmt.Errorf still resolves to its taxonomy code.
		fmt.Fprintln(os.Stderr, "Error:", err.Error())
	}
	os.Exit(clio.ExitCode(err))
}
