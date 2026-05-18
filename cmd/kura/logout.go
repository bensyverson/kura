package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/cobra"
)

// newLogoutCmd builds `kura logout`: delete the cached short-lived
// token. The next remote command will fall through to the "no cached
// credential" auth error until `kura login` runs again.
//
// logout is deliberately idempotent — an agent must be able to call it
// without first checking whether a credential exists. A missing file
// is reported as a clean no-op on stdout, not an error.
func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Delete the cached login token",
		Long: `Delete the cached short-lived login token, if any.

logout is idempotent: an empty cache is a no-op, not an error. After
logout, the next remote command will report "no cached credential
(run kura login)" until you sign in again.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cache, err := defaultTokenCache()
			if err != nil {
				return err
			}
			if err := os.Remove(cache.path()); err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					fmt.Fprintln(cmd.OutOrStdout(), "Signed out. (no cached credential)")
					return nil
				}
				return clio.InternalError("logout", "removing cached credential: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Signed out. Cached credential removed.")
			return nil
		},
	}
}
