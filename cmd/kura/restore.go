package main

import (
	"github.com/bensyverson/kura/internal/backup"
	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/cobra"
)

// newRestoreCmd builds `kura restore <object-key>`: restore the database
// from a named backup object on the remote kura serve. The restore —
// fetch from the backups bucket, decrypt, pg_restore — runs server-side
// as an async job; this verb submits it and, with --wait, polls to
// terminal. Restore is destructive (it overwrites the target database),
// so it requires --confirm.
func newRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore <object-key>",
		Short: "Restore the database from a backup object on the remote kura serve",
		Long: `Restore the database from a named backup object on the remote kura serve.

The object key names a backup in the backups bucket (as reported by a
prior ` + "`kura backup`" + ` or listed in the ledger). The server fetches it,
decrypts it with the secrets-sourced backup key, and runs pg_restore
against the target. It runs as a server-side async job recorded on the
jobs ledger; use ` + "`--wait`" + ` to poll until it finishes.

Restore overwrites the target database, so it is destructive: pass
` + "`--confirm`" + ` to proceed. Submitting a restore is an admin operation.
The idempotency key defaults to one derived from the object key, so an
accidental double-submit re-attaches to the in-flight restore rather
than running it twice.`,
		RunE: restoreRun,
	}
	cmd.Flags().Bool("wait", false, "poll until the restore job reaches a terminal status (succeeded or failed)")
	cmd.Flags().Duration("timeout", defaultWaitTimeout, "maximum time to wait when --wait is set (e.g. 30s, 2m, 1h)")
	cmd.Flags().String("idempotency-key", "", "override the object-key-derived idempotency key")
	return cmd
}

// restoreRun submits a restore job for the named object and reports it,
// optionally waiting for it to finish.
func restoreRun(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return clio.UsageError("restore", "exactly one backup object key is required")
	}
	objectKey := args[0]

	if local, _ := cmd.Flags().GetBool("local"); local {
		return clio.UsageError("restore", "--local restore needs the on-box storage backend, which lands in the deployment baseline (Phase 6); run against a remote kura serve for now")
	}
	if confirm, _ := cmd.Flags().GetBool("confirm"); !confirm {
		return clio.UsageError("restore", "restore overwrites the target database — pass --confirm to proceed")
	}

	server, err := resolveServerFromFlags(cmd, "restore")
	if err != nil {
		return err
	}

	key, _ := cmd.Flags().GetString("idempotency-key")
	if key == "" {
		key = "restore-" + objectKey
	}

	// The server stamps the authenticated principal into the params; the
	// CLI sends only the object key.
	params := struct {
		ObjectKey string `json:"object_key"`
	}{ObjectKey: objectKey}
	j, err := submitJob(cmd, "restore", server, backup.KindRestore, key, params)
	if err != nil {
		return err
	}

	if wait, _ := cmd.Flags().GetBool("wait"); wait {
		timeout, _ := cmd.Flags().GetDuration("timeout")
		if timeout <= 0 {
			timeout = defaultWaitTimeout
		}
		j, err = waitForJob(cmd, server, j.ID, timeout)
		if err != nil {
			return err
		}
	}
	return renderJob(cmd, j)
}
