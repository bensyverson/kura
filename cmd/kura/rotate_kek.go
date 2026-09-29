package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/bensyverson/kura/internal/db"
	"github.com/bensyverson/kura/internal/keystore"
	"github.com/bensyverson/kura/internal/secrets"
	"github.com/spf13/cobra"
)

const rotateKEKSummary = "Re-wrap every DEK under a new master KEK (KEK-only rotation)"

// newRotateKEKCmd builds `kura rotate-kek`: an operational, resumable job that
// re-wraps every wrapped DEK in the key store from the retiring KEK generation
// to the active one. It is KEK-only rotation (ADR 0002) — the DEK value, and
// therefore every ciphertext in the live database and the immutable backups,
// is left untouched and fully decryptable; only the wrapping changes.
//
// It connects directly to the key store (like a migration), not through the
// HTTP API: at hundreds of millions of DEKs this is a long, throughput-bound
// job, not a request. The operator first sets the active KEK to the new
// generation and loads the retiring one alongside it (KURA_KEK_VERSION,
// FIELD_ENCRYPTION_KEY_RETIRING, KURA_KEK_RETIRING_VERSION); the running
// server then reads the mixed store correctly while this command drains the
// old generation. It is safe to interrupt and re-run — progress lives durably
// in each row's kek_version, so a re-run resumes and never double-wraps.
func newRotateKEKCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate-kek",
		Short: rotateKEKSummary,
		Long: `Re-wrap every DEK in the key store from the retiring KEK to the active one.

This is KEK-only rotation: it unwraps each per-value DEK with the retiring
master key and re-wraps it with the active one, then stamps the row's new
generation. The DEK value never changes, so every ciphertext — in the live
database and in the deny-delete immutable backups — stays decryptable. (Per
ADR 0002, per-value DEK rotation is deliberately not done: it would break the
backups.)

Before running, provision the new KEK and configure the server for the
rotation:

  FIELD_ENCRYPTION_KEY           the new (active) KEK
  KURA_KEK_VERSION               its generation, one above the old one
  FIELD_ENCRYPTION_KEY_RETIRING  the old (retiring) KEK
  KURA_KEK_RETIRING_VERSION      its generation

The running server, holding both keys, keeps reading correctly while this
command re-wraps the store. It connects directly to KURA_KEYSTORE_DATABASE_URL
and is safe to interrupt: re-running resumes from where it stopped and never
double-wraps a row. When it reports every row rotated, remove the retiring KEK
from the configuration.`,
		RunE: rotateKEKRun,
	}
	cmd.Flags().Int("batch", 1000, "wrapped DEKs to re-wrap per committed batch")
	return cmd
}

// rotateKEKRun sources the rotation config from the environment and secrets
// backend, connects to the key store, and drives the re-wrap to completion.
func rotateKEKRun(cmd *cobra.Command, _ []string) error {
	getenv := os.Getenv
	tenantID := getenv("KURA_DB_TENANT_ID")
	if tenantID == "" {
		return clio.UsageError("rotate-kek", "KURA_DB_TENANT_ID is required")
	}
	dsn := getenv("KURA_KEYSTORE_DATABASE_URL")
	if dsn == "" {
		return clio.UsageError("rotate-kek", "KURA_KEYSTORE_DATABASE_URL is required (the key store to re-wrap)")
	}

	backend, err := buildSecretsBackend(getenv)
	if err != nil {
		return err
	}
	from, to, rewrap, err := buildRotationPlan(cmd.Context(), backend, getenv)
	if err != nil {
		return err
	}

	pool, err := db.Open(dsn)
	if err != nil {
		return clio.InternalError("rotate-kek", "opening key store: %w", err)
	}
	defer pool.Close()
	store, err := keystore.NewPostgresStore(pool)
	if err != nil {
		return clio.InternalError("rotate-kek", "building key store: %w", err)
	}

	batch, _ := cmd.Flags().GetInt("batch")
	_, err = runRotateKEK(cmd.Context(), store, tenantID, from, to, batch, rewrap, cmd.OutOrStdout())
	return err
}

// buildRotationPlan derives the rotation from the configured KEK generations:
// the retiring version (KURA_KEK_RETIRING_VERSION) is the source, the active
// version (KURA_KEK_VERSION) the target, and the rewrap unwraps under the
// retiring KEK and re-wraps under the active one — both taken from the key
// ring, so no raw KEK is handled here. A rotation needs a key to rotate away
// from, so a missing retiring generation is a clear error.
func buildRotationPlan(ctx context.Context, backend secrets.Backend, getenv func(string) string) (from, to int, rewrap keystore.Rewrap, err error) {
	raw := getenv(kekRetiringVersionVar)
	if strings.TrimSpace(raw) == "" {
		return 0, 0, nil, clio.UsageError("rotate-kek",
			"a rotation requires %s and %s to be set (the KEK to rotate away from)", kekRetiringVersionVar, secrets.EncryptionKeyRetiringName)
	}
	ring, err := buildKeyRing(ctx, backend, getenv)
	if err != nil {
		return 0, 0, nil, err
	}
	from, err = parsePositiveInt(raw, kekRetiringVersionVar)
	if err != nil {
		return 0, 0, nil, err
	}
	to = ring.ActiveVersion()
	rewrap = func(oldWrapped []byte) ([]byte, error) {
		dek, err := ring.Unwrap(oldWrapped, from)
		if err != nil {
			return nil, err
		}
		newWrapped, _, err := ring.WrapActive(dek)
		return newWrapped, err
	}
	return from, to, rewrap, nil
}

// runRotateKEK drives the resumable, batched rotation to completion, reporting
// per-batch progress and a final total to out. It returns the number of rows
// rotated in this run (zero if the store was already fully rotated).
func runRotateKEK(ctx context.Context, store keystore.KeyStore, tenantID string, from, to, batchSize int, rewrap keystore.Rewrap, out io.Writer) (int, error) {
	fmt.Fprintf(out, "Rotating wrapped DEKs from KEK v%d to v%d (batch %d)…\n", from, to, batchSize)
	total, err := keystore.Rotate(ctx, store, tenantID, from, to, batchSize, rewrap, func(_, running int) {
		fmt.Fprintf(out, "  … %d rotated\n", running)
	})
	if err != nil {
		return total, clio.InternalError("rotate-kek", "rotating wrapped DEKs (re-run to resume): %w", err)
	}
	fmt.Fprintf(out, "Done: %d wrapped DEK(s) now at KEK v%d.\n", total, to)
	return total, nil
}
