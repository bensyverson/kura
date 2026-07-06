package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/cobra"
)

// eraseVerb and eraseSummary are shared by the ops-registry declaration
// (registry.go) and the hand-written command below, so the agent-facing
// projection and the CLI command cannot drift.
const (
	eraseVerb    = "erase"
	eraseSummary = "Crypto-shred records, destroying the keys that decrypt their field values"
)

// newEraseCmd builds `kura erase <record-id> [record-id...]`: crypto-shred
// a set of records through the remote kura serve. Erasure destroys the
// per-value keys, never the rows — so an erased value is permanently
// undecryptable in every copy (the live database, replicas, and the
// deny-delete immutable backup) while the record itself stays put and
// append-only entities remain intact.
//
// The verb is domain-agnostic: it names records by id. A caller maps its
// own notion of "who" — a person, an account — to a record set; erase
// knows only records. It is destructive and irreversible, so it requires
// --confirm.
func newEraseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   eraseVerb + " <record-id> [record-id...]",
		Short: eraseSummary,
		Long: `Crypto-shred a set of records through the remote kura serve.

Erasure destroys the per-value keys that decrypt a record's encrypted
fields — it does not delete the row. The ciphertext stays where it is but
becomes permanently undecryptable in every copy: the live database, its
replicas, and the deny-delete immutable backup alike. Because no row is
mutated, erasure is compatible with append-only entities.

Records are named by id — one or more. Erasure is domain-agnostic: a
caller maps its own concept of a person or account to the ids to shred.

This is destructive and irreversible. Pass ` + "`--confirm`" + ` to proceed;
it is the only confirmation. Erasing a record with no encrypted fields, or
one already erased, is harmless.`,
		RunE: eraseRun,
	}
}

// eraseRun validates the request, resolves the server, and shreds the
// named records' keys through the erasure endpoint, reporting how many
// wrapped DEKs were destroyed.
func eraseRun(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return clio.UsageError("erase", "at least one record id is required")
	}
	if local, _ := cmd.Flags().GetBool("local"); local {
		return clio.UsageError("erase", "--local erasure needs the on-box key store, which lands with the deployment baseline; run against a remote kura serve for now")
	}
	if confirm, _ := cmd.Flags().GetBool("confirm"); !confirm {
		return clio.UsageError("erase", "erasure is destructive and irreversible — pass --confirm to proceed")
	}

	server, err := resolveServerFromFlags(cmd, "erase")
	if err != nil {
		return err
	}

	shredded, err := postErase(cmd, server, args)
	if err != nil {
		return err
	}
	return renderErase(cmd, args, shredded)
}

// eraseResult is the CLI's view of POST /api/erase: how many wrapped DEKs
// the server destroyed.
type eraseResult struct {
	Shredded int `json:"shredded"`
}

// postErase POSTs the record ids to /api/erase with the cached bearer
// token and returns the shredded count. A non-2xx is classified through
// the shared HTTP-status mapper so the taxonomy is uniform across verbs.
func postErase(cmd *cobra.Command, server string, recordIDs []string) (int, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return 0, err
	}
	_, token, err := cache.load()
	if err != nil {
		return 0, err
	}
	payload, err := json.Marshal(struct {
		RecordIDs []string `json:"record_ids"`
	}{RecordIDs: recordIDs})
	if err != nil {
		return 0, clio.InternalError("erase", "encoding request: %w", err)
	}
	target := strings.TrimRight(server, "/") + "/api/erase"
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return 0, clio.InternalError("erase", "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, clio.TransientError("erase", "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, classifyHTTPStatus("erase", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out eraseResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, clio.InternalError("erase", "decoding server response: %w", err)
	}
	return out.Shredded, nil
}

// renderErase writes the outcome to stdout — JSON for machines, dense
// Markdown otherwise. The Markdown view names the records asked to erase
// and how many keys were actually destroyed.
func renderErase(cmd *cobra.Command, recordIDs []string, shredded int) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	return clio.Render(cmd.OutOrStdout(), format, eraseResult{Shredded: shredded}, func(w io.Writer) error {
		fmt.Fprintf(w, "# kura erase\n\n")
		fmt.Fprintf(w, "Requested erasure of %d record(s): %s\n", len(recordIDs), strings.Join(recordIDs, ", "))
		fmt.Fprintf(w, "Destroyed %d wrapped key(s); the erased field values can no longer be decrypted.\n", shredded)
		return nil
	})
}
