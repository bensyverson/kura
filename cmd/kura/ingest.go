package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/cobra"
)

// newIngestCmd builds `kura ingest <entity>`: read records as JSON (from a
// file or stdin) and write each through the remote server's ingestion
// endpoint, which enforces PII scanning and field encryption at the
// boundary. It is the bulk-import path for getting a client's existing
// data into Kura.
func newIngestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ingest <entity>",
		Short: "Ingest records into an entity through the remote kura serve",
		Long: `Ingest records into a manifest entity through the remote kura serve.

Records are read as JSON — a single object, or an array of objects — from
a file (--file) or from stdin. Field values are strings. Each record is
written through the server's ingestion endpoint, which authorizes the
write, validates the fields against the schema manifest, scans for PII,
and encrypts high-sensitivity and free-text fields at rest. The new
record ids are reported.`,
		RunE: ingestRun,
	}
	cmd.Flags().String("file", "", "path to a JSON file of records; reads stdin when omitted")
	return cmd
}

// ingestRun reads the records, resolves the server, and writes each one
// through the ingestion endpoint, reporting the new ids. A single
// rejected record stops the run — partial imports are reported by the ids
// already printed are not, so the operator re-runs against a corrected
// input rather than guessing which records landed.
func ingestRun(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return clio.UsageError("ingest", "exactly one entity name is required")
	}
	entity := args[0]

	server, err := resolveServerFromFlags(cmd, "ingest")
	if err != nil {
		return err
	}

	raw, err := readIngestInput(cmd)
	if err != nil {
		return err
	}
	records, err := parseIngestRecords(raw)
	if err != nil {
		return clio.UsageError("ingest", "%v", err)
	}
	if len(records) == 0 {
		return clio.UsageError("ingest", "no records to ingest")
	}

	cache, err := defaultTokenCache()
	if err != nil {
		return err
	}
	_, token, err := cache.load()
	if err != nil {
		return err
	}

	ids := make([]string, 0, len(records))
	for _, rec := range records {
		id, err := postRecord(cmd, server, entity, token, rec)
		if err != nil {
			// err is already a clio taxonomy error scoped to "ingest"; the
			// ids printed so far are not, so a partial run is re-run against
			// a corrected input rather than reconciled by hand.
			return err
		}
		ids = append(ids, id)
	}
	return renderIngestResult(cmd, entity, ids)
}

// readIngestInput reads the record JSON from --file, or from stdin when no
// file is given.
func readIngestInput(cmd *cobra.Command) ([]byte, error) {
	if file, _ := cmd.Flags().GetString("file"); file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, clio.UsageError("ingest", "reading %s: %v", file, err)
		}
		return b, nil
	}
	b, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return nil, clio.InternalError("ingest", "reading stdin: %w", err)
	}
	return b, nil
}

// parseIngestRecords accepts either a single JSON object or an array of
// objects, normalizing both to a slice of field maps. Values are strings —
// the storage layer keeps field values as text.
func parseIngestRecords(raw []byte) ([]map[string]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("input is empty")
	}
	if trimmed[0] == '[' {
		var arr []map[string]string
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("parsing JSON array of records: %w", err)
		}
		return arr, nil
	}
	var one map[string]string
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return nil, fmt.Errorf("parsing JSON record: %w", err)
	}
	return []map[string]string{one}, nil
}

// postRecord POSTs one record to /api/{entity} with the bearer token and
// returns the new record's id. A non-201 is classified through the shared
// HTTP-status taxonomy.
func postRecord(cmd *cobra.Command, server, entity, token string, fields map[string]string) (string, error) {
	body, err := json.Marshal(fields)
	if err != nil {
		return "", clio.InternalError("ingest", "encoding record: %w", err)
	}
	target := strings.TrimRight(server, "/") + "/api/" + entity
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return "", clio.InternalError("ingest", "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", clio.TransientError("ingest", "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", classifyHTTPStatus("ingest", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", clio.InternalError("ingest", "decoding server response: %w", err)
	}
	return out.ID, nil
}

// renderIngestResult writes the created ids — JSON if --json is set, dense
// Markdown otherwise.
func renderIngestResult(cmd *cobra.Command, entity string, ids []string) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	payload := struct {
		Entity  string   `json:"entity"`
		Created int      `json:"created"`
		IDs     []string `json:"ids"`
	}{Entity: entity, Created: len(ids), IDs: ids}
	return clio.Render(cmd.OutOrStdout(), format, payload, func(w io.Writer) error {
		fmt.Fprintf(w, "Ingested %d record(s) into %q:\n", len(ids), entity)
		for _, id := range ids {
			fmt.Fprintf(w, "- %s\n", id)
		}
		return nil
	})
}
