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

Records are read as JSON — a single record, or an array of records — from
a file (--file) or from stdin. Each record is an object of the form:

    {"fields": {"name": "value", ...},
     "relationships": {"relationship_name": ["target-id", ...]}}

Field values are strings. "relationships" is optional: it maps a
relationship the manifest declares on the entity to the ids of the target
records it points at — a "one" relationship takes a single id, a "many"
relationship takes several. Relationships are supplied only at creation.

Each record is written through the server's ingestion endpoint, which
authorizes the write, validates the fields and relationships against the
schema manifest, scans for PII, and encrypts high-sensitivity and
free-text fields at rest. The new record ids are reported.`,
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

// ingestRecord is one record to create: its field values and, optionally,
// the relationship edges to create with it. It mirrors the server's
// ingestion body — fields, plus relationships keyed by the relationship name
// declared on the entity to the ids of the target records it points at. The
// relationships are omitted when the record has none.
type ingestRecord struct {
	Fields        map[string]string   `json:"fields"`
	Relationships map[string][]string `json:"relationships,omitempty"`
}

// parseIngestRecords accepts either a single JSON record or an array of
// records, normalizing both to a slice. Each record is {fields, relationships}
// — field values are strings (the storage layer keeps them as text), and
// relationships are supplied at creation, the only point edges are written.
func parseIngestRecords(raw []byte) ([]ingestRecord, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("input is empty")
	}
	if trimmed[0] == '[' {
		var arr []ingestRecord
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("parsing JSON array of records: %w", err)
		}
		return arr, nil
	}
	var one ingestRecord
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return nil, fmt.Errorf("parsing JSON record: %w", err)
	}
	return []ingestRecord{one}, nil
}

// postRecord POSTs one record to /api/{entity} with the bearer token and
// returns the new record's id. A non-201 is classified through the shared
// HTTP-status taxonomy.
func postRecord(cmd *cobra.Command, server, entity, token string, rec ingestRecord) (string, error) {
	body, err := json.Marshal(rec)
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
