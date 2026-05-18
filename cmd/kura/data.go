package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/bensyverson/kura/internal/clio"
	"github.com/spf13/cobra"
)

// newQueryCmd builds `kura query <entity>`: a bounded, masked page of an
// entity's records, generic across whatever the schema manifest defines.
// The verb is a thin presenter over the gate's list endpoint — the
// gate clamps the page (DefaultPageSize=50, MaxPageSize=200) and masks
// every record per the caller's policy. The CLI never tries to bypass
// either bound: --limit > MaxPageSize is silently capped on the server
// and the effective limit comes back in the response, so an agent can
// see what it actually got rather than what it asked for.
//
// Kura does not traverse relationships. Each call returns one entity's
// page; if a caller wants related records they make a second call. See
// `docs/content/docs/machine-interface/cli-data.md`.
func newQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query <entity>",
		Short: "List records of an entity (bounded, masked)",
		Long: `List records of an entity, bounded and masked.

The server's gate clamps Limit into [1, MaxPageSize=200], with no Limit
meaning DefaultPageSize=50, and floors Offset at zero. The response
echoes the effective Limit and Offset back, so an agent can see what
the gate actually applied.

PII masking is access-time: every field returned has already been
masked per the caller's policy by the server. The CLI is a presenter
over the wire response — it does not mask, unmask, or filter further.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return clio.UsageError("query", "exactly one entity name is required")
			}
			entity := args[0]
			limit, _ := cmd.Flags().GetInt("limit")
			offset, _ := cmd.Flags().GetInt("offset")
			server, err := resolveServerFromFlags(cmd, "query")
			if err != nil {
				return err
			}
			page, err := fetchEntityPage(cmd, server, entity, limit, offset)
			if err != nil {
				return err
			}
			return renderEntityPage(cmd, entity, page)
		},
	}
	cmd.Flags().Int("limit", 0, "page size (0 = server default; capped server-side at MaxPageSize)")
	cmd.Flags().Int("offset", 0, "page offset (floored at zero by the server)")
	return cmd
}

// newShowCmd builds `kura show <entity> <id>`: a single record, masked
// per the caller's policy by the server. Flat shape — no relationship
// traversal, by design (Kura does not own data shape; clients
// orchestrate multi-entity fetches with second calls if they need them).
func newShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <entity> <id>",
		Short: "Show a single record by id (masked)",
		Long: `Show a single record by id, masked per the caller's policy.

The output is the record's field values, exactly as the server's gate
masked them — the CLI does not transform, unmask, or follow
relationships. Use a second ` + "`kura query`" + ` or ` + "`kura show`" + ` call to
fetch related records.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return clio.UsageError("show", "exactly one entity name and one id are required")
			}
			entity, id := args[0], args[1]
			server, err := resolveServerFromFlags(cmd, "show")
			if err != nil {
				return err
			}
			fields, err := fetchEntityRecord(cmd, server, entity, id)
			if err != nil {
				return err
			}
			return renderEntityRecord(cmd, entity, id, fields)
		},
	}
}

// entityPage is the CLI's view of `GET /api/{entity}`: the masked
// records on the page plus the effective Limit and Offset the gate
// actually applied. The agent reads Limit/Offset to know what bounds
// it actually got, which can differ from the request when clamping
// kicked in.
type entityPage struct {
	Records []entityRecord `json:"records"`
	Limit   int            `json:"limit"`
	Offset  int            `json:"offset"`
}

// entityRecord is one record in an entityPage: id plus masked fields.
type entityRecord struct {
	ID     string            `json:"id"`
	Fields map[string]string `json:"fields"`
}

// fetchEntityPage GETs /api/{entity} with the cached bearer token and
// optional limit/offset query parameters. A non-2xx is classified
// through the shared HTTP-status mapper so the taxonomy is uniform
// across verbs.
func fetchEntityPage(cmd *cobra.Command, server, entity string, limit, offset int) (entityPage, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return entityPage{}, err
	}
	_, token, err := cache.load()
	if err != nil {
		return entityPage{}, err
	}
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	target := strings.TrimRight(server, "/") + "/api/" + url.PathEscape(entity)
	if encoded := q.Encode(); encoded != "" {
		target += "?" + encoded
	}
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, target, nil)
	if err != nil {
		return entityPage{}, clio.InternalError("query", "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return entityPage{}, clio.TransientError("query", "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return entityPage{}, classifyHTTPStatus("query", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var page entityPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return entityPage{}, clio.InternalError("query", "decoding server response: %w", err)
	}
	return page, nil
}

// fetchEntityRecord GETs /api/{entity}/{id}, returning the record's
// masked field values. The server's response is just the fields map —
// the id is in the URL, not the body.
func fetchEntityRecord(cmd *cobra.Command, server, entity, id string) (map[string]string, error) {
	cache, err := defaultTokenCache()
	if err != nil {
		return nil, err
	}
	_, token, err := cache.load()
	if err != nil {
		return nil, err
	}
	target := strings.TrimRight(server, "/") + "/api/" + url.PathEscape(entity) + "/" + url.PathEscape(id)
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, target, nil)
	if err != nil {
		return nil, clio.InternalError("show", "building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, clio.TransientError("show", "%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, classifyHTTPStatus("show", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var fields map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&fields); err != nil {
		return nil, clio.InternalError("show", "decoding server response: %w", err)
	}
	return fields, nil
}

// renderEntityPage writes the page to stdout — JSON for machines,
// dense Markdown for humans. Field iteration is sorted so the output is
// deterministic across runs.
func renderEntityPage(cmd *cobra.Command, entity string, page entityPage) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	return clio.Render(cmd.OutOrStdout(), format, page, func(w io.Writer) error {
		fmt.Fprintf(w, "# kura query %s\n\n", entity)
		fmt.Fprintf(w, "_limit=%d, offset=%d, returned=%d_\n\n", page.Limit, page.Offset, len(page.Records))
		if len(page.Records) == 0 {
			fmt.Fprintf(w, "no records on this page — try a different `--offset`, or check that `%s` is an entity in the manifest.\n", entity)
			return nil
		}
		for _, rec := range page.Records {
			fmt.Fprintf(w, "- **%s** — %s\n", rec.ID, formatFieldsInline(rec.Fields))
		}
		return nil
	})
}

// renderEntityRecord writes a single record to stdout. The shape — id
// then field rows in sorted order — is the same in JSON and Markdown,
// so masking invariance across formats is by construction.
func renderEntityRecord(cmd *cobra.Command, entity, id string, fields map[string]string) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	format := clio.FormatMarkdown
	if useJSON {
		format = clio.FormatJSON
	}
	payload := struct {
		Entity string            `json:"entity"`
		ID     string            `json:"id"`
		Fields map[string]string `json:"fields"`
	}{Entity: entity, ID: id, Fields: fields}
	return clio.Render(cmd.OutOrStdout(), format, payload, func(w io.Writer) error {
		fmt.Fprintf(w, "# %s %s\n\n", entity, id)
		if len(fields) == 0 {
			fmt.Fprintln(w, "no fields visible — your policy may mask every field on this entity")
			return nil
		}
		names := make([]string, 0, len(fields))
		for k := range fields {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(w, "- %s: %s\n", name, fields[name])
		}
		return nil
	})
}

// formatFieldsInline renders a record's fields as a single sorted line
// for the Markdown list view of `kura query`. Sorted so output is
// deterministic; semicolon-separated so a field value containing a
// comma does not look like a field boundary.
func formatFieldsInline(fields map[string]string) string {
	if len(fields) == 0 {
		return "(no visible fields)"
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = name + ": " + fields[name]
	}
	return strings.Join(parts, "; ")
}
