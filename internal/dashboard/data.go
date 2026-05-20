package dashboard

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/bensyverson/kura/internal/identity"
	"github.com/bensyverson/kura/internal/manifest"
)

// dataListLimit bounds how many records one page of an entity list shows.
const dataListLimit = 50

// dataIndexView is the data browser's landing page: every entity the
// manifest declares, each a card linking into its record list.
type dataIndexView struct {
	Entities []dataEntitySummary
}

// dataEntitySummary is one entity on the index — its name, description,
// field count, and a link to browse it.
type dataEntitySummary struct {
	Name        string
	Description string
	FieldCount  int
	RelCount    int
	Href        string
}

// dataListView is one entity's record list: the columns (manifest fields,
// in order), the masked record rows, the entity's relationships rendered as
// links, and pagination.
type dataListView struct {
	Entity        string
	Description   string
	Columns       []string
	Records       []dataRecordRow
	Relationships []dataRelLink
	HasPrev       bool
	HasNext       bool
	PrevURL       string
	NextURL       string
}

// dataRecordRow is one record in a list: its id (linked to the detail page)
// and its cell values in column order.
type dataRecordRow struct {
	ID    string
	Href  string
	Cells []string
}

// dataRelLink is one relationship rendered as a link to the target
// entity's browser — "follow relationships" without a join key, since the
// manifest declares none.
type dataRelLink struct {
	Name   string
	Kind   string
	Target string
	Href   string
}

// dataRecordView is a single record's detail: each field with its masked
// value and PII category (if any), plus the entity's relationships.
type dataRecordView struct {
	Entity        string
	ID            string
	Fields        []dataFieldDetail
	Relationships []dataRelLink
}

// dataFieldDetail is one field on the record detail: its name, its masked
// value, and the PII category it carries (empty if not personally
// identifying).
type dataFieldDetail struct {
	Name  string
	Value string
	PII   string
}

// handleDataIndex renders the data browser landing page: the entity list,
// straight from the manifest. An auth problem lands on sign-in; an
// unreachable remote on the error page.
func (s *Server) handleDataIndex(w http.ResponseWriter, r *http.Request) {
	principal, err := s.api.whoami(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/data", err)
		return
	}
	m, err := s.api.manifest(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/data", err)
		return
	}
	view := buildDataIndex(m)
	s.render(w, http.StatusOK, "data_index", pageData{
		Title:     "Data browser",
		Nav:       navFor("/data"),
		Principal: &principal,
		DataIndex: &view,
	})
}

// handleDataList renders one entity's record list. The entity must be in
// the manifest — an unknown one is a clean 404, so the browser stays
// bounded by the schema. Records arrive already masked from the gate; this
// only arranges them into columns.
func (s *Server) handleDataList(w http.ResponseWriter, r *http.Request) {
	entity := r.PathValue("entity")
	principal, err := s.api.whoami(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/data", err)
		return
	}
	m, err := s.api.manifest(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/data", err)
		return
	}
	ent, ok := m.Entity(entity)
	if !ok {
		s.renderNotFound(w, &principal, "No such entity", "This entity is not declared in your schema manifest.")
		return
	}

	offset := parseOffset(r.URL.Query().Get("offset"))
	records, err := s.api.listRecords(r.Context(), entity, dataListLimit, offset)
	if err != nil {
		s.renderAuthOrError(w, "/data", err)
		return
	}

	view := buildDataList(ent, records, offset)
	s.render(w, http.StatusOK, "data_list", pageData{
		Title:     ent.Name,
		Nav:       navFor("/data"),
		Principal: &principal,
		DataList:  &view,
	})
}

// handleDataRecord renders a single record's detail. Like the list, the
// entity must be in the manifest, and the record arrives masked.
func (s *Server) handleDataRecord(w http.ResponseWriter, r *http.Request) {
	entity := r.PathValue("entity")
	id := r.PathValue("id")
	principal, err := s.api.whoami(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/data", err)
		return
	}
	m, err := s.api.manifest(r.Context())
	if err != nil {
		s.renderAuthOrError(w, "/data", err)
		return
	}
	ent, ok := m.Entity(entity)
	if !ok {
		s.renderNotFound(w, &principal, "No such entity", "This entity is not declared in your schema manifest.")
		return
	}

	fields, err := s.api.record(r.Context(), entity, id)
	if err != nil {
		if errors.Is(err, ErrRemoteNotFound) {
			s.renderNotFound(w, &principal, "No such record", "No record with that id exists for this entity.")
			return
		}
		s.renderAuthOrError(w, "/data", err)
		return
	}

	view := buildDataRecord(ent, id, fields)
	s.render(w, http.StatusOK, "data_record", pageData{
		Title:      ent.Name + " · " + id,
		Nav:        navFor("/data"),
		Principal:  &principal,
		DataRecord: &view,
	})
}

// renderNotFound renders a 404 through the shared chrome so a missing
// entity or record is a real page, not a bare status line.
func (s *Server) renderNotFound(w http.ResponseWriter, principal *identity.Principal, title, body string) {
	s.render(w, http.StatusNotFound, "notfound", pageData{
		Title:     title,
		Nav:       navFor("/data"),
		Principal: principal,
		Body:      body,
	})
}

// buildDataIndex projects the manifest into the entity index. No
// entity-specific code: it walks whatever entities the manifest declares.
func buildDataIndex(m *manifest.Manifest) dataIndexView {
	view := dataIndexView{Entities: make([]dataEntitySummary, 0, len(m.Entities))}
	for _, e := range m.Entities {
		view.Entities = append(view.Entities, dataEntitySummary{
			Name:        e.Name,
			Description: e.Description,
			FieldCount:  len(e.Fields),
			RelCount:    len(e.Relationships),
			Href:        "/data/" + e.Name,
		})
	}
	return view
}

// buildDataList arranges an entity's records into columns drawn from the
// manifest, in manifest field order, and renders the relationships as links
// to their target entities. It makes no masking or policy decision — the
// records are already masked.
func buildDataList(e *manifest.Entity, records []recordRow, offset int) dataListView {
	columns := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		columns[i] = f.Name
	}

	rows := make([]dataRecordRow, len(records))
	for i, rec := range records {
		cells := make([]string, len(columns))
		for j, col := range columns {
			cells[j] = rec.Fields[col]
		}
		rows[i] = dataRecordRow{
			ID:    rec.ID,
			Href:  "/data/" + e.Name + "/" + rec.ID,
			Cells: cells,
		}
	}

	view := dataListView{
		Entity:        e.Name,
		Description:   e.Description,
		Columns:       columns,
		Records:       rows,
		Relationships: relLinks(e),
	}
	if offset > 0 {
		prev := max(offset-dataListLimit, 0)
		view.HasPrev = true
		view.PrevURL = dataPageHref(e.Name, prev)
	}
	// A full page implies there may be more; offer a next link. The list
	// endpoint does not report a total, so this is the honest signal.
	if len(records) == dataListLimit {
		view.HasNext = true
		view.NextURL = dataPageHref(e.Name, offset+dataListLimit)
	}
	return view
}

// buildDataRecord pairs each manifest field with its masked value and PII
// category, in manifest order, and renders the relationships as links.
func buildDataRecord(e *manifest.Entity, id string, fields map[string]string) dataRecordView {
	details := make([]dataFieldDetail, 0, len(e.Fields))
	for _, f := range e.Fields {
		var category string
		if f.PII != nil {
			category = string(*f.PII)
		}
		details = append(details, dataFieldDetail{
			Name:  f.Name,
			Value: fields[f.Name],
			PII:   category,
		})
	}
	return dataRecordView{
		Entity:        e.Name,
		ID:            id,
		Fields:        details,
		Relationships: relLinks(e),
	}
}

// relLinks renders an entity's relationships as links to the target
// entity's browser. The manifest declares no join key, so the browser
// follows a relationship to the related entity's list rather than a
// filtered sub-query — a sanity-check tool, not a CRM.
func relLinks(e *manifest.Entity) []dataRelLink {
	links := make([]dataRelLink, 0, len(e.Relationships))
	for _, rel := range e.Relationships {
		links = append(links, dataRelLink{
			Name:   rel.Name,
			Kind:   string(rel.Kind),
			Target: rel.Target,
			Href:   "/data/" + rel.Target,
		})
	}
	return links
}

// dataPageHref builds an entity-list URL at the given page offset.
func dataPageHref(entity string, offset int) string {
	if offset <= 0 {
		return "/data/" + entity
	}
	return "/data/" + entity + "?offset=" + strconv.Itoa(offset)
}
