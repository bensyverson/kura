-- Migration 0008: relationship edges between records.
--
-- kura.record_edges persists the manifest's declared relationships as typed
-- edges: one row per (source record, relationship, target record). Both
-- endpoints are real foreign keys into kura.records, so an edge can never
-- dangle — the structural referential integrity that EAV field-values in
-- record_field_values could not provide, and the reason relationships live
-- here rather than there.
--
-- There is NO cardinality column. Whether a relationship is `one` or `many`
-- is a manifest property, enforced at the gate; storing it here would
-- duplicate the source of truth and could drift from it.
--
-- Endpoint ids are plaintext, indexable uuids — relationship references are
-- never encrypted. "All edges pointing at X, ordered" is served by querying
-- target_record_id and ordering by the source record's seq via a join to
-- kura.records (migration 0007).
--
-- Like every other application table, it is tenant-scoped and RLS-bound from
-- creation (migration 0002's fail-closed rationale), and reaches the
-- component roles through the schema's default privileges (migration 0003).

CREATE TABLE kura.record_edges (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL,
    source_record_id uuid NOT NULL REFERENCES kura.records (id) ON DELETE CASCADE,
    target_record_id uuid NOT NULL REFERENCES kura.records (id) ON DELETE CASCADE,
    relationship     text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- "Edges pointing at X" (filtered by relationship) and "edges from X".
CREATE INDEX record_edges_target_idx ON kura.record_edges (tenant_id, target_record_id, relationship);
CREATE INDEX record_edges_source_idx ON kura.record_edges (tenant_id, source_record_id);

ALTER TABLE kura.record_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.record_edges FORCE ROW LEVEL SECURITY;
CREATE POLICY record_edges_tenant_isolation ON kura.record_edges
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);
