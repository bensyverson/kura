-- Migration 0002: row-level security on every tenant-scoped table.
--
-- Kura ships single-tenant but enforces tenant isolation from day one —
-- RLS is far harder to retrofit than to start with. Every policy keys on
-- the kura.tenant_id GUC. current_setting(..., true) yields NULL when the
-- GUC is unset, and `tenant_id = NULL` is never true, so a connection that
-- never sets the GUC sees nothing: fail closed by construction.
--
-- FORCE ROW LEVEL SECURITY makes the policies bind the table owner too, so
-- a provisioning path that queries as the owner is not silently exempt.
-- None of the component roles in migration 0003 has BYPASSRLS.

ALTER TABLE kura.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.records FORCE ROW LEVEL SECURITY;
CREATE POLICY records_tenant_isolation ON kura.records
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);

ALTER TABLE kura.record_field_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.record_field_values FORCE ROW LEVEL SECURITY;
CREATE POLICY record_field_values_tenant_isolation ON kura.record_field_values
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);

ALTER TABLE kura.pii_spans ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.pii_spans FORCE ROW LEVEL SECURITY;
CREATE POLICY pii_spans_tenant_isolation ON kura.pii_spans
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);
