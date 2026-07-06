-- Keystore migration 0001: the wrapped-DEK table.
--
-- This lineage is applied against the key store — a PHYSICALLY SEPARATE
-- Postgres instance from the main kura database (ADR 0002). The separation
-- is the whole point: the immutable backup pipeline targets the main
-- cluster, never this one, so destroying a wrapped DEK here (crypto-shred)
-- reaches every copy of a value — live, replica, and sealed backup —
-- without the keys ever having been captured by an immutable dump. The key
-- store carries its own erasable backup instead.
--
-- One row per encrypted field value, identified exactly as a
-- kura.record_field_values row is — (tenant_id, record_id, field_name) — so
-- there is a 1:1 map between a ciphertext and its key. wrapped_dek is the
-- per-value DEK sealed under the master KEK; kek_version records which KEK
-- generation wrapped it, so KEK rotation can re-wrap in place and tell done
-- rows from pending ones.

CREATE SCHEMA IF NOT EXISTS kura;

CREATE TABLE kura.wrapped_deks (
    tenant_id   uuid NOT NULL,
    record_id   uuid NOT NULL,
    field_name  text NOT NULL,
    wrapped_dek bytea NOT NULL,
    kek_version integer NOT NULL DEFAULT 1,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, record_id, field_name)
);

-- Shredding deletes every key for a set of records within a tenant; this
-- index keeps that delete (and per-record fetches) an indexed lookup rather
-- than a scan.
CREATE INDEX wrapped_deks_record_idx ON kura.wrapped_deks (tenant_id, record_id);

-- Tenant isolation, mirroring the main schema's migration 0002: every row
-- access keys on the kura.tenant_id GUC, which is NULL when unset so a
-- connection that never sets it sees nothing (fail closed). FORCE binds the
-- table owner too, so no provisioning path is silently exempt.
ALTER TABLE kura.wrapped_deks ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.wrapped_deks FORCE ROW LEVEL SECURITY;
CREATE POLICY wrapped_deks_tenant_isolation ON kura.wrapped_deks
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);
