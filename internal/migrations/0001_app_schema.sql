-- Migration 0001: the pgcrypto extension and the Kura application schema.
--
-- pgcrypto supplies the field-level encryption primitives
-- (pgp_sym_encrypt / pgp_sym_decrypt). pgaudit is intentionally NOT created
-- here: pgaudit only functions when it is present in the server's
-- shared_preload_libraries, which is a deployment-time concern a migration
-- cannot force. internal/db.VerifyExtensions reports its availability.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS kura;

-- records: one row per stored record. Manifest-agnostic by design — entity
-- is a free-text discriminator, so this static schema never has to change
-- when a client's manifest does.
CREATE TABLE kura.records (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL,
    entity     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- record_field_values: one row per (record, field). A non-sensitive scalar
-- lands in value_text; a free-text or high-sensitivity value is
-- pgcrypto-encrypted into value_encrypted and value_text stays NULL.
CREATE TABLE kura.record_field_values (
    record_id       uuid NOT NULL REFERENCES kura.records (id) ON DELETE CASCADE,
    tenant_id       uuid NOT NULL,
    field_name      text NOT NULL,
    field_type      text NOT NULL,
    value_text      text,
    value_encrypted bytea,
    PRIMARY KEY (record_id, field_name),
    CONSTRAINT exactly_one_value CHECK (
        (value_text IS NULL) <> (value_encrypted IS NULL)
    )
);

-- pii_spans: detected-PII metadata produced at ingestion by the PII layer.
-- The span coordinates are byte positions into the source text; the text
-- itself never lives here.
CREATE TABLE kura.pii_spans (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    record_id   uuid NOT NULL REFERENCES kura.records (id) ON DELETE CASCADE,
    tenant_id   uuid NOT NULL,
    field_name  text NOT NULL,
    category    text NOT NULL,
    byte_offset integer NOT NULL,
    byte_length integer NOT NULL,
    confidence  real NOT NULL
);

CREATE INDEX records_tenant_entity_idx ON kura.records (tenant_id, entity);
CREATE INDEX record_field_values_tenant_idx ON kura.record_field_values (tenant_id);
CREATE INDEX pii_spans_record_idx ON kura.pii_spans (record_id);
