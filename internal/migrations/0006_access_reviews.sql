-- Migration 0006: the access-review artifacts.
--
-- kura.access_reviews is the durable record of every periodic access
-- review — a point-in-time attestation that the right people hold the
-- right access. kura.access_review_items is the per-subject snapshot and
-- the reviewer's decision (approve or remove). A completed review is an
-- immutable artifact: the application never updates a row whose review has
-- status='completed'.
--
-- The id is application-generated text (a 128-bit hex string), matching
-- the jobs ledger's id scheme, so the review subsystem owns its ids the
-- same way and they stay stable and lexically sortable.
--
-- Like every other application table in this schema, both are
-- tenant-scoped and RLS-bound from creation (see migration 0002 for the
-- fail-closed rationale); the kura_api / kura_admin / kura_audit grants
-- from migration 0003 reach them through the schema's default privileges.

CREATE TABLE kura.access_reviews (
    id           text PRIMARY KEY,
    tenant_id    uuid NOT NULL,
    started_by   text NOT NULL,
    status       text NOT NULL CHECK (status IN ('open','completed')),
    started_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE TABLE kura.access_review_items (
    review_id  text NOT NULL REFERENCES kura.access_reviews (id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL,
    email      text NOT NULL,
    roles      jsonb NOT NULL DEFAULT '[]'::jsonb,
    decision   text NOT NULL CHECK (decision IN ('pending','approved','removed')),
    note       text NOT NULL DEFAULT '',
    PRIMARY KEY (review_id, email)
);

CREATE INDEX access_reviews_tenant_idx       ON kura.access_reviews (tenant_id, started_at DESC);
CREATE INDEX access_review_items_tenant_idx  ON kura.access_review_items (tenant_id);

ALTER TABLE kura.access_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.access_reviews FORCE ROW LEVEL SECURITY;
CREATE POLICY access_reviews_tenant_isolation ON kura.access_reviews
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);

ALTER TABLE kura.access_review_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.access_review_items FORCE ROW LEVEL SECURITY;
CREATE POLICY access_review_items_tenant_isolation ON kura.access_review_items
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);
