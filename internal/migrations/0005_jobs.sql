-- Migration 0005: the async-jobs ledger.
--
-- kura.jobs is the durable record of every long-running operation
-- submitted through the API: backups, restores, provisioning steps.
-- The ledger has two properties the rest of Kura relies on:
--
--   * idempotency on (tenant_id, actor, kind, idempotency_key): a
--     caller that lost its job id can re-submit with the same key and
--     pick up the existing job. This is what makes a retry safe.
--
--   * persistence across process restarts: a worker that crashed
--     mid-job is detected at startup (status='running' with no
--     finished_at), and its row is flipped back to 'pending' so the
--     next worker can claim it exactly once.
--
-- Like every other application table in this schema, kura.jobs is
-- tenant-scoped and RLS-bound from creation; the kura_api / kura_admin
-- / kura_audit grants from migration 0003 reach it through the schema's
-- default privileges.

CREATE TABLE kura.jobs (
    id               text PRIMARY KEY,
    tenant_id        uuid NOT NULL,
    kind             text NOT NULL,
    status           text NOT NULL CHECK (status IN ('pending','running','succeeded','failed')),
    actor            text NOT NULL,
    idempotency_key  text NOT NULL,
    params           jsonb NOT NULL DEFAULT '{}'::jsonb,
    result           jsonb,
    error            text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    started_at       timestamptz,
    finished_at      timestamptz,
    UNIQUE (tenant_id, actor, kind, idempotency_key)
);

CREATE INDEX jobs_tenant_idx        ON kura.jobs (tenant_id);
CREATE INDEX jobs_actor_created_idx ON kura.jobs (tenant_id, actor, created_at DESC);
-- Partial index for the worker's "next pending job" claim; pending rows
-- are the hot set, terminal rows are not interesting to the claim path.
CREATE INDEX jobs_pending_idx       ON kura.jobs (tenant_id, created_at) WHERE status = 'pending';

ALTER TABLE kura.jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY jobs_tenant_isolation ON kura.jobs
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);
