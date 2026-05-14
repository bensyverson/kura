-- Migration 0004: the authorized-user list and role assignments.
--
-- kura.users is the authorized list — one row per email allowed to hold
-- a principal in this deployment. kura.role_assignments records which
-- roles each holds; a user with no assignment rows is on the list but
-- has no access. Roles are stored as free text, matching the cedar
-- policy IR's role names, so this static schema never changes when a
-- deployment edits its role set.
--
-- Both tables are tenant-scoped and RLS-bound from creation, exactly
-- like the record tables — see migration 0002 for the fail-closed
-- rationale. The kura_api / kura_admin / kura_audit privileges from
-- migration 0003 reach these tables through the schema's default
-- privileges, so no GRANT is repeated here.

CREATE TABLE kura.users (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL,
    email      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE TABLE kura.role_assignments (
    user_id    uuid NOT NULL REFERENCES kura.users (id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL,
    role       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role)
);

CREATE INDEX users_tenant_idx ON kura.users (tenant_id);
CREATE INDEX role_assignments_tenant_idx ON kura.role_assignments (tenant_id);

ALTER TABLE kura.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_isolation ON kura.users
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);

ALTER TABLE kura.role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.role_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY role_assignments_tenant_isolation ON kura.role_assignments
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);
