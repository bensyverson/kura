-- Migration 0003: per-component database roles, minimum privilege.
--
-- Three roles, one per component, mirroring 03-for-agents.md's database
-- layer: kura_api (the running API server), kura_admin (schema
-- provisioning), kura_audit (the tech owner's read-only audit access).
--
-- Roles are created NOLOGIN and without passwords — a password in a
-- committed migration would be a baked-in secret. The IaC layer runs
-- ALTER ROLE ... LOGIN PASSWORD with a value from the secrets manager when
-- it provisions a deployment. The initial extension/role bootstrap is run
-- by the platform's provisioning superuser (e.g. DigitalOcean's doadmin);
-- kura_admin owns ongoing schema migrations within the kura schema.
--
-- None of these roles has BYPASSRLS — the tenant-isolation policies from
-- migration 0002 bind all three.

DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kura_api') THEN
        CREATE ROLE kura_api NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kura_admin') THEN
        CREATE ROLE kura_admin NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kura_audit') THEN
        CREATE ROLE kura_audit NOLOGIN;
    END IF;
END $$;

-- kura_api: read/write the application data, and nothing else. Scoped to
-- the kura schema; no DDL, no role management, no other schema.
GRANT USAGE ON SCHEMA kura TO kura_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA kura TO kura_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA kura TO kura_api;

-- kura_admin: schema provisioning. Owns schema evolution — full rights
-- within the kura schema, including DDL — but is not a superuser and stays
-- RLS-bound.
GRANT USAGE, CREATE ON SCHEMA kura TO kura_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA kura TO kura_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA kura TO kura_admin;

-- kura_audit: read-only. The tech owner's break-glass audit view — can
-- SELECT, can change nothing.
GRANT USAGE ON SCHEMA kura TO kura_audit;
GRANT SELECT ON ALL TABLES IN SCHEMA kura TO kura_audit;

-- Future tables in the kura schema inherit the same grants, so a later
-- migration cannot silently create a table no role can reach — or one the
-- read-only auditor can write.
ALTER DEFAULT PRIVILEGES IN SCHEMA kura
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kura_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA kura
    GRANT USAGE, SELECT ON SEQUENCES TO kura_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA kura
    GRANT ALL PRIVILEGES ON TABLES TO kura_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA kura
    GRANT ALL PRIVILEGES ON SEQUENCES TO kura_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA kura
    GRANT SELECT ON TABLES TO kura_audit;
