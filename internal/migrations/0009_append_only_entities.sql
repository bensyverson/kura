-- Migration 0009: append-only entities — insert-only enforcement at the
-- database layer.
--
-- An entity the manifest marks append_only stores insert-only records: they
-- may be created but never updated or deleted. This is enforced mechanically
-- here, below the application, so it holds even against a direct kura_api
-- connection — the runtime role the API server uses.
--
-- The protected set is data, not schema: kura.append_only_entities holds one
-- row per (tenant, entity) that is frozen. A BEFORE UPDATE OR DELETE trigger
-- on both record tables consults the set and raises if the row's entity is
-- in it. A trigger is chosen over a second RLS policy because it fails loud
-- and specific (a named error a caller can match) and composes with the
-- existing forced tenant-isolation RLS rather than competing with it.
--
-- Credential separation is the keystone. The set table and the guard
-- function are owned by kura_admin (the migrator/owner role), and kura_api
-- is granted NOTHING on the set — otherwise the runtime role could empty the
-- set and unfreeze an entity, self-bypassing the control. The guard function
-- is SECURITY DEFINER so it reads the set with the owner's rights even though
-- the invoking runtime role cannot. The ALTER ... OWNER statements make that
-- ownership deterministic regardless of which login role runs the migration
-- (kura_admin in production, the cluster superuser in the test harness).
--
-- Why the function reads the set reliably under the set table's forced RLS:
-- a record can only be mutated on a connection whose kura.tenant_id GUC
-- equals the record's tenant (kura.records itself is forced-RLS, migration
-- 0002), and the trigger fires inside that same transaction, so the GUC the
-- set's policy keys on is exactly the row's tenant.

CREATE TABLE kura.append_only_entities (
    tenant_id  uuid NOT NULL,
    entity     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, entity)
);

ALTER TABLE kura.append_only_entities OWNER TO kura_admin;

-- The runtime role gets no access to the set. Migration 0003's default
-- privileges would otherwise have granted kura_api DML on this new table;
-- revoke it explicitly so the runtime role cannot read, let alone change,
-- what is frozen.
REVOKE ALL ON kura.append_only_entities FROM kura_api;

-- Tenant isolation, like every other application table (migration 0002's
-- fail-closed rationale). current_setting(..., true) yields NULL when the
-- GUC is unset, and `= NULL` is never true, so a connection that never sets
-- the GUC sees nothing.
ALTER TABLE kura.append_only_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE kura.append_only_entities FORCE ROW LEVEL SECURITY;
CREATE POLICY append_only_entities_tenant_isolation ON kura.append_only_entities
    USING (tenant_id = current_setting('kura.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('kura.tenant_id', true)::uuid);

-- The guard. On UPDATE or DELETE of a record (or one of its field values),
-- resolve the row's tenant and entity and reject the mutation if that entity
-- is frozen. For kura.records the discriminator is on the row itself; for
-- kura.record_field_values it is on the parent record, reached by id.
CREATE FUNCTION kura.reject_append_only_mutation()
    RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = kura, pg_temp
AS $$
DECLARE
    target_tenant uuid;
    target_entity text;
BEGIN
    IF TG_TABLE_NAME = 'records' THEN
        target_tenant := OLD.tenant_id;
        target_entity := OLD.entity;
    ELSE
        SELECT r.tenant_id, r.entity
          INTO target_tenant, target_entity
          FROM kura.records r
         WHERE r.id = OLD.record_id;
    END IF;

    IF EXISTS (
        SELECT 1 FROM kura.append_only_entities
         WHERE tenant_id = target_tenant AND entity = target_entity
    ) THEN
        RAISE EXCEPTION 'kura: entity "%" is append-only; % is not permitted',
            target_entity, TG_OP
            USING ERRCODE = 'check_violation';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

ALTER FUNCTION kura.reject_append_only_mutation() OWNER TO kura_admin;

CREATE TRIGGER records_append_only_guard
    BEFORE UPDATE OR DELETE ON kura.records
    FOR EACH ROW EXECUTE FUNCTION kura.reject_append_only_mutation();

CREATE TRIGGER record_field_values_append_only_guard
    BEFORE UPDATE OR DELETE ON kura.record_field_values
    FOR EACH ROW EXECUTE FUNCTION kura.reject_append_only_mutation();
