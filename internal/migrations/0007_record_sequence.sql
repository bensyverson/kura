-- Migration 0007: a monotonic ordering sequence on every record.
--
-- Records gain a bigint `seq` drawn from one shared Postgres sequence at
-- INSERT — a deterministic, clock-skew-immune order key for "events for a
-- subject, ordered" (substrate Item F). It applies to ALL records, not just
-- append-only entities: ordering is a cheap (~8 bytes/row), generally useful
-- property, and gating it on a domain flag would add conditional complexity
-- for no real saving.
--
-- created_at is kept for wall-clock meaning but is NOT the order key: now()
-- is transaction-start time, so it ties within a transaction and is subject
-- to clock skew.
--
-- The sequence orders events *within* a subject; it is NOT a safe global
-- progress cursor. A value is assigned at INSERT but only becomes visible at
-- COMMIT, and transactions can commit out of order — so a reader using
-- `seq > N` across the whole stream can skip an event that committed late.
-- The supported projection model is replay-from-scratch per subject.

CREATE SEQUENCE kura.record_seq;

ALTER TABLE kura.records
    ADD COLUMN seq bigint NOT NULL DEFAULT nextval('kura.record_seq');

-- Tie the sequence's lifecycle to the column it backs.
ALTER SEQUENCE kura.record_seq OWNED BY kura.records.seq;

-- Grant explicitly rather than leaning on default privileges, which depend
-- on which role created the sequence: kura_api must be able to draw the next
-- value on every INSERT (fail-closed over implicit inheritance).
GRANT USAGE, SELECT ON SEQUENCE kura.record_seq TO kura_api;
GRANT ALL PRIVILEGES ON SEQUENCE kura.record_seq TO kura_admin;
