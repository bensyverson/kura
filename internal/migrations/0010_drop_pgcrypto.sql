-- Migration 0010: drop the pgcrypto extension.
--
-- Field-level encryption has moved from in-database pgcrypto
-- (pgp_sym_encrypt / pgp_sym_decrypt) to the application layer: per ADR 0002
-- the per-value DEKs live in a physically separate, erasable key store,
-- unreachable from a SQL expression in this database, so encryption and
-- decryption now run in Go (internal/crypto, AES-256-GCM). The ciphertext
-- still lands in kura.record_field_values.value_encrypted; only the producer
-- of those bytes moved out of Postgres. The framing in migration 0001's
-- header ("pgcrypto supplies the field-level encryption primitives") is
-- therefore historical — migrations are forward-only, so this migration, not
-- an edit to 0001, records the change.
--
-- pgcrypto's only consumers were pgp_sym_encrypt / pgp_sym_decrypt, both now
-- removed. gen_random_uuid(), used for the UUID primary-key defaults in
-- migrations 0001/0004/0008, has been a core Postgres built-in since PG13
-- (Kura runs PG18), so those defaults bind to the core function and do not
-- depend on the extension. The drop therefore has no dependent objects.

DROP EXTENSION IF EXISTS pgcrypto;
