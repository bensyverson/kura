---
title: Record ingestion
weight: 13
---

Ingestion is how a client's existing data gets **into** Kura. Every
engagement starts with data the client already holds, in a shape unique to
that client — so ingestion has to be a single, generic pathway that works
across differing schemas, not a per-client write path. It is, because the
same three facts that make reads manifest-driven make writes
manifest-driven too:

- the **[schema manifest](schema-manifest) is the per-client schema** —
  each field declares its type and its PII category;
- **storage is schema-agnostic** — records live in an EAV layout
  (`kura.records` + `kura.record_field_values`), so any entity and any
  field set fit without a per-schema table (see the
  [database layer](database));
- every **per-field ingestion decision is read from the manifest** — what
  to validate, what to scan, and what to encrypt.

The result is one ingestion path, parameterized by the manifest, exactly
as the read routes are.

## The write goes through the gate

Writes are enforced by the **[core gate](gate)**, symmetric with reads.
Where a read is `authenticate → authorize → access → mask → audit`, an
ingestion is:

```
authenticate → authorize(create) → validate → PII-scan → classify → write → audit
```

Every step happens, in order, every time. The persistence callback runs
only after authorization, validation, and scanning pass, and only with the
fields the gate classified — so it cannot be a way around the gate, just as
a read Fetcher cannot.

- **Authorize.** The write is a Cedar `create` action on the entity. The
  default policy grants `create` to the `admin` and `user` roles; the
  read-only `auditor` cannot ingest. A denied principal never reaches the
  store.
- **Validate.** Every field in the incoming record must be one the
  manifest declares for the entity. An undeclared field is refused — it
  could never be read back through the gate (no policy reasons about it)
  and would smuggle unscanned data past the schema.
- **PII-scan.** The record is scanned by the self-hosted
  [PII detector](pii). This is the ingestion-time scan; its detected spans
  are persisted as metadata in `kura.pii_spans` (coordinates only — never
  the text).
- **Classify.** Each field's at-rest storage is decided: a value is stored
  **encrypted** when its manifest type is free-text, when the manifest
  declares it a high-sensitivity category (account numbers, secrets), or
  when the ingestion scan detected a high-sensitivity category in it. The
  last rule catches PII landing in a field the schema author did not flag.
  Everything else is stored as plaintext. (This mirrors how the read path
  decides what to decrypt.)
- **Write & audit.** The record, its field values, and its spans are
  persisted in one tenant-scoped transaction, and the create is recorded
  in the [audit log](audit) against the new record's id.

## The surfaces

Ingestion is exposed two ways, both thin adapters over `Gate.Ingest`:

| Surface | Shape |
| --- | --- |
| `POST /api/{entity}` | A manifest-driven route per entity. POST a JSON record; on success it returns `201` with the new id. Unknown entity → `404`; an undeclared field or malformed body → `400`; a denied principal → `403`. |
| `kura ingest <entity>` | The bulk-import CLI. Reads a JSON object or array of objects from a file (`--file`) or stdin and writes each through `POST /api/{entity}`, reporting the new ids. |

Field values are strings — the storage layer keeps field values as text.

## Decision: Kura owns ingestion (a unified, manifest-driven pathway)

Decided with the user (2026-05-19). The question was whether Kura should
own a record-ingestion path at all, or leave the client's own application
to write directly to Postgres.

**Kura owns ingestion.** The deciding requirement: every client needs to
import existing data quickly, and only a Kura-owned write path can
*guarantee* PII scanning and field encryption at the boundary — a client
writing directly to Postgres could not be made to. Because the pathway is
manifest-driven and the storage is EAV, one generic implementation serves
every client's differing schema, so owning ingestion costs no
per-client code. The earlier implicit model (client-writes-directly, with
the read-only `RecordStore` and a `data.go` note deferring writes as "a
separate concern") is superseded by this decision.
