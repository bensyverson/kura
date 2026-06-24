---
title: Schema manifest
weight: 0
---

The **schema manifest** is the keystone of a Kura deployment. One per-client manifest
file declares the client's entities, the relationships between them, and which fields
carry which PII categories — and that one file drives four surfaces: the dashboard's
data browser, the CLI's `query` / `show` verbs, the MCP data tools, and the Cedar
policy IR.

Because every surface is generated from the manifest, standing up a new engagement's
usability layer collapses to "write the manifest." None of the four surfaces contains
entity-specific code.

## Format

The manifest is a single **JSON** file. JSON keeps the format dependency-free
(`encoding/json` is in the Go standard library) — a deliberate choice for a security
product, where every dependency is audit and supply-chain surface. Documentation that
would otherwise live in comments lives in first-class `description` fields, which are
structured and feed the other surfaces.

```json
{
  "version": "1",
  "entities": [ ... ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `version` | yes | Manifest format version. Currently `"1"`. |
| `entities` | yes | The kinds of record the client stores. At least one. |

## Entities

```json
{
  "name": "customer",
  "description": "A person or organization whose data the client holds.",
  "fields": [ ... ],
  "relationships": [ ... ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Unique entity name. |
| `description` | no | Human- and agent-readable summary. |
| `fields` | yes | The entity's attributes. At least one. |
| `relationships` | no | Typed edges to other entities. |

## Fields

```json
{ "name": "email", "type": "string", "description": "Primary contact email.", "pii": "private_email" }
```

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Field name, unique within the entity. |
| `type` | yes | One of the recognized field types below. |
| `description` | no | Human- and agent-readable summary. |
| `pii` | no | A PII category. Omit for non-identifying fields. |

### Field types

| Type | Meaning |
|---|---|
| `string` | A short, structured string. |
| `text` | **Free-text.** Assumed to contain PII: PII-scanned at ingestion and encrypted at rest. |
| `integer` | A whole number. |
| `boolean` | True / false. |
| `timestamp` | A point in time. |

### PII categories

A field's `pii` tag is a **category** — the same vocabulary the PII detection layer
produces and the Cedar policy IR gates on. v1 recognizes eight categories, mirroring
the OpenAI Privacy Filter's detection vocabulary:

`account_number`, `private_address`, `private_email`, `private_person`,
`private_phone`, `private_url`, `private_date`, `secret`.

`account_number` and `secret` are **high-sensitivity**: they warrant field-level
encryption, not just category-based masking. High-sensitivity is a property Kura
assigns over the category set in code — it is not declared per field.

An unrecognized `pii` value fails validation.

## Relationships

```json
{ "name": "orders", "kind": "many", "target": "order", "description": "Orders placed by this customer." }
```

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Relationship name, unique within the entity. |
| `kind` | yes | `one` or `many` — the cardinality of the target. |
| `target` | yes | The name of the entity this relationship points to. Must resolve. |
| `description` | no | Human- and agent-readable summary. |

### How relationships are persisted

A declared relationship becomes a typed **edge** between records, stored in
`kura.record_edges` (see [Database](../database/#relationships-typed-edges)).
Relationships are supplied **at record creation**, in the same request as the
record's fields, and the edge is written in the same transaction as the
record — they commit together or not at all. Standalone post-creation
add/remove of an edge is a mutation, and Kura has no update path yet, so it is
deferred to that future work.

Each edge is validated **at the gate** on ingest, instance by instance:

- the relationship must be one the entity declares;
- every target must be an existing record **of the declared `target` entity**
  (a target that is missing, or is some other entity, is rejected);
- **cardinality holds** — a `one` relationship accepts at most one target; a
  `many` relationship accepts several.

A record is created with relationships by sending `{fields, relationships}`,
where `relationships` maps a relationship name to its target record ids. A
`one` relationship takes a single id; a `many` relationship takes a list:

```json
{
  "fields": { "total_cents": "4200" },
  "relationships": {
    "customer": ["cust-7"],
    "line_items": ["item-1", "item-2", "item-3"]
  }
}
```

Here `customer` is a `one` relationship (exactly one target) and `line_items`
is a `many` relationship (several). Endpoint ids are stored as plaintext,
indexable uuids — relationship references are never encrypted — so a record's
edges can be read back in either direction with `kura edges <entity> <id>
--direction out|in` (or `GET /api/{entity}/{id}/edges`). Kura does not
*traverse* relationships: an edge read returns ids, not the related records'
fields; fetch a target with a second `kura show`.

## Validation

A manifest that parses but does not validate is never returned — callers always get
either a usable manifest or a specific error. Validation rejects, with a matchable
message:

- a missing `version` or an empty `entities` list;
- an entity with no name, no fields, or a duplicate name;
- a field with no name, a duplicate name, an unrecognized `type`, or an unrecognized
  `pii` category;
- a relationship with no name, a duplicate name, an unrecognized `kind`, an empty
  `target`, or a `target` that does not match any entity (a *dangling* relationship).

## Full example

```json
{
  "version": "1",
  "entities": [
    {
      "name": "customer",
      "description": "A person or organization whose data the client holds.",
      "fields": [
        { "name": "id", "type": "string", "description": "Stable identifier." },
        { "name": "full_name", "type": "string", "description": "Customer's name.", "pii": "private_person" },
        { "name": "email", "type": "string", "description": "Primary contact email.", "pii": "private_email" },
        { "name": "ssn", "type": "string", "description": "Social security number.", "pii": "account_number" },
        { "name": "notes", "type": "text", "description": "Free-text case notes; PII-scanned at ingestion." }
      ],
      "relationships": [
        { "name": "orders", "kind": "many", "target": "order", "description": "Orders placed by this customer." }
      ]
    },
    {
      "name": "order",
      "description": "A single purchase.",
      "fields": [
        { "name": "id", "type": "string", "description": "Stable identifier." },
        { "name": "placed_at", "type": "timestamp", "description": "When the order was placed." },
        { "name": "total_cents", "type": "integer", "description": "Order total, in cents." }
      ],
      "relationships": [
        { "name": "customer", "kind": "one", "target": "customer", "description": "The customer who placed this order." }
      ]
    }
  ]
}
```
