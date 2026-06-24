---
title: CLI data verbs — query, show & edges
weight: 6
---

`kura query`, `kura show`, and `kura edges` are the CLI's window onto the records the server stores. They are manifest-driven: the entity name is just an argument, and the verbs work for any entity the manifest declares — there is no per-entity wiring in the CLI.

All three are **remote-only**. They GET the server's masked data routes (`GET /api/{entity}`, `GET /api/{entity}/{id}`, `GET /api/{entity}/{id}/edges`) over the cached bearer token; access-time masking and page bounds are the server's job, never the CLI's.

## The verbs

```sh
kura query <entity> [--limit N] [--offset M]
kura show  <entity> <id>
kura edges <entity> <id> --direction out|in
```

## Bounded by default

`kura query` is bounded by the gate, not by the CLI:

- No `--limit` → server applies `gate.DefaultPageSize` (50 today).
- `--limit N` ≤ `gate.MaxPageSize` (200 today) → server honors it.
- `--limit N` > `MaxPageSize` → server silently caps at `MaxPageSize`.
- Negative `--offset` → server floors at zero.

The response echoes the **effective** `limit` and `offset` back, so an agent can see what bound the gate actually applied rather than what was asked for. The Markdown view prints them inline; the `--json` view exposes the same numeric fields.

This is deliberate: the CLI does not try to fight the gate's bounds. There is no `--all` flag, no recursive page-walking helper. An agent that needs more than `MaxPageSize` records pages by repeatedly bumping `--offset`.

## Masked by the server, surfaced unchanged

Every field value the CLI prints has already been masked per the caller's policy by the server. The CLI never:

- replaces masked values with plaintext,
- adds masking on top (the server is the source of truth),
- or filters records out of a page.

If the agent's policy hides every field on an entity, `kura show` prints an explicit "no fields visible" line rather than an empty record — the empty state is informative, not silent.

## Edges: relationships, not traversal

`kura edges` lists a record's relationship [edges](../../concepts/schema-manifest/#how-relationships-are-persisted). The `--direction` is **required** — a caller asks for one view of a record's connections explicitly, never an implied default:

- `--direction out` — the record's own outgoing relationships (the edges it declared at creation).
- `--direction in` — the incoming edges that point at the record, ordered by the source record's [sequence](../../concepts/database/#record-ordering-a-shared-sequence) (deterministic, clock-skew-immune).

Each edge is a relationship name and the source and target record ids, plus the source record's `seq`. Crucially, **edges carry ids, not field values** — `kura edges` exposes *which* records are connected, not the related records' contents. So Kura surfaces relationships without **traversing** them:

- `kura show <entity> <id>` returns the single record's fields, flat.
- `kura edges <entity> <id> --direction …` returns the ids it connects to; there is no tree-of-records shape, no implicit FK following, no joined view.
- To read a connected record, follow up with a second `kura show <target-entity> <target-id>`.

The stance is that Kura is the access and storage layer; clients orchestrate. Kura authorizes, masks, audits, paginates, and tells you how records are connected; the caller composes the shape it wants. Relationships are supplied at record creation (`kura ingest` with a `relationships` block) and read back as edges — standalone post-creation edge mutation rides with the future update path.

## Output and errors

Both verbs follow the shared contract from [CLI output & errors](../cli-output):

- `--json` emits the stable schema (a `{records, limit, offset}` page for query; `{entity, id, fields}` for show; an `{edges: [...]}` list for edges). Markdown is the default.
- `KindUsage` (exit 2) when the positional shape is wrong (no entity, `show`/`edges` missing the id, or `edges` with a missing or invalid `--direction`).
- `KindNotFound` (exit 4) when `kura show` asks for an id the server does not have.
- `KindAuth` (exit 3) on 401/403; `KindTransient` (exit 6) on 5xx; everything else falls through `classifyHTTPStatus` to `KindInternal`.
