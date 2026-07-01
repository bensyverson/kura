---
title: The HTTP API server
weight: 11
---

`kura serve` runs the remote HTTP API — **Kura's only public surface**. It
is a thin adapter over the core: routing, middleware, and lifecycle here;
every policy decision, audit write, and masking rule delegated to the
[enforcement gate](gate).

It is *just* a JSON API. No HTML, no dashboard pages — the
[dashboard](../) is a separate local adapter. A remote attacker sees the
JSON API and the OAuth callback, nothing more.

## The lifecycle and routing tree

- **Routing** on the stdlib `net/http.ServeMux` — its method-and-path
  patterns (`GET /healthz`) cover Kura's needs, so no router dependency is
  taken.
- **Health endpoints.** `GET /healthz` and `GET /readyz` are open: a load
  balancer must reach them without a credential.
- **OAuth endpoints.** `GET /oauth/login` and `GET /oauth/callback` are
  open too — they are how a caller *acquires* a credential. See below.
- **Auth before business logic.** Everything under `/api/` is wrapped in
  `requireAuth`, which resolves the request's bearer token to a Cedar
  principal *before* any handler runs. A request with no token, or a
  malformed or expired one, is rejected with `401`, and the failed
  authentication is recorded — a rejected credential is an audit-worthy
  event. A resolved principal is carried to the handler on the request
  context.
- **The gate boundary.** Every data route under `/api/` is a
  `gatedHandler` — a handler whose only job is to delegate to
  [`Gate.Access`](gate) and serialize the masked result. A data route is
  not registered with a free-form `http.HandlerFunc`; it is registered
  through `registerData`, which supplies a *binding*: a function that
  describes the gate request and the underlying read, and is handed no
  `ResponseWriter` of its own. The binding cannot return a response that
  skipped the gate, because it never gets to write a response at all. The
  data-route map is typed so that *only* a gated handler can be stored in
  it — a raw handler does not satisfy the `gatedRoute` interface — and an
  architectural test asserts the invariant a second time.
- **Structured request logging** to stderr — one line per request with
  method, path, status, duration, and client IP. Request telemetry is
  operational output, never mixed into a response body.
- **Real client IP on every audit event.** A middleware reads the
  forwarded client IP once at the request boundary and carries it on the
  request context, so every audit event the gate writes while serving the
  request — authentication, authorization, access — is stamped with the
  IP the request actually came from.
- **Graceful shutdown.** `SIGINT` / `SIGTERM` drains in-flight requests
  within a bounded timeout, then exits cleanly.

## Data endpoints: generated from the manifest

The data routes are not hand-written per entity — they are **generated
from the [schema manifest](schema-manifest)**. For every entity the
manifest declares, the server registers one route pair:

| Route | Verb | Through the gate |
| --- | --- | --- |
| `GET /api/{entity}/{id}` | get one record | `Gate.Access` (the `read` action) |
| `GET /api/{entity}` | list a page of records | `Gate.List` (the `list` action) |
| `POST /api/{entity}` | ingest one record | `Gate.Ingest` (the `create` action) |

A client adds an entity to its manifest and the API grows the matching
routes with no per-entity code. With an empty manifest no data routes
exist at all — exactly right for a server that has no schema yet.

- **The POST route is the write half**, covered in full by
  [Record ingestion](ingestion): it authorizes the `create`, validates the
  body against the manifest, scans for PII, encrypts content fields by
  default (everything but the structural types), and persists — the
  symmetric counterpart to the masked read. `kura ingest` is the bulk-import
  CLI over it.

- **Every response is masked** by the gate, per the requesting
  principal's policy. The server never sees unmasked data: the binding
  describes the read, the gate performs it and redacts the result. A get
  for a record that does not exist is a `404`; a denied request is a
  `403`.
- **A read carries its erased fields.** A record with a crypto-shredded
  field reads back normally — never an error. The get response is
  `{"fields": {…}, "erased": [names…]}`, and each record in a list page
  carries the same `erased` list; a shredded field is **absent from
  `fields` and named in `erased`**, so a client can tell a field that was
  erased (its key destroyed by design) apart from one that was never set,
  and never sees the ciphertext. `erased` is elided when empty, so an
  ordinary record reads as just its fields. This is distinct from a
  genuine decrypt failure — tampered ciphertext or a wrong KEK — which
  stays a hard `500`, never a silent erased read.
- **List endpoints are bounded by default.** `GET /api/{entity}` accepts
  optional `limit` and `offset` query parameters. The gate clamps the
  page — a missing limit becomes the **default page size of 50**, and a
  limit above the **ceiling of 200** is capped — so a list endpoint can
  never dump an unbounded result set. The response body carries the
  records alongside the effective `limit` and `offset`, so a client can
  page without guessing. A malformed pagination parameter is a `400`.
- **The records come from a `RecordStore`** — the storage seam in the
  `data` package (see the [database layer](database)). The bindings read
  through it; it knows nothing about authorization or masking. The
  in-memory `MemStore` and the Postgres-backed `PostgresStore` satisfy
  the same interface, so the server is indifferent to which one it has.

## Admin endpoints: users, roles, and policy

Beyond the manifest's data, the server exposes a small administrative
surface — the authorized-user list, role assignments, and read access to
the effective policy. These are not manifest entities, so they do not go
through `Gate.Access`/`List`; they go through **`Gate.Admin`**, which
runs the same chain without the data steps. They are gated routes all
the same — authorized and audited by construction.

| Route | Through the gate | Who |
| --- | --- | --- |
| `POST /api/users` | `AdminManage` | admin |
| `GET /api/users` | `AdminReview` | admin or auditor |
| `POST /api/users/{email}/roles` | `AdminManage` | admin |
| `DELETE /api/users/{email}/roles` | `AdminManage` | admin |
| `GET /api/users/mismatches` | `AdminReview` | admin or auditor |
| `GET /api/policy` | `AdminReview` | admin or auditor |
| `GET /api/overview` | `AdminReview` | admin or auditor |
| `GET /api/manifest` | `AdminReview` | admin or auditor |
| `POST /api/reviews` | `AdminManage` | admin |
| `GET /api/reviews` | `AdminReview` | admin or auditor |
| `GET /api/reviews/{id}` | `AdminReview` | admin or auditor |
| `POST /api/reviews/{id}/decisions` | `AdminManage` | admin |
| `POST /api/reviews/{id}/complete` | `AdminManage` | admin |
| `POST /api/erase` | `AdminErase` | admin |
| `GET /api/whoami` | (auth only) | any authenticated principal |

- **Mutations are the admin role's alone**; the reads — the authorized
  list, the effective policy, the IdP mismatches — are access-review
  work the read-only auditor may also do.
- **Role assignment and revocation are variadic and atomic**: a request
  carries a set of role names, and the store applies the whole set or
  none of it. Adding a user to the list and granting them roles are
  *distinct* operations — a role op on a user not on the list is a `404`.
- **`/api/erase` crypto-shreds records.** It takes a JSON body of
  `record_ids` and runs through **`Gate.Erase`** — authorized against the
  `AdminErase` capability (admin only) and audited, one event per record.
  Erasure destroys the per-value keys, never the rows, so it is compatible
  with append-only entities and reaches the deny-delete immutable backup;
  it names records by id and knows nothing of any domain entity. The `kura
  erase` verb is its remote-first client, and requires `--confirm`. The
  full mechanism is described in [storage](storage).
- **`/api/policy` is read-only.** The effective policy is rendered from
  the [Cedar IR](policy); there is no write method on the route, because
  policy authoring stays a repo/PR activity, not a server endpoint.
- **`/api/whoami` is the self-identity read.** It returns the principal
  `requireAuth` resolved for the bearer token — type, id, email, tenant
  — and nothing else. No additional gate decision is needed: reading
  your own identity is implicit in being authenticated, and the auth
  event the recorder writes already covers it. `kura whoami` is the
  CLI client.
- **`/api/overview` is the dashboard's landscape briefing in one read.**
  It composes — without making any new decision — the record and user
  counts (per-entity and total), the most recent audit events, and the
  needs-attention panel: live IdP mismatches today, with deployment tier
  and audit-anomaly fields present as stable placeholders until those
  subsystems land (the same forward-compatible shape `kura status` uses).
  It is the [local dashboard](dashboard)'s overview page; there is no CLI
  client, because the CLI's `kura status` already answers the same orienting
  questions.
- **IdP mismatches** — a suspended or absent account in the configured
  identity provider that still holds Kura roles — are surfaced by
  `GET /api/users/mismatches`, which cross-checks the authorized list
  against the vendor [Directory client](identity) (Google Workspace
  Admin SDK, Microsoft Graph, or a no-op for generic OIDC, picked by
  `KURA_IDP`).
- **`/api/reviews` runs the periodic access review.** `POST /api/reviews`
  snapshots the current authorized list into a new open review (an admin
  action); `POST /api/reviews/{id}/decisions` records an approve/remove
  verdict per subject; `POST /api/reviews/{id}/complete` archives the review
  as an immutable artifact. The reads (`GET /api/reviews` and `…/{id}`) are
  `AdminReview`, so the auditor may inspect past reviews. The store is a
  dedicated subsystem ([`internal/review`](dashboard)), not a projection
  over the audit log — a completed review is a first-class, retrievable
  record.
- **`/api/manifest` exposes the schema.** It returns the
  [schema manifest](schema-manifest) verbatim — entities, fields (with
  their PII categories), and relationships — the one input that drives the
  data routes, the policy IR, and the dashboard's data browser. It carries
  schema only, never a record or a field value, so there is nothing for the
  gate to mask; it is an `AdminReview` read so the schema (including which
  fields carry which PII) is authorized and audited like the other reviews.

## Sign-in: the loopback OAuth/OIDC handoff

The token a request carries is minted by `kura serve` after the
consultant authenticates against whichever IdP the deployment is
configured for. The flow is a **loopback handoff** — chosen over the
OAuth device flow because the consultant runs `kura` from a workstation
with a browser, it is the smoothest UX there, and it matches the
precedent set by Google's own Workspace CLI.

The protocol is **family-agnostic**. The four IdP families Kura supports
(Google, Microsoft Entra, generic OIDC, plus the test fake) plug in
behind a single `IdentityProvider` seam — the piece that runs the code
exchange and verifies the id_token. The loopback handoff above this
seam looks the same for every family:

1. `kura login` binds a temporary `127.0.0.1` listener, generates a
   `state`, and opens the browser to `GET /oauth/login?redirect=<loopback>`.
   The server refuses any `redirect` that is not a loopback address — a
   token redirect to an arbitrary host would be a token leak.
2. `/oauth/login` stores the loopback target under a fresh server-side
   `state` and redirects the browser to the configured IdP.
3. The consultant authenticates with the IdP against the firm (or
   client) tenant. The IdP redirects back to `/oauth/callback`.
4. `/oauth/callback` — the **only** point that mints a token — exchanges
   the code for a verified identity through the configured
   `IdentityProvider`, maps the resulting `(email, tenant)` to a Cedar
   principal via [TenantTrust](identity), issues a short-lived HMAC
   token, records the authentication, and redirects the browser to the
   CLI's loopback URL with the token attached.
5. The CLI's loopback listener verifies the round-tripped `state`, catches
   the token, and caches it under the user's config directory.

State is single-use and TTL-bounded on both legs.

### Per-IdP verification details

Each `IdentityProvider` implementation owns its own verification — the
shape that arrives at step 4 is always a `VerifiedIdentity{Email,
Tenant, Issuer}`, but how each field is produced differs:

- **Google.** Code exchange via `golang.org/x/oauth2`; id_token
  verified by `google.golang.org/api/idtoken` (RS256 against Google's
  rotating JWKS). `Tenant` comes from the `hd` (hosted-domain) claim;
  an id_token without `hd` or with `email_verified=false` is rejected
  outright — a Kura principal must come from a verified Workspace
  identity, never a bare Gmail account.
- **Microsoft Entra.** OIDC discovery against
  `https://login.microsoftonline.com/<tenant>/v2.0` at startup; tokens
  verified by `coreos/go-oidc` against the cached JWKS. `Tenant` comes
  from the `tid` claim (the actual signing tenant). For `tenant=common`
  the issuer field is a template, so per-token issuer-equality is
  skipped — the trust decision belongs to `TenantTrust` on `tid`. A
  token without `tid` is rejected.
- **Generic OIDC.** Discovery against the configured issuer URL at
  startup; tokens verified by `coreos/go-oidc`. `Tenant` is the
  **issuer URL itself** — OIDC core has no tenant claim — so two
  Keycloak realms or two Auth0 tenants are two Kura tenants. As with
  Google, `email_verified=false` is rejected.

The pieces *outside* the seam — `TenantTrust`, the token model, the
audit log, the gate — never see which family signed the request; they
see only the verified identity.

## Startup configuration: stores and manifest

`kura serve` reads its backings from the environment, so the same binary
runs the credential-less dev/bare path and a real Postgres-backed
deployment:

| Variable | Effect |
| --- | --- |
| `KURA_DATABASE_URL` | When set (TLS required), records and the authorized-user list are read/written through the Postgres-backed `PostgresStore`/`PostgresUserStore`, and pending [migrations](database) run against the database at startup. When unset, both stay in the in-memory `MemStore`/`MemUserStore` — existing behavior. |
| `KURA_DB_TENANT_ID` | The tenant id the Postgres stores scope their row-level security to. Required when `KURA_DATABASE_URL` is set. |
| `FIELD_ENCRYPTION_KEY` | The **active** master KEK the record store wraps per-value DEKs under (base64-encoded 32-byte AES-256 key). Sourced through the [secrets manager](secrets) under its canonical secret name — from Doppler in production, from this process environment on the dev/bare path — never read into the data path directly. Required when `KURA_DATABASE_URL` is set. |
| `KURA_KEK_VERSION` | The generation number the active `FIELD_ENCRYPTION_KEY` belongs to, stamped onto every wrapped DEK written. Defaults to `1`; you raise it by one for each KEK rotation. Non-sensitive config, read from the environment (not the secrets manager). |
| `FIELD_ENCRYPTION_KEY_RETIRING` / `KURA_KEK_RETIRING_VERSION` | The **outgoing** KEK and its generation number, set only *during* a rotation. Loaded alongside the active key so the server can still open rows not yet re-wrapped; the retiring version must be below `KURA_KEK_VERSION`. Both are set together, and both are removed once the rotation drains. Unset outside a rotation. |
| `KURA_DOPPLER_TOKEN` / `KURA_DOPPLER_PROJECT` / `KURA_DOPPLER_CONFIG` | When a Doppler service token is set, every secret (`FIELD_ENCRYPTION_KEY` included) is read from [Doppler](secrets) over its HTTPS API rather than the process environment; the project and config address the store and are then required. The token is injected at runtime by the deployment, never baked in. Unset, secrets resolve from the process environment — the dev/bare path. |
| `KURA_ADMIN_DATABASE_URL` | The elevated migrator/owner DSN (TLS required; the `kura_admin` role). Schema migrations and append-only reconciliation run on this connection at startup — never the runtime `kura_api` connection — so the runtime role cannot own schema objects or write the append-only set. Required when `KURA_DATABASE_URL` is set. See [Database](database#two-connections-two-credentials). |
| `KURA_DO_SPACES_ENDPOINT` | DO Spaces (S3-compatible) host without scheme, e.g. `nyc3.digitaloceanspaces.com`. Setting it turns on the `backup`/`restore` [job kinds](../machine-interface/cli-backup-restore); unset, they stay unregistered and `POST /api/jobs` for them answers a clear 400. The five variables below become required once it is set. |
| `KURA_DO_SPACES_REGION` | Spaces region slug, e.g. `nyc3`. Required once Spaces is configured. |
| `KURA_DO_SPACES_ACCESS_KEY` / `KURA_DO_SPACES_SECRET_KEY` | Credentials for the backups bucket's credential domain. The runtime opens the bucket [append-only](storage). Required once Spaces is configured. |
| `KURA_DO_SPACES_BACKUPS_BUCKET` | The concrete name the IaC provisioned for the backups bucket this deployment writes to. Required once Spaces is configured. |
| `KURA_BACKUP_ENCRYPTION_KEY` | High-entropy secret the backup dump is encrypted under (AES-256-GCM), **distinct from** `FIELD_ENCRYPTION_KEY` by design. Required once Spaces is configured; backups also require `KURA_DATABASE_URL` (there must be a database to dump). |
| `KURA_MANIFEST_PATH` | Path to the [schema manifest](schema-manifest) file. When set, the gate enforces against it and the API grows a data route per entity; an invalid manifest fails startup loudly. When unset, the gate runs on an empty manifest and generates no data routes. |
| `KURA_DIRECTORY` | Set to `none` to disable IdP-mismatch detection: the [Directory client](identity) becomes a no-op that reports every account active and never dials out, so `GET /api/users/mismatches` and the overview's needs-attention panel return no mismatches. For a deployment without directory-API access, and for the offline [local dev instance](../getting-started/local-development). When unset, the directory is the one paired with `KURA_IDP`. |

The production source of the database connection, secrets, and manifest is
the deployment repo and its secrets backend; the environment variables are
the dev stand-in for that wiring.

## Caveat: the rest of `kura serve` is still mid-build

The endpoints above are the v1 surface. The audit log still uses the
in-memory backing — a v1 placeholder that will land as its own build-plan
task. The IdP-mismatch endpoint is *real* on Google and Microsoft now; on
generic OIDC it answers consistently empty (see [Identity](identity) for
the why).

## Conventions

- **Paths over queries.** A resource is `/api/people/89`, not
  `/api/people?id=89`. Query parameters are reserved for pagination
  (`limit`, `offset`), search, sort, and filter.
- **TLS terminates in front.** Caddy terminates TLS and proxies to the
  server on loopback (`kura serve` defaults to binding `127.0.0.1:8080`),
  so the server itself never needs a public-facing socket. It trusts the
  forwarded `X-Forwarded-For` client IP for audit logging.
