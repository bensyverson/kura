---
title: The local dashboard
weight: 12
---

`kura dashboard` runs a **local** web app — bound to loopback on the
admin's own machine — that is itself an HTTP client of the remote
[API server](server), exactly like the CLI. It is the human face of Kura:
an overview, user & role management, the quarterly access review, a
masked PII data browser, an audit-log viewer, and a Cedar policy viewer.

It is a thin presentation adapter. It makes **no** policy, audit, or
masking decision — every byte it renders is fetched from the remote API,
which enforces all of that. There is no database seam in the dashboard at
all.

## The overview page

The landing page (`/`) is the **overview**: the state of the store at a
glance. It renders system status, the deployment tier, record and user
counts (a total plus a per-entity breakdown), the recent-audit tail, and a
**needs-attention** panel. The whole page is one server-side read of
[`GET /api/overview`](server) (plus `GET /api/whoami` for the signed-in
identity in the top bar).

The needs-attention panel is where attention — and vermilion (朱), the one
alert color — is earned. It surfaces **IdP mismatches**: an authorized user
whose identity-provider account is suspended or absent while they still
hold roles. Audit-anomaly detection, the deployment tier, and access-review
tracking arrive in later phases; their fields are present now as stable
placeholders so the page's shape does not change when their values become
real (the same forward-compatible contract `kura status` uses).

## The users & roles page

`/users` is where the client's admins manage **who is authorized and what
each person can do**. It reads the authorized list
([`GET /api/users`](server)), the effective policy
([`GET /api/policy`](server)), and the IdP mismatches
([`GET /api/users/mismatches`](server)) — all server-side — and joins them
into one view:

- **the authorized list**, each user shown with the roles they hold;
- **role management** — assign a defined role, revoke a held one, add a new
  email to the list, or *deactivate* a user (strip every role at once);
- **effective access per user** — the policy projected to that user's roles
  (`cedar.Policy.ForRoles`), shown as the entities, actions, and visible
  PII categories their roles actually grant;
- **IdP mismatches**, flagged inline in vermilion when an authorized user's
  identity-provider account no longer matches their access.

The dividing line is deliberate: **role *assignment* is data** you edit
here, but **policy *authoring* is not**. There is no free-form policy
editor — the roles and the permissions they carry are defined in your
deployment's policy and changed through a reviewed pull request. This page
only assigns existing roles to people.

### How mutations work (and stay safe)

Reads aside, this is the first page that *changes* state. It does so the
boring, robust way: plain HTML `<form>`s POST to the local dashboard, which
makes the matching authenticated call to the remote API and then issues a
**redirect back** (POST-redirect-GET), so a refresh never re-submits.
Success and failure surface as a short banner; only fixed status *codes*
cross the redirect, never remote error text, so nothing attacker-influenced
is reflected into the page.

Because the dashboard listens on a known local port, a malicious web page
the admin happens to visit could try to POST to it — the loopback `Host`
check does **not** stop that (the browser sends *our* host, not the
attacker's). So every state-changing request must additionally prove it
came from the dashboard itself: its `Origin` (or, failing that, `Referer`)
must be loopback. A cross-site or origin-less POST is refused with `403`
before it ever reaches the remote API.

## The policy page (Cedar structured viewer)

`/policy` is a **read-only** view of the authorization policy your
deployment enforces. It reads the policy IR — the same intermediate
representation [Cedar](policy) compiles to policy text — from
[`GET /api/policy`](server) and renders it two ways for human review:

- a **grid per entity**: rows are roles, columns are the five actions
  (read, list, create, update, delete), each cell marking allowed or not,
  with a column for the PII categories that role sees in plaintext on a
  read or list;
- **plain-language statements**, one per role-with-access on each entity
  (e.g. *"admin can read, delete patient; reads reveal private_person"*),
  so a non-technical reviewer can read the policy as prose.

This is V1 of the Cedar UI and a deliberate baby-step toward a future
structured *editor*: it reads the exact IR that editor will edit, so
nothing here is throwaway. There is **no free-form editor** — authoring
Cedar stays a reviewed pull request, outside the constrained IR.

## The audit-log viewer

`/audit` is the human counterpart to [`kura log`](../machine-interface/cli-audit):
a filtered, paginated view over the append-only audit log. It reads
[`GET /api/audit`](server) server-side and renders one page of events at a
time, **newest first**.

The filter form forwards the same axes the gate's `audit.Filter` exposes —
**actor**, **resource** (the entity; named "resource" to match the
`kura log --resource` flag), **action**, and an inclusive **since** /
exclusive **until** RFC 3339 time window. Filtering is the remote gate's
query, not a local sieve; the dashboard only forwards the axes and renders
what comes back. A malformed time bound is caught before any request is made
and surfaced as a banner, so a typo becomes a correction prompt rather than
a `502`.

Pagination is a presentation concern: the dashboard slices the filtered
result into pages of 50 and renders **Newer**/**Older** links that carry the
active filter forward, so paging never drops it. Every event carries
identifiers only — actor, action, resource id, outcome, time, IP — never a
field value, by the shape of the audit `Event` type. Reading the log is
itself an audited `AdminReview` event, so a non-admin/auditor gets the
sign-in or permission path, never the data.

## Why it runs locally

A remote web app drags XSS, CSRF, session, and template attack surface
onto the public internet. The dashboard renders client PII (the data
browser), so an XSS in a *remote* dashboard would be an XSS *inside the
security boundary*, in an authenticated admin's session — the worst
single vulnerability this system could have. Running locally puts that
entire surface on one user's localhost, never a shared host, and lets
`kura serve` stay [a JSON API and nothing more](server).

The audience is tiny (1–3 admins per client) and already holds the `kura`
binary, so local distribution is acceptable. There is no mobile target.

## How it talks to the API (backend-for-frontend)

The dashboard renders **server-side**: each route handler fetches from
the remote API in Go, then renders HTML with `html/template`. The browser
receives HTML, never raw API JSON, and **never holds the bearer token** —
the cached `kura login` token is read per request and attached
server-side. This is the backend-for-frontend model:

- the browser talks only to `127.0.0.1`;
- the remote stays CORS-free and API-only;
- raw API data and the token never reach browser-reachable code.

The token is read from the cache per request, so a fresh `kura login` is
picked up without restarting the dashboard. No cached credential (or a
`401` from the remote) renders a sign-in prompt rather than an error.

## Running it

```bash
kura dashboard --server https://kura.client.example
# or, after `kura login`, the cached server is used:
kura dashboard
```

It binds `127.0.0.1:7878` by default (`--addr` to change) and opens your
browser (`--no-browser` to suppress). A request bearing a non-loopback
`Host` is refused — the first defense against a remote page reaching the
local server (DNS-rebinding / CSRF).

## Front-end conventions

Server-side rendered, **zero dependencies** — vanilla HTML/CSS/JS and Web
Components, system fonts, no inline styles, responsive, light/dark via
`prefers-color-scheme`. JavaScript only *enhances* server-rendered markup
(progressive enhancement); it never produces primary content, fetches
data, or holds the token. Logical pages are real routes; query strings
are reserved for search, sort, and pagination within a page.

The visual design system lives in `internal/dashboard/DESIGN.md` (the
[design.md](https://github.com/google-labs-code/design.md) token format)
— the source of truth every dashboard page follows.
