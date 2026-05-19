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
