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
- **Structured request logging** to stderr — one line per request with
  method, path, status, duration, and client IP. Request telemetry is
  operational output, never mixed into a response body.
- **Graceful shutdown.** `SIGINT` / `SIGTERM` drains in-flight requests
  within a bounded timeout, then exits cleanly.

## Sign-in: the loopback OAuth handoff

The token a request carries is minted by `kura serve` after a Google
sign-in. The flow is a **loopback handoff** — chosen over the OAuth device
flow because the consultant runs `kura` from a workstation with a browser,
it is the smoothest UX there, and it matches the precedent set by Google's
own Workspace CLI:

1. `kura login` binds a temporary `127.0.0.1` listener, generates a
   `state`, and opens the browser to `GET /oauth/login?redirect=<loopback>`.
   The server refuses any `redirect` that is not a loopback address — a
   token redirect to an arbitrary host would be a token leak.
2. `/oauth/login` stores the loopback target under a fresh server-side
   `state` and redirects the browser to Google.
3. The consultant authenticates with Google against the firm (or client)
   Workspace domain. Google redirects back to `/oauth/callback`.
4. `/oauth/callback` — the **only** point that mints a token — exchanges
   the code for a verified identity, maps the `hd` hosted-domain claim to
   a Cedar principal via [domain trust](identity), issues a short-lived
   HMAC token, records the authentication, and redirects the browser to
   the CLI's loopback URL with the token attached.
5. The CLI's loopback listener verifies the round-tripped `state`, catches
   the token, and caches it under the user's config directory.

State is single-use and TTL-bounded on both legs. The Google code
exchange and id_token verification go through `golang.org/x/oauth2` and
`google.golang.org/api/idtoken` — verifying RS256 against Google's
rotating keys is not something to hand-roll on a security boundary.

## Conventions

- **Paths over queries.** A resource is `/api/people/89`, not
  `/api/people?id=89`. Query parameters are reserved for search, sort, and
  filter.
- **TLS terminates in front.** Caddy terminates TLS and proxies to the
  server on loopback (`kura serve` defaults to binding `127.0.0.1:8080`),
  so the server itself never needs a public-facing socket. It trusts the
  forwarded `X-Forwarded-For` client IP for audit logging.
