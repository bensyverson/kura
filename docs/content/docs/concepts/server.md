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

## What the skeleton provides

The server skeleton (build-plan Phase 2, first task) stands up the
lifecycle and the routing tree the later endpoint tasks fill in:

- **Routing** on the stdlib `net/http.ServeMux` — its method-and-path
  patterns (`GET /healthz`) cover Kura's needs, so no router dependency is
  taken.
- **Health endpoints.** `GET /healthz` and `GET /readyz` are open: a load
  balancer must reach them without a credential.
- **Auth before business logic.** Everything under `/api/` is wrapped in
  the auth gate. An unauthenticated request to any data route is rejected
  with `401` *before* it reaches a handler. The skeleton checks only that
  a credential is present; resolving it to a Cedar principal is the next
  task.
- **Structured request logging** to stderr — one line per request with
  method, path, status, duration, and client IP. Request telemetry is
  operational output, never mixed into a response body.
- **Graceful shutdown.** `SIGINT` / `SIGTERM` drains in-flight requests
  within a bounded timeout, then exits cleanly.

## Conventions

- **Paths over queries.** A resource is `/api/people/89`, not
  `/api/people?id=89`. Query parameters are reserved for search, sort, and
  filter.
- **TLS terminates in front.** Caddy terminates TLS and proxies to the
  server on loopback (`kura serve` defaults to binding `127.0.0.1:8080`),
  so the server itself never needs a public-facing socket. It trusts the
  forwarded `X-Forwarded-For` client IP for audit logging.
