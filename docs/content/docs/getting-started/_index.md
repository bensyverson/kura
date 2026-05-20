---
title: Getting started
weight: 2
---

Install Kura and stand up a deployment — from the `kura` binary to a
running, audited data store.

## Pick an identity provider

Kura is **IdP-agnostic**: the same trust model, token model, and audit
log run on top of three concrete identity providers, picked by the
`KURA_IDP` environment variable. Start with the one your firm — and the
client deployment you are standing up for — already uses.

- **[Google Workspace sign-in](google-sign-in)** — for firms and
  clients on Google Workspace. Covers OAuth client registration,
  `KURA_GOOGLE_*` env vars, and the Workspace-domain-as-tenant model.
- **[Microsoft Entra sign-in](microsoft-sign-in)** — for firms and
  clients on Microsoft 365 / Entra (Azure AD). Covers app
  registration, `KURA_MICROSOFT_*` env vars, and the Entra-tenant-ID
  trust model.
- **[Generic OIDC sign-in](generic-oidc-sign-in)** — for any
  standards-compliant OpenID Connect provider (Okta, Auth0, Keycloak,
  Zitadel, …). Covers issuer-as-tenant, the `email_verified`
  requirement, and end-to-end recipes for Keycloak and Zitadel.

## After sign-in: directory and trust

Two cross-IdP concerns share one shape across all three families:

- **[Tenant trust](tenant-trust)** — the per-deployment mapping from
  IdP tenant → Cedar principal (`Consultant` / `User` / `Admin`).
- **Directory clients for IdP-mismatch detection.** Each IdP family
  pairs its sign-in with an optional directory client that powers
  `GET /api/users/mismatches`:
  - **[Google Workspace directory](google-workspace-directory)** —
    service-account + domain-wide delegation, read-only scope.
  - **[Microsoft Entra directory](microsoft-entra-directory)** —
    app-only Graph access, `User.Read.All` application permission.
  - **Generic OIDC** — there is no portable directory API; Kura wires
    a no-op directory and recommends compensating IdP-side controls
    (short token lifetimes, IdP-side revocation, prompt removal from
    the Kura authorized-user list). Documented in
    [Generic OIDC sign-in](generic-oidc-sign-in#known-limitation-no-idp-mismatch-detection).

## Run it locally

Before any of that, you can stand up a complete, populated Kura on your
own machine — Postgres, the API, seeded data, and the dashboard — with one
command, no IdP or model service required. See
**[Local development](local-development)**.

*Coming soon.* The end-to-end deployment guide (TLS termination,
secrets injection, the `kura init` per-client scaffold) lands as
Phases 6 and 7 of the build plan.
