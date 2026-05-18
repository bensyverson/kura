---
title: Tenant trust configuration
weight: 5
---

`kura serve` decides whether a verified sign-in belongs to a
**Consultant**, a **User**, or an **Admin** by matching the IdP's
verified tenant against a per-deployment trust list. The trust list
lives in three environment variables:

| Variable                | What it does                                                  |
| ----------------------- | ------------------------------------------------------------- |
| `KURA_FIRM_DOMAIN`      | The one tenant the firm's consultants sign in from. Matches → `Consultant`. |
| `KURA_CLIENT_DOMAINS`   | Comma-separated client tenants. Matches → `User`.             |
| `KURA_ADMIN_EMAILS`     | Comma-separated client-tenant emails granted `Admin` instead of `User`. |

The variable names still say "domain," but the **value** is the
**verified tenant key** the IdP family produces:

| IdP family | Tenant key the IdP exposes        | What you put in the trust vars                          |
| ---------- | ---------------------------------- | ------------------------------------------------------- |
| Google     | the `hd` claim — a DNS domain     | the firm's and clients' Workspace domains               |
| Microsoft  | the `tid` claim — an Entra GUID   | the firm's and clients' **tenant IDs** (or `common`)    |
| OIDC       | none — Kura uses the issuer URL  | the firm's and clients' **issuer URLs**                  |

This matters because a typo here is silent: a value that does not
match any verified tenant simply yields no principal — the sign-in
fails with a "denied" audit event, no error in the operator's
terminal.

## Recipe: Google Workspace

```sh
KURA_IDP=google
KURA_FIRM_DOMAIN=examplefirm.com
KURA_CLIENT_DOMAINS=acme.example,otherclient.example
KURA_ADMIN_EMAILS=boss@acme.example,owner@otherclient.example
```

`alex@examplefirm.com` → `Consultant`. `user@acme.example` → `User`.
`boss@acme.example` → `Admin`. Anyone else → no principal, denied.

## Recipe: Microsoft Entra

The trust key is the **Directory (tenant) ID** GUID, not a domain.
For a multi-tenant Entra app, use the literal string `common` in the
client trust list to accept any Entra tenant — but only do this if
the policy truly accepts unknown tenants; usually you want to enumerate.

```sh
KURA_IDP=microsoft
KURA_MICROSOFT_TENANT_ID=common
KURA_FIRM_DOMAIN=11111111-1111-1111-1111-111111111111
KURA_CLIENT_DOMAINS=22222222-2222-2222-2222-222222222222,33333333-3333-3333-3333-333333333333
KURA_ADMIN_EMAILS=boss@acme.example
```

Note that **admin emails are still emails**, not GUIDs — the admin
allowlist matches the user's `preferred_username`/`email` claim, not
their tenant.

## Recipe: Generic OIDC (Zitadel, Keycloak, Okta, Auth0)

The trust key is the **issuer URL**. For Keycloak, that includes the
realm path; for Zitadel, it is the instance root; for Okta and Auth0,
it is the per-org URL.

```sh
KURA_IDP=oidc
KURA_OIDC_ISSUER_URL=http://localhost:8085/realms/kura
KURA_FIRM_DOMAIN=http://localhost:8085/realms/kura
KURA_CLIENT_DOMAINS=https://acme.okta.com,https://otherclient.auth0.com/
KURA_ADMIN_EMAILS=boss@acme.com
```

Two things to watch for:

- **Trailing slashes matter.** The OIDC verifier strict-compares the
  `iss` claim to the configured issuer URL. Auth0 issues with a
  trailing slash (`https://tenant.auth0.com/`); Okta does not. Use
  whatever the IdP's discovery document shows for `issuer`.
- **A Keycloak realm change changes the tenant.** Moving the
  deployment to a different realm changes the issuer URL — update
  `KURA_FIRM_DOMAIN`/`KURA_CLIENT_DOMAINS` to match, or sign-ins from
  the new realm will silently land as no-principal denials.

## What if the firm is on a different IdP family than the clients?

`kura serve` runs **one** IdP family at a time — `KURA_IDP` picks
exactly one. A deployment whose firm is on Google Workspace and whose
clients are on Microsoft Entra cannot trust both from the same
`kura serve` process today.

This is a deliberate v1 scope choice: cross-family trust would
duplicate the verifier, the discovery, and the trust mapping across
the OAuth callback. If your deployment needs it, file an issue —
multi-family trust is on the radar for a later phase.
