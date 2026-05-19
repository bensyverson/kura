---
title: Generic OIDC sign-in
weight: 4
---

Kura accepts sign-in from **any OpenID Connect provider** that
implements Discovery and JWKS — Zitadel, Keycloak, Okta, Auth0, and
others. The generic-OIDC IdP is one implementation of the same
`IdentityProvider` seam the Google and Microsoft IdPs use — the trust
model, token model, and audit log are identical. Only the IdP-side
setup changes.

This page covers what the abstraction guarantees, what it does not, the
gotchas that bit us when we wired the two reference vendors, and
end-to-end recipes for Zitadel and Keycloak with notes for Okta and
Auth0.

## Issuer-URL-as-tenant

Vanilla OIDC has no tenant claim. The Google IdP gets one from the `hd`
claim and Microsoft Entra from `tid`; generic OIDC has neither.

Kura therefore uses the **issuer URL** as the tenant identifier. The
issuer is what the IdP signs the id_token against, and it is the one
field every OIDC vendor agrees on — so it is the closest universal
proxy for "which tenant signed this token."

The practical consequence: `KURA_FIRM_DOMAIN` and `KURA_CLIENT_DOMAINS`
take the **issuer URL** for the generic-OIDC IdP, not a DNS domain. So
for a Keycloak realm, the firm tenant is something like
`http://localhost:8085/realms/kura`, not `kura.example`. For a Zitadel
instance, it is the root URL of the instance.

This is a tradeoff worth naming:

- **Two Keycloak realms on one host become two tenants.** Different
  realm path → different issuer URL → different Kura tenant. That is
  usually what you want.
- **An OIDC vendor with multiple "tenants" under one issuer URL
  cannot be tenant-distinguished by Kura on the generic-OIDC path.**
  Okta's per-org issuer (`https://<org>.okta.com/oauth2/default`) gives
  you one tenant per org, which is what you want for one-org-per-Kura
  deployments. Auth0's per-tenant issuer
  (`https://<tenant>.auth0.com/`) similarly gives one tenant per
  Auth0 tenant.

If your IdP has a real tenant claim (Google `hd`, Entra `tid`), use the
dedicated IdP for that family — it will give you a richer trust signal
than issuer-as-tenant.

## What `email_verified` must be

Kura **rejects** any id_token whose `email_verified` claim resolves to
false. We require the IdP to have proven the email, not merely
transcribed it.

Some IdPs (notably Zitadel) default to a **minimal id_token + rich
userinfo** layout — the id_token doesn't carry `email_verified` at all
and the relying party is expected to call `/userinfo` for it. Kura
handles this transparently: when the id_token lacks the
`email_verified` claim, Kura calls the OIDC `/userinfo` endpoint
(authenticated with the access_token from the same exchange) and uses
the verified-email assertion from there. No operator toggle is needed.

An **explicit** `email_verified=false` from the id_token is treated as
a definitive negative — Kura does not re-check it via `/userinfo`,
because overriding the IdP's explicit "no" would silently downgrade
its assertion. To resolve an unverified email, fix it at the IdP:

- **Keycloak** — set `emailVerified: true` on the user in the realm,
  or set `verifyEmail: true` on the realm so the flow forces a
  verification step before issuing a token.
- **Zitadel** — mark the user's email as verified in the Console (it
  is *not* verified by default for users created through the admin UI;
  it *is* verified when a user signs themselves up through the
  registration flow).
- **Okta / Auth0** — verified by default for users created through the
  invitation/registration flows; not verified for users created
  directly through admin APIs.

## What you need

- An **OIDC provider** reachable from where `kura serve` runs.
- The provider's **issuer URL** — the base URL whose
  `/.well-known/openid-configuration` returns the discovery document.
- A **confidential client** registered with the provider, with
  `<KURA_PUBLIC_URL>/oauth/callback` as a redirect URI.
- The client's **ClientID** and **ClientSecret** (Kura is a server-side
  relying party, not a public/PKCE-only client).

## Configure `kura serve`

| Variable                 | Value                                              |
| ------------------------ | -------------------------------------------------- |
| `KURA_IDP`               | `oidc`                                             |
| `KURA_OIDC_ISSUER_URL`   | issuer URL                                         |
| `KURA_OIDC_CLIENT_ID`    | OIDC client ID                                     |
| `KURA_OIDC_CLIENT_SECRET`| OIDC client secret                                 |
| `KURA_PUBLIC_URL`        | the deployment's public URL                        |
| `KURA_FIRM_DOMAIN`       | the issuer URL (Kura uses issuer-as-tenant)        |
| `KURA_CLIENT_DOMAINS`    | comma-separated client issuer URLs (if any)        |

`kura serve` runs OIDC discovery and a JWKS fetch at startup. An
unreachable issuer fails startup within 15 seconds — no hang.

## Recipe: Keycloak

This is the smoother of the two reference vendors. The
[`scripts/oidc-dev/`](https://github.com/bensyverson/kura/tree/main/scripts/oidc-dev)
stack imports a pre-configured realm at boot, so you can be signing in
within a minute.

```sh
docker compose -f scripts/oidc-dev/docker-compose.keycloak.yml up -d
```

Wait for discovery:

```sh
until curl -fsS http://localhost:8085/realms/kura/.well-known/openid-configuration >/dev/null; do
  sleep 1
done
```

Seeded test user: `alice@kura.test` / `alice`.
Seeded client: `kura` / `kura-dev-secret`.

```sh
export KURA_IDP=oidc
export KURA_OIDC_ISSUER_URL=http://localhost:8085/realms/kura
export KURA_OIDC_CLIENT_ID=kura
export KURA_OIDC_CLIENT_SECRET=kura-dev-secret
export KURA_FIRM_DOMAIN=http://localhost:8085/realms/kura
# ... the rest of the kura serve env
./kura serve
```

For a non-dev Keycloak, the equivalent click-through:

1. **Realms** → New → name it (the realm name appears in the issuer
   path).
2. **Clients → Create** → Client type `OpenID Connect`, Client ID
   `kura`.
3. **Client authentication: On** (this is the toggle that makes it a
   confidential client and reveals the secret).
4. **Authentication flow**: only **Standard flow** (the OAuth code
   flow). Disable direct access grants for a sign-in app.
5. **Valid redirect URIs**: `<KURA_PUBLIC_URL>/oauth/callback`. The URI
   must match `KURA_PUBLIC_URL` exactly.
6. **Credentials → Client secret → Regenerate**. Copy the value into
   `KURA_OIDC_CLIENT_SECRET`.
7. On the user you want to sign in with, set the email and toggle
   **Email verified: On** under **Details**.

The issuer URL is `<keycloak-host>/realms/<realm-name>`. Note the
**realm path** — this is the most common Keycloak gotcha: a URL
without `/realms/<name>` returns 404 from discovery.

## Recipe: Zitadel

Zitadel's first start prints a one-time admin login into the container
logs.

```sh
docker compose -f scripts/oidc-dev/docker-compose.zitadel.yml up -d
docker logs -f kura-zitadel | grep -E 'username|password'
```

App registration is click-through in the Console at
<http://localhost:8086/ui/console>:

1. Sign in with the printed admin credentials.
2. **Projects → Create New Project** → name it `kura`.
3. **New Application → Web**, "CODE" flow, "POST" auth method (this
   selects `client_secret_post`, which `coreos/go-oidc` handles
   correctly).
4. **Redirect URIs**: `<KURA_PUBLIC_URL>/oauth/callback`.
5. After creation, copy the **ClientID** and **ClientSecret**.
6. Under **Users**, create a human user and **mark their email as
   verified** (Zitadel-side action under the user's detail page).

```sh
export KURA_IDP=oidc
export KURA_OIDC_ISSUER_URL=http://localhost:8086
export KURA_OIDC_CLIENT_ID=<copied ClientID>
export KURA_OIDC_CLIENT_SECRET=<copied ClientSecret>
export KURA_FIRM_DOMAIN=http://localhost:8086
./kura serve
```

The issuer URL is **the instance root**, with no path. Zitadel does
not have a realm concept; the tenancy boundary is the instance itself
(plus the Zitadel Org concept layered on top, which the
generic-OIDC IdP does not see).

## Recipe: Okta

Okta's issuer URL has two shapes:

- **Org authorization server**: `https://<org>.okta.com` — discovery
  at `https://<org>.okta.com/.well-known/openid-configuration`.
- **Custom authorization server**: `https://<org>.okta.com/oauth2/<id>`
  — discovery at the path
  `https://<org>.okta.com/oauth2/<id>/.well-known/openid-configuration`.

Use the one your client is registered against. App type is **Web** for
a confidential client; the redirect URI is
`<KURA_PUBLIC_URL>/oauth/callback`. `email_verified` is set when the
user was provisioned through the regular flows; if you created the
user through the admin API, verify their email through the user's
profile page before signing in.

## Recipe: Auth0

Auth0's issuer URL is `https://<tenant>.auth0.com/` — note the **trailing
slash**, which Auth0 includes in its discovery `iss` claim and which
must match exactly for verification to succeed.

App type **Regular Web Application** in the Auth0 dashboard;
Application URIs → Allowed Callback URLs →
`<KURA_PUBLIC_URL>/oauth/callback`. Auth0 sets `email_verified=true`
after the user verifies their email through the link Auth0 sends.

## Known limitation: no IdP-mismatch detection

The Google and Microsoft IdPs each pair with a directory client
(Workspace Admin SDK, Microsoft Graph) that powers Kura's
**IdP-mismatch detection** — the `GET /api/users/mismatches` endpoint
that surfaces users who hold Kura roles but whose IdP account is
suspended or deleted upstream.

Generic OIDC has **no standard directory API**. The OIDC core spec
covers token issuance; account-state retrieval is vendor-specific
(Keycloak's Admin REST API, Zitadel's Management API, Okta's Users
API, Auth0's Management API) with no portable shape Kura can target.

On the generic-OIDC IdP path Kura therefore wires a no-op directory:
the mismatch endpoint runs (so callers get a consistent surface) but
always reports zero mismatches. This is the most conservative answer
— it never produces a false positive — but it does mean the
defense-in-depth that the dedicated IdPs offer is unavailable here.

Compensate at the IdP side:

- **Shorter token lifetimes.** A revoked Kura role only stops mattering
  to the gate; a still-active IdP session can sign back in. A 1-hour
  Kura token TTL is the lower bound; pair it with an IdP session that
  is itself short-lived.
- **IdP-side session revocation.** When a person leaves, revoke their
  IdP session there (Keycloak: **Users → Sessions → Logout**; Zitadel:
  **Deactivate user**; Okta/Auth0: deactivate). Combined with a short
  Kura TTL, this caps how long stale access can be exercised.
- **Remove from the Kura authorized-user list promptly.** This is the
  Kura-side control: a user who is not on the list cannot exercise any
  role, regardless of IdP state.

If you need IdP-mismatch detection and your provider exposes a
directory API, file an issue describing the provider — a vendor-specific
directory client is straightforward to add behind the same
`identity.Directory` seam the Google and Microsoft clients implement.

## Verify

`scripts/oidc-smoke.sh` drives the full sign-in end-to-end against
whichever issuer the environment points at. It is the OIDC analogue of
`oauth-smoke.sh`. See `scripts/oidc-dev/README.md` for the dev stacks
and `scripts/oidc-smoke.sh` for the smoke driver.

If sign-in fails, the audit log records a `denied` authentication
event with the failure reason — invalid signature, untrusted issuer,
`email_verified=false`. The browser shows a generic failure; the audit
log has the diagnostic.
