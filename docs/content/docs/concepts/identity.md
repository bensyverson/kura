---
title: Identity & principals
weight: 1
---

Every action in Kura is attributed to a **principal** — a real Cedar entity that the
audit log records and that Cedar policy reasons about. There is no "the CLI is
trusted" backdoor: the CLI, the HTTP API, the dashboard, and MCP all resolve a
principal and emit an audit event for every action.

This page records the **consultant authentication model** — a decision resolved
during design — and the Cedar principal schema that follows from it.

## The consultant authentication model

The consultant is a **distinct Cedar principal type** (`Consultant`), **not** a guest
in the client's identity provider.

Authentication is OIDC against whichever IdP family the deployment is configured
for — Google Workspace, Microsoft Entra (Azure AD), or any standards-compliant
OIDC provider (Okta, Auth0, Keycloak, Zitadel, …). A consultant signs in against
the **consulting firm's own IdP tenant** — whatever tenant the firm operating the
engagement controls. A client's deployment config names that firm tenant and
trusts it for the `Consultant` principal type *only* — separately from the
client's own tenant, which maps to `User` and `Admin`. The firm tenant is
per-deployment configuration; Kura hardwires no firm identity.

The consultant's agent acts **as** the consultant: `kura login` signs the consultant
in against the firm tenant, and the agent uses that short-lived token. There is **no
separate per-agent principal in v1** — the human owns the session, and the audit log
attributes actions to them. Ending an engagement, or re-engaging, is a config change:
add or remove the firm-tenant trust.

### Why

- **Offboarding control.** The consulting firm controls consultant offboarding, not
  the client. A consultant who leaves the firm loses access to *every* client
  deployment at once, through the firm's own IdP — the client never has to act.
- **Distinct audit trail.** Consultant actions are a distinct principal type in the
  audit log, never blurred into the client's own users.
- **Engagement-end is declarative.** Re-engagement and disengagement are a trust-list
  edit in the deployment config, not an account-lifecycle dance in the client's
  directory.

> **Example.** A firm running an engagement on a Google Workspace domain
> `firm.example` configures the client deployment to trust `firm.example` for
> `Consultant`; a consultant logs in as e.g. `alex@firm.example`. The same model
> works for a firm using Entra (the trust list names a tenant GUID instead of a
> domain) or a generic-OIDC provider (the trust list names the issuer URL). None
> of this is baked into Kura.

This decision shapes `kura login`, the short-lived token model, and the Cedar
principal schema.

## The IdP abstraction

Kura's identity layer is **IdP-agnostic**. The same trust model and the same
principal schema run on top of three concrete identity providers:

| KURA_IDP   | Sign-in protocol            | What the deployment configures                       |
| ---------- | --------------------------- | ---------------------------------------------------- |
| `google`   | Google OAuth + id_token     | OAuth client + Workspace domain(s) + admin emails    |
| `microsoft`| Entra OIDC                  | App registration + tenant ID(s) + admin emails       |
| `oidc`     | Generic OpenID Connect      | OIDC client + issuer URL(s) + admin emails           |

Internally these are three implementations of one `IdentityProvider` seam — the
piece that runs the OAuth code exchange and verifies the id_token. The pieces
*outside* that seam — the trust decision, the token model, the audit log, the
gate — see only the **verified identity** the seam returns: an email, an IdP
tenant identifier, and the issuer URL. The downstream code never branches on
which family the IdP is.

The same shape holds for the **directory** (the IdP-side seam Kura reads to
detect mismatches between the authorized-user list and live IdP state): Google
Workspace Admin SDK on the Google path, Microsoft Graph on the Entra path, a
no-op on the generic-OIDC path (no portable directory API exists). See
[The HTTP API server](../server/) for how the mismatch endpoint surfaces this.

## The Tenant abstraction

Every IdP has *some* notion of "which tenant signed this token." The names
differ; the role they play in Kura's trust decision is identical.

| KURA_IDP   | Tenant identifier                  | id_token claim Kura reads        |
| ---------- | ---------------------------------- | -------------------------------- |
| `google`   | Workspace domain (e.g. `firm.example`) | `hd`                         |
| `microsoft`| Entra tenant ID (a GUID, or `common`)  | `tid`                        |
| `oidc`     | Issuer URL (the OIDC `iss` claim)      | `iss`                        |

The verified identity carries that tenant key in a single field (`Tenant`).
Trust decisions compare it against the deployment's tenant allowlists — nothing
in the trust layer cares which family produced it.

**Tradeoff worth naming for generic OIDC.** Vanilla OIDC has no tenant claim
analogous to `hd` or `tid`; Kura therefore uses the **issuer URL** as the
tenant identifier on that path. The practical consequence: two Keycloak realms
on one host (different `/realms/<name>` paths) are two tenants, which is
usually what you want; an OIDC vendor that exposes multiple logical tenants
under one issuer URL cannot be tenant-distinguished by Kura on the generic-OIDC
path. If your IdP has a real tenant claim (Google `hd`, Entra `tid`), use the
dedicated IdP family — it gives a richer trust signal than issuer-as-tenant.

## TenantTrust: the deployment-side mapping

`TenantTrust` is the per-deployment policy that turns a verified
`(email, tenant)` pair into a Kura principal:

```go
type TenantTrust struct {
    FirmTenant    string   // Consultant: the firm's IdP tenant
    ClientTenants []string // User (or Admin): the client's IdP tenant(s)
    AdminEmails   []string // explicit allowlist; promotes a client User → Admin
}
```

The rules:

- A verified identity whose tenant equals `FirmTenant` → `Consultant`.
- A verified identity whose tenant is in `ClientTenants` → `User`, or `Admin`
  if its email is in `AdminEmails`.
- Any other tenant → `ErrUntrustedTenant`. There is **no default principal type**.

`AdminEmails` is intentionally a flat allowlist, not a directory-group lookup —
granting and revoking the elevated principal is a deployment-config edit, the
same shape as everything else in the engagement model.

## Side-by-side config

The environment variables that drive `TenantTrust` are family-agnostic — the
same three keys (`KURA_FIRM_DOMAIN`, `KURA_CLIENT_DOMAINS`, `KURA_ADMIN_EMAILS`)
hold tenant identifiers in whatever shape the configured IdP uses. The full
list of family-specific OAuth/OIDC variables is in
[The HTTP API server](../server/) and the per-IdP getting-started pages
([Google][gs-google] / [Microsoft Entra][gs-microsoft] /
[Generic OIDC][gs-oidc]).

```sh
# Google Workspace
export KURA_IDP=google
export KURA_GOOGLE_CLIENT_ID=...               # OAuth client (sign-in)
export KURA_GOOGLE_CLIENT_SECRET=...
export KURA_GOOGLE_DIRECTORY_CREDENTIALS=...   # service-account JSON (mismatch detection)
export KURA_GOOGLE_DIRECTORY_SUBJECT=admin@firm.example
export KURA_FIRM_DOMAIN=firm.example           # Consultant tenant
export KURA_CLIENT_DOMAINS=client.example      # User tenant
export KURA_ADMIN_EMAILS=boss@client.example   # Admin allowlist

# Microsoft Entra
export KURA_IDP=microsoft
export KURA_MICROSOFT_CLIENT_ID=...
export KURA_MICROSOFT_CLIENT_SECRET=...
export KURA_MICROSOFT_TENANT_ID=common         # sign-in scope (or a specific tenant)
export KURA_FIRM_DOMAIN=11111111-2222-3333-...    # firm Entra tenant ID (Consultant)
export KURA_CLIENT_DOMAINS=aaaaaaaa-bbbb-cccc-... # client Entra tenant ID (User)
export KURA_ADMIN_EMAILS=boss@client.example

# Generic OIDC
export KURA_IDP=oidc
export KURA_OIDC_ISSUER_URL=https://issuer.example/
export KURA_OIDC_CLIENT_ID=...
export KURA_OIDC_CLIENT_SECRET=...
export KURA_FIRM_DOMAIN=https://issuer.example/   # firm issuer URL (Consultant)
export KURA_CLIENT_DOMAINS=https://client-issuer.example/
export KURA_ADMIN_EMAILS=boss@client.example
```

Same trust model, three IdP families. The downstream code (Cedar evaluation,
audit recording, gate enforcement) is identical in all three.

## Cedar principal schema

The principal types Cedar reasons about. Roles, resource types, and actions are
layered on by the per-client schema manifest; this records only the **principal**
taxonomy.

```cedarschema
// Client-tenant human with standard, policy-scoped access.
entity User {
  email: String,
  tenant: String,
};

// Client-tenant human with elevated access (dashboard administration,
// access reviews). Distinct entity type so policy can grant to Admin
// without enumerating individuals.
entity Admin {
  email: String,
  tenant: String,
};

// Firm-tenant human — the consulting firm's operator, signed in against
// the firm's own IdP tenant. Trusted per-deployment, separately from
// the client tenant.
entity Consultant {
  email: String,
  tenant: String,
};

// Non-human principal: kura serve's own internal operations,
// provisioning, and (post-handoff) a client's automated agents. v1
// issues no per-agent principal to a consultant's agent — that agent
// acts as the Consultant. This type exists for genuine service accounts.
entity Service {
  name: String,
};
```

**Tenant trust, not entity membership, is what separates a `Consultant` from a
`User`.** Both authenticate through the same IdP family Kura is configured for;
the deployment config decides which tenant maps to which principal type. An
unauthenticated request resolves to *no principal* and is denied.

## The token model

The token **is** the identity. A request carries a short-lived token; resolving that
token yields the principal, and every action is attributed to it. There is no
anonymous path and no "trusted CLI" path — a request with no valid token resolves to
no principal and is denied.

Kura's tokens are **self-contained and HMAC-SHA256 signed**. A token carries the
principal and an expiry, and the signature is verified on every resolve:

- **Self-contained** — the token needs no server-side session store to validate. The
  core identity layer has no storage or network dependency, which also means it is in
  place before the database and the OAuth flow are.
- **One fixed algorithm** — there is no algorithm field to negotiate, so there is no
  algorithm-confusion attack surface.
- **Injected signing secret** — the secret comes from the secrets manager (see
  [Secrets](../secrets/)) and is rotatable; it is never baked in.

Resolving a credential has exactly three failure modes, each distinct so a caller can
act on them: *no credential* (unauthenticated), *malformed or unverified* (invalid
token), and *verified but past expiry* (expired token). Only a fully valid token
yields a principal.

`kura login` performs the OAuth/OIDC flow and obtains one of these short-lived
tokens. The flow is a **loopback handoff**: `kura serve` brokers the IdP sign-in
and mints the token, then redirects it back to a temporary `127.0.0.1` listener
the CLI stood up. The full sequence — and why loopback was chosen over the
OAuth device flow — is in [The HTTP API server](../server/). The HTTP
middleware that resolves the token to a principal on every request lives there
too.

[gs-google]: ../../getting-started/google-workspace-directory
[gs-microsoft]: ../../getting-started/microsoft-sign-in
[gs-oidc]: ../../getting-started/generic-oidc-sign-in
