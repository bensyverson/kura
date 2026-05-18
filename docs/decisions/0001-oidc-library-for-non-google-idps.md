# ADR 0001 — OIDC library for non-Google IdPs

- **Status:** Accepted
- **Date:** 2026-05-18
- **Approved by:** Ben Syverson

## Context

Kura's multi-IdP rearchitecture
(`project/2026-05-18-multi-idp-identity.md`) adds two new
`IdentityProvider` implementations alongside the existing Google one:
Microsoft Entra (Azure AD) and a generic OIDC provider. Both need:

1. **OIDC discovery** — fetch the issuer's `/.well-known/openid-configuration`
   to learn the authorization, token, and JWKS endpoints.
2. **JWKS-based `id_token` verification** — fetch the issuer's signing
   keys, verify the JWT signature, check `iss` / `aud` / `exp` /
   `nbf` / `email_verified`, and read the claims.

The Google implementation does not need a generic OIDC library: it uses
`google.golang.org/api/idtoken`, which knows Google's JWKS endpoint and
audience model directly. The new IdPs cannot reuse that — they are not
Google.

## Decision

Use **`github.com/coreos/go-oidc/v3`** for the discovery and id_token
verification needed by the Microsoft Entra and generic-OIDC
implementations.

The Google implementation continues to use `idtoken.Validate`. No
existing code is touched by this decision; go-oidc is anchored in
`internal/server/idp.go` with a blank import until the first concrete
consumer (the Microsoft IdP) lands.

## Alternatives considered

### `github.com/zitadel/oidc`

A full-featured Go OIDC client/server library. Capable and actively
maintained, but considerably more opinionated about how a relying party
should be structured — it bundles a session store, a state manager, and
its own HTTP handler conventions. Kura already has `oauthHandler`,
`stateStore`, and a settled `IdentityProvider` interface; the parts of
zitadel/oidc we would actually use are a thin verifier underneath
several layers of code we would not. Library shape mismatched to the
job.

### Hand-rolled JWKS verification

Fetch the discovery document and the JWKS ourselves, parse the JWT,
verify the signature with `github.com/go-jose/go-jose`. Doable, and the
verification logic is well-understood. But every IdP we add would have
to re-implement JWKS caching, key rotation, algorithm-allowlist
enforcement, and `nbf` / `iat` skew handling — all problems already
solved correctly by go-oidc. Re-implementing them is exactly the kind
of bespoke crypto-adjacent code Kura should avoid: easy to get wrong,
hard to audit, no upside over the standard library choice.

### Stay with `google.golang.org/api/idtoken` and extend it

Not actually possible. The Google library is hard-wired to Google's
JWKS endpoint and Google's `iss` value; it cannot validate a Microsoft
or self-hosted-OIDC token.

## Consequences

**Positive**

- One small, well-scoped dependency for two IdP implementations,
  rather than two ad-hoc verifiers.
- JWKS fetching, caching, and key rotation are handled by the library
  — the implementations only have to wire the verifier, the trust
  decision, and the `VerifiedIdentity` mapping.
- Migrating the Google implementation off `idtoken` to go-oidc later
  is straightforward if a single verification path becomes desirable.

**Negative**

- One new transitive dependency
  (`github.com/go-jose/go-jose/v4`, already in the tree).
- Two libraries verifying id_tokens in the same package
  (`idtoken` for Google, `go-oidc` for others) until the consolidation
  above happens. The split is honest: each library matches its IdP's
  conventions exactly.

## Scope of this ADR

This decision covers id_token verification and OIDC discovery only. It
does not commit Kura to using go-oidc for any other purpose (session
handling, OAuth flow orchestration, server-side OP behavior) — those
remain Kura code.
