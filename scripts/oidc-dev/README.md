# OIDC dev infrastructure

Two docker-compose stacks — **Keycloak** and **Zitadel** — that boot a
real OIDC vendor on the local machine so Kura's generic-OIDC IdP can
be validated end-to-end without registering anything in a hosted
identity service.

Each stack binds to `127.0.0.1` only and reserves a port that does not
clash with `kura serve` on `127.0.0.1:8080`:

| Vendor    | Bound at                  | Issuer URL                                  |
| --------- | ------------------------- | ------------------------------------------- |
| Keycloak  | `http://localhost:8085/`  | `http://localhost:8085/realms/kura`         |
| Zitadel   | `http://localhost:8086/`  | `http://localhost:8086`                     |

Both are intended for development and validation only. The compose
files disable TLS and use throwaway credentials baked into the file —
do not point them at a real network.

## Prerequisites

- A Docker-compatible runtime. The project's convention is
  [Colima](https://github.com/abiosoft/colima), not Docker Desktop:

  ```sh
  brew install colima docker docker-compose
  colima start
  ```

- The Kura binary built locally:

  ```sh
  go build -o kura ./cmd/kura
  ```

## Keycloak

The realm is **pre-imported** at boot from
[`keycloak-realm-kura.json`](./keycloak-realm-kura.json). The seeded
client and user are ready immediately — no Console click-ops needed.

```sh
docker compose -f scripts/oidc-dev/docker-compose.keycloak.yml up -d
```

Wait until the realm endpoint responds:

```sh
until curl -fsS http://localhost:8085/realms/kura/.well-known/openid-configuration >/dev/null; do
  sleep 1
done
```

Seeded test user: **alice@kura.test** / **alice**.
Seeded client: `kura` / `kura-dev-secret`.

Start Kura against it:

```sh
export KURA_IDP=oidc
export KURA_OIDC_ISSUER_URL=http://localhost:8085/realms/kura
export KURA_OIDC_CLIENT_ID=kura
export KURA_OIDC_CLIENT_SECRET=kura-dev-secret
# ... the rest of the kura serve env (KURA_SIGNING_SECRET, etc.)
./kura serve
```

Tear down:

```sh
docker compose -f scripts/oidc-dev/docker-compose.keycloak.yml down -v
```

## Zitadel

App registration is a click-through in the Console — there is no
realm-import equivalent. The compose file pins the bootstrap admin
credentials (no rotating temporary password to chase) so a
wipe-and-restart cycle is cheap.

```sh
docker compose -f scripts/oidc-dev/docker-compose.zitadel.yml up -d
```

Admin (dev-only): `zitadel-admin@zitadel.localhost` / `Password1!`.

Then in the Console at <http://localhost:8086/ui/console>:

1. Sign in with the admin credentials above.
2. **Projects → Create New Project** → name it `kura`.
3. **New Application → Web**, "CODE" flow, "POST" auth method (this
   selects `client_secret_post`, which `coreos/go-oidc` handles).
4. **Redirect URIs**: `http://127.0.0.1:8080/oauth/callback`.
5. **Development Mode: ON** (relaxes the HTTPS-only validation so
   Zitadel accepts the `http://127.0.0.1:...` redirect URI). Do *not*
   leave this on in production.
6. After creation, open the new app → **Token Settings**, and turn
   **"User Info inside ID Token" ON**. Zitadel defaults to a minimal
   id_token (no `email` / `email_verified` claims), and Kura reads
   identity from the id_token rather than the userinfo endpoint, so
   without this toggle every sign-in fails with
   `email_verified=false`.
7. Copy the **ClientID** and **ClientSecret**.
8. Create a human user under **Users**; **mark the email as verified**
   (Zitadel-side action — the per-user verify button on the email
   field, not the registration-side verify-on-signup flow). Kura
   rejects an `id_token` whose `email_verified` claim is false or
   absent.

Start Kura against it:

```sh
export KURA_IDP=oidc
export KURA_OIDC_ISSUER_URL=http://localhost:8086
export KURA_OIDC_CLIENT_ID=<the ClientID you copied>
export KURA_OIDC_CLIENT_SECRET=<the ClientSecret you copied>
./kura serve
```

Tear down:

```sh
docker compose -f scripts/oidc-dev/docker-compose.zitadel.yml down -v
```

## Smoke-testing the full sign-in

The companion script
[`../oidc-smoke.sh`](../oidc-smoke.sh) drives `kura login` against
whichever issuer the env points at, with a human completing the
browser sign-in. It is the OIDC analogue of `oauth-smoke.sh` (which is
Google-specific).
