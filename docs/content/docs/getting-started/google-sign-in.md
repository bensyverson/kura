---
title: Google Workspace sign-in
weight: 2
---

Kura accepts sign-in from **Google Workspace**. The Google IdP is one
implementation of the same `IdentityProvider` seam the Microsoft and
generic-OIDC IdPs use — the trust model, token model, and audit log are
identical. Only the IdP-side setup changes.

This page walks through the Google-side OAuth client registration a
deployment needs before `kura serve` can broker sign-in. For
IdP-mismatch detection (the admin endpoint that surfaces suspended or
deleted accounts that still hold Kura roles), see
[Google Workspace directory](google-workspace-directory) — a separate
setup with its own service-account credentials.

## What you need

- A **Google Workspace tenant** for the firm — every consultant signs
  in against this tenant. (A separate set of `KURA_CLIENT_DOMAINS`
  trust entries can name client-side Workspace domains; the deployment
  decides which domain maps to `Consultant`, `User`, and `Admin`.)
- **Admin or developer access** to a **Google Cloud project** — the
  OAuth client is registered against a GCP project, not against the
  Workspace tenant directly. Any project will do.
- The **public URL** of the Kura deployment (the URL `kura serve`
  answers on). The `/oauth/callback` path under that URL is the
  redirect URI you will register below.

## Register the OAuth client

1. Open the [Google Cloud Console][gcp] and select (or create) a
   project to host the OAuth client.
2. **APIs & Services → OAuth consent screen** — choose **Internal** if
   the Workspace tenant is the only one that should sign in; choose
   **External** if you want any Google account to be able to reach
   the consent screen (you will gate trust through `KURA_FIRM_DOMAIN`
   regardless). Fill in the app name and support email.
3. **APIs & Services → Credentials → Create credentials → OAuth client
   ID**.
4. **Application type: Web application**.
5. **Authorized redirect URIs** — add
   `https://<your-kura-public-url>/oauth/callback`. The URI must match
   the `KURA_PUBLIC_URL` the server is configured with, exactly. For
   local development against the loopback handoff, the redirect URI
   is `http://127.0.0.1:8080/oauth/callback` (Google permits
   `http://127.0.0.1` redirects without TLS).
6. Click **Create**. Copy the **Client ID** and **Client secret** — the
   secret is shown only once.

## Configure `kura serve`

With the Client ID and Client secret in hand, set the corresponding
environment variables when running `kura serve`:

| Variable                              | Value                                                                |
| ------------------------------------- | -------------------------------------------------------------------- |
| `KURA_IDP`                            | `google`                                                             |
| `KURA_GOOGLE_CLIENT_ID`               | OAuth Client ID                                                      |
| `KURA_GOOGLE_CLIENT_SECRET`           | OAuth Client secret                                                  |
| `KURA_GOOGLE_DIRECTORY_CREDENTIALS`   | Path to the service-account JSON (see [directory setup][gs-dir])    |
| `KURA_GOOGLE_DIRECTORY_SUBJECT`       | Workspace admin email the directory service account impersonates    |
| `KURA_PUBLIC_URL`                     | The deployment's public URL                                          |

Both directory variables are required when `KURA_IDP=google`. The
directory is the IdP-side seam that powers `GET /api/users/mismatches`;
service-account setup is documented separately at
[Google Workspace directory][gs-dir].

The Kura-side tenant-trust configuration (`KURA_FIRM_DOMAIN`,
`KURA_CLIENT_DOMAINS`, `KURA_ADMIN_EMAILS`) is shared across all IdPs.
For Google, the **tenant key is the Workspace domain** (the `hd` claim
on the id_token). Put each accepted Workspace domain in the trust
list. See [Tenant trust](tenant-trust) for the cross-IdP details.

`KURA_IDP` is required — there is no default. A deployment must
explicitly pick one of `google`, `microsoft`, or `oidc`; an unset
selector fails server startup.

## Verify

Once the server is running, `kura login` opens the Google consent
screen in your browser. After consent, the browser is redirected to
`/oauth/callback` on your Kura public URL, the server verifies the
id_token, and the CLI receives a short-lived Kura token. The token is
the identity; from that point on, the session behaves the same as a
Microsoft- or OIDC-authenticated session.

If sign-in fails, the audit log records a `denied` authentication
event with the failure reason — invalid signature, untrusted domain,
missing `hd` claim, `email_verified=false`. The browser shows a
generic failure; the audit log has the diagnostic.

For an end-to-end manual check against a real Workspace domain, see
`scripts/oauth-smoke.sh` in the repository — it drives the full flow
and verifies the token the server mints actually resolves.

[gcp]: https://console.cloud.google.com/
[gs-dir]: google-workspace-directory
