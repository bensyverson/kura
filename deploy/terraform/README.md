# Kura — DigitalOcean Standard-Regulated baseline (Terraform)

This is the tested, known-good infrastructure baseline for a Kura
deployment on DigitalOcean. It is **parameterized**: one baseline serves
every Standard-Regulated engagement, configured by a per-client
`terraform.tfvars` plus secrets injected from Doppler. The per-client
deployment repo (produced by `kura init`) embeds this directory and
instantiates it.

It stands up, in doc 03's provisioning order:

| Resource | Purpose | Posture |
| --- | --- | --- |
| VPC + Cloud Firewall | Private network for all resources | Inbound **443 only**; **no public SSH** (admin via Tailscale) |
| Spaces × 2 (`backups`, `audit-log`) | Encrypted dumps + audit trail | Private, versioned, lifecycle retention, **deny-delete policy** from the admin credential domain |
| Managed Postgres | Application database | On the VPC; **database firewall** admits only the tagged droplets — no public access; TLS-only |
| Droplets × 2 (PII, API) | PII detection + API server | Tagged into the VPC; join the tailnet via cloud-init; PII stood up first |

What this baseline does **not** include (separate, sequenced follow-ups —
see `project/2026-05-28-do-core-infra-plan.md`): the Caddy reverse proxy,
Doppler provisioning, the scheduled-backup timer, monitoring/alerting, and
the static IaC policy / plan-snapshot tests.

## Prerequisites

- [OpenTofu](https://opentofu.org) or [Terraform](https://terraform.io) ≥ 1.6.
- A DigitalOcean account and an API token with write access.
- A Spaces access key / secret key pair for the **admin** credential domain
  (used by Terraform to administer buckets and set the deny-delete policy).
  The **runtime** append-only keys the API server uses
  (`KURA_DO_SPACES_ACCESS_KEY` / `_SECRET_KEY`) are separate and issued
  out of band.
- A Tailscale account and an **ephemeral, pre-authorized** auth key.
- [Doppler](https://doppler.com) holding the secrets below.

## Secrets (never committed)

Provide these at apply time as `TF_VAR_*` environment variables — the
recommended path is `doppler run`, so nothing is written to disk:

| Variable | `TF_VAR` name |
| --- | --- |
| DO API token | `TF_VAR_do_token` |
| Spaces admin access key | `TF_VAR_spaces_access_key` |
| Spaces admin secret key | `TF_VAR_spaces_secret_key` |
| Tailscale auth key | `TF_VAR_tailscale_auth_key` |

## Apply

```sh
# 1. Configure the deployment (non-secret).
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars

# 2. Initialize providers.
tofu init        # or: terraform init

# 3. Review the plan — read it before it runs (doc 02).
doppler run -- tofu plan

# 4. Stand it up.
doppler run -- tofu apply
```

After apply, wire the API server's runtime config from the outputs
(`tofu output`): `database_private_host`, `database_name`,
`database_user`, `database_migrator_user`, `backups_bucket`,
`audit_log_bucket`. Set `KURA_DO_SPACES_*` and `KURA_DATABASE_URL`
accordingly so `kura serve` registers the backup/restore job kinds.

`kura serve` needs **two** database DSNs: `KURA_DATABASE_URL` for the
runtime `kura_api` user (`database_user`) and `KURA_ADMIN_DATABASE_URL`
for the elevated migrator/owner `kura_admin` user
(`database_migrator_user`), which runs migrations and append-only
reconciliation at startup. The two are a deliberate credential-domain
separation — the runtime user cannot own schema objects or write the
append-only set. See the [Database concept doc](../../docs/content/docs/concepts/database.md).

## Verifying the security posture

The baseline encodes doc 03's "what not to deploy without" gates; after
apply, confirm:

- **No public database port** — the database firewall lists only the
  droplet tag as a trusted source; a connection attempt from an untrusted
  IP is refused.
- **No public SSH** — `ssh root@<api_droplet_ip>` times out / is refused;
  `tailscale ssh <hostname>` works.
- **Buckets private + immutable** — both buckets are private, versioning is
  on, and a `DeleteObject` from any key is denied by the bucket policy.

## Teardown

```sh
doppler run -- tofu destroy
```
