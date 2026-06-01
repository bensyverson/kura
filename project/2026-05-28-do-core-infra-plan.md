# Core DigitalOcean infrastructure (Terraform baseline) — `Bpp3j`

*2026-05-28. Design record for Phase 6 leaf `Bpp3j` and its job children
`X1aN1`/`LFYIU`/`5zh0k`/`KGURj`/`xlzMP`/`I2Vm0`.*

## Context

Kura's critical path to a real deployment runs through Phase 6: nothing stands up
until the infrastructure exists. The S3-compatible DO Spaces `storage.Store`
client (`YKmQv`, commit `3066977`) and its wiring into `kura serve` (`9f554c0`)
filled the buildable software gap. `Bpp3j` is the remaining keystone — the
**declarative IaC** that provisions the resource set doc 03 specifies, in its
dependency order, parameterized so one baseline serves every Standard-Regulated
engagement.

Phase 0 resolved the tooling: **Terraform** (HCL is readable to the SMB tech owner
who inherits the per-client repo; `plan`/`apply` maps to doc 02's "read the agent's
plan before it runs") and **Doppler** for secrets.

**Honest constraint:** criterion `OoL` ("`terraform apply` stands up the full
resource set in a test DO account") needs a real DO token and incurs cost, so it is
**operator-run** — released like the Google E2E validation (`fjc5g`). This work
delivers authored, `fmt`/`validate`-clean HCL plus an operator runbook; the live
apply is the operator's to run.

## Location

`deploy/terraform/` — a flat root module (file-per-concern; flatter HCL reads better
for the non-specialist handoff target). Phase 7's `kura init` (`t6id9`) embeds this
directory via `embed.FS` and instantiates it per client, so it must be
self-contained and parameter-driven.

## Layout

```
deploy/terraform/
  versions.tf               required_version + required_providers (digitalocean, cloudinit)
  variables.tf              per-client params (region, client slug, sizes, domain) + sensitive secrets
  main.tf                   provider config + naming locals (<client>-<resource>)
  network.tf                digitalocean_vpc + digitalocean_firewall (droplet ingress, no public 22)
  database.tf               digitalocean_database_cluster (pgaudit/pgcrypto) + digitalocean_database_firewall
  storage.tf                2× spaces_bucket + versioning + lifecycle + deny-delete bucket policy
  compute.tf                2× droplet (API, PII) + cloud-init Tailscale join
  outputs.tf                non-secret outputs (db private host, bucket names, droplet IPs)
  cloud-init/tailscale.yaml.tftpl   user_data: install Tailscale, join tailnet, base hardening
  terraform.tfvars.example  representative non-secret config
  README.md                 operator runbook
```

## Resources, mapped to doc 03's provisioning order

Order is encoded via Terraform implicit references / `depends_on`:

1. **Network (step 2)** — VPC (private net for everything); Cloud Firewall on the
   droplet tag: inbound **443 only**, **no public 22** (SSH over `tailscale0`). → `qyn`.
2. **Object storage (step 4)** — `backups` + `audit-log` buckets, `acl=private`,
   **versioning on both**, lifecycle/retention (30–35d / 365–730d, matching
   `storage.BackupsSpec()`/`AuditLogSpec()`), and a **deny-delete bucket policy**
   (`DeleteObject`/`DeleteObjectVersion`/`PutBucketVersioning`) applied from an admin
   credential domain while the runtime uses append-only keys. This is the
   "suspenders" to the Go `AppendOnly` "belt" (`internal/storage/doc.go`). → `4VC`, `BFc`.
   - ⚠️ DO Spaces per-key bucket scoping is coarser than AWS IAM; the deny-delete
     *bucket policy* is the portable mechanism the criterion names. The exact key/grant
     split is confirmed against the current DO provider at apply time.
3. **Database (step 5)** — Managed Postgres (stable major, pgaudit + pgcrypto) on the
   VPC via `private_network_uuid`; `database_firewall` trusted-sources limited to the
   API droplet tag → **no public port**; TLS-only default. → `qyn` (DB half).
4. **Compute (step 6)** — two droplets (PII first, then API) tagged into the VPC;
   `user_data` cloud-init installs Tailscale and joins the tailnet with a sensitive
   Doppler-sourced auth key. No public sshd.

## Parameterization

`variables.tf` exposes per-client knobs (region, client slug, droplet/db sizes, domain)
with Standard-Regulated defaults, plus **sensitive** secret vars (`do_token`,
`spaces_access_key`/`secret_key`, `tailscale_auth_key`, db password as needed) supplied
at apply via `TF_VAR_*` from a `doppler run` wrapper. Full Doppler wiring is the `RyHcv`
leaf; the variable shapes anticipate it. `terraform.tfvars.example` shows a complete
non-secret config.

## Validation

- Install OpenTofu/Terraform (separate tool, not a `go.mod` dep, per `dec-terraform`).
- `terraform fmt -check` + `terraform validate` pass (validate needs `init` to fetch the
  provider — network, no DO creds).
- `plan`/`apply`/`destroy` are operator-run with a DO token; the README documents the
  sequence.
- **TDD note:** strict Go red/green doesn't map to HCL authoring. The static test analog
  — tflint/Conftest policy gates that fail on a deliberately broken config, and
  `terraform plan` snapshots — are the separate leaves `YxZdl` and `7a5Pd`. For `Bpp3j`
  the mechanical gate is `terraform validate`.

## Remaining Phase 6 work (in the ledger, blocked on `Bpp3j`)

- `6tVWB` Caddy reverse proxy (auto-TLS, HSTS, rate limit, real client IP).
- `RyHcv` Secrets backend provisioning (Doppler) + runtime injection + smoke-verify.
- `0Us1a` Automated backup scheduling (timer/Function → `kura backup`; append-only cred +
  secrets key; DO managed backups stay on). Software side now unblocked by `YKmQv`+`9f554c0`.
- `eLT3D` Monitoring & alerting (DO alert policies + audit-stream consumer).
- `YxZdl` Static IaC policy tests (tflint/Conftest) — the red/green gate for the HCL.
- `7a5Pd` `terraform plan` snapshot tests.
- Downstream: Phase 7 `kura init` (`t6id9`) embeds `deploy/terraform/`.

## Verification (end-to-end)

1. `cd deploy/terraform && terraform init && terraform fmt -check && terraform validate` → clean.
2. Read-through vs doc 03's "What Not To Deploy Without": TLS everywhere, no public DB port,
   no public SSH, buckets private + immutable posture — each visible in the HCL.
3. Operator: `doppler run -- terraform plan` then `apply` in a test DO account; confirm DB has
   no public port, SSH only via Tailscale, buckets private + versioned + deny-delete; then
   `terraform destroy`.
