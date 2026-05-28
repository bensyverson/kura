# Object storage: the two buckets that live outside Postgres — encrypted
# backup dumps and the append-only audit trail. Each is private, versioned,
# retention-bounded by a lifecycle rule, and protected by a deny-delete
# bucket policy. Doc 03 provisioning step 4; the immutability posture is
# the one internal/storage/doc.go describes (versioning + deny-delete, the
# proportionate Standard-Regulated stand-in for true WORM).
#
# Credential domains. Terraform administers these buckets — and sets the
# deny-delete policy — using the admin Spaces keys (the spaces_* provider
# credentials). The runtime writers use *different*, append-only Spaces
# keys (KURA_DO_SPACES_ACCESS_KEY / _SECRET_KEY) the operator issues
# separately. So the credential that can administer the bucket is not the
# credential the running system holds: a compromised runtime writer can
# append but cannot destroy.

# --- BACKUPS bucket: separate region, 30-35 day retention ------------------
resource "digitalocean_spaces_bucket" "backups" {
  name   = "${local.name}-backups"
  region = var.backups_region
  acl    = "private"

  versioning {
    enabled = true
  }

  # Retention is policy, not an action any runtime credential takes: the
  # platform expires objects at the ceiling of the backups retention window
  # (storage.BackupsSpec MaxDays = 35).
  lifecycle_rule {
    enabled = true
    expiration {
      days = 35
    }
  }
}

resource "digitalocean_spaces_bucket_policy" "backups_deny_delete" {
  region = var.backups_region
  bucket = digitalocean_spaces_bucket.backups.name
  policy = local.deny_delete_policy[digitalocean_spaces_bucket.backups.name]
}

# --- AUDIT-LOG bucket: 1-2 year retention ----------------------------------
resource "digitalocean_spaces_bucket" "audit_log" {
  name   = "${local.name}-audit-log"
  region = var.region
  acl    = "private"

  versioning {
    enabled = true
  }

  # Ceiling of the audit-log retention window (storage.AuditLogSpec
  # MaxDays = 730).
  lifecycle_rule {
    enabled = true
    expiration {
      days = 730
    }
  }
}

resource "digitalocean_spaces_bucket_policy" "audit_log_deny_delete" {
  region = var.region
  bucket = digitalocean_spaces_bucket.audit_log.name
  policy = local.deny_delete_policy[digitalocean_spaces_bucket.audit_log.name]
}

locals {
  # An explicit-Deny bucket policy denying object/version deletion and
  # versioning-disable to every principal. Explicit deny always wins in
  # S3 semantics, so no key — runtime or admin — can destroy stored
  # objects or weaken the bucket's immutability. Lifecycle expiration
  # still applies: it is performed by the storage platform, not by a
  # principal the policy binds.
  bucket_names = [
    digitalocean_spaces_bucket.backups.name,
    digitalocean_spaces_bucket.audit_log.name,
  ]

  deny_delete_policy = {
    for name in local.bucket_names : name => jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "DenyObjectAndVersionDeletion"
          Effect    = "Deny"
          Principal = { AWS = ["*"] }
          Action = [
            "s3:DeleteObject",
            "s3:DeleteObjectVersion",
            "s3:PutBucketVersioning",
          ]
          Resource = [
            "arn:aws:s3:::${name}",
            "arn:aws:s3:::${name}/*",
          ]
        },
      ]
    })
  }
}
