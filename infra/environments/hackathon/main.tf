# Delegation Fabric — hackathon environment.
# Provisions regional KMS signing key and least-privilege service accounts.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  type        = string
  description = "GCP project id."
}

variable "region" {
  type        = string
  default     = "asia-south1"
  description = "Deployment region for all resources."
}

variable "container_image" {
  type        = map(string)
  description = <<-EOT
    Container image per Cloud Run service. These are PLACEHOLDER digest-pinned
    references: `make deploy` builds from source via gcloud and replaces the
    running image. Because image replacement happens outside Terraform, the
    image attribute is ignored on subsequent applies (see lifecycle below);
    this variable only bootstraps a service shell if it does not yet exist.
  EOT

  default = {
    "control-plane"     = "us-docker.pkg.dev/cloud-run-source-deploy/delegation-fabric/control-plane@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    "execution-gateway" = "us-docker.pkg.dev/cloud-run-source-deploy/delegation-fabric/execution-gateway@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    "worker"            = "us-docker.pkg.dev/cloud-run-source-deploy/delegation-fabric/worker@sha256:0000000000000000000000000000000000000000000000000000000000000000"
  }
}

locals {
  services = ["control-plane", "execution-gateway", "worker"]

  # Full KMS key-version resource name consumed as DF_KMS_KEY_VERSION by the
  # control plane (signing) and execution gateway (public-key fetch).
  kms_key_version_ref = "${google_kms_crypto_key.grant_signing.id}/cryptoKeyVersions/1"

  # Environment shared by all three services (mirrors .env.example).
  env_common = {
    GOOGLE_CLOUD_PROJECT  = var.project_id
    GOOGLE_CLOUD_LOCATION = var.region
    DF_ENV                = "hackathon"
    DF_STORE              = "firestore"
    DF_PUBSUB_PROJECT     = var.project_id
  }

  # Grant sign/verify pairing: issuer and audience MUST stay consistent
  # between control plane (issues) and execution gateway (verifies).
  env_grant = {
    DF_KMS_KEY_VERSION    = local.kms_key_version_ref
    DF_GRANT_ISSUER       = "delegation-fabric-control-plane"
    DF_GRANT_AUDIENCE     = "delegation-fabric-execution-gateway"
    DF_GRANT_TTL_SECONDS  = "300"
    DF_CLOCK_SKEW_SECONDS = "30"
  }

  # Per-service overrides layered on top of env_common (+ env_grant where set).
  env_per_service = {
    "control-plane"     = local.env_grant
    "execution-gateway" = local.env_grant
    # ERP backend stays file-based until Cloud SQL + Secret Manager exist here;
    # see commented DATABASE_URL example on the service resource below.
    "worker"            = {}
  }
  # Canonical dotted topic names mandated by PLAN.md (§ Topics); the publisher
  # in delegation_fabric_adapters.pubsub builds the same f"{prefix}.{suffix}" ids.
  topics = [
    "delegation_fabric.tasks",
    "delegation_fabric.approvals",
    "delegation_fabric.webhooks",
  ]
}

resource "google_kms_key_ring" "grants" {
  name     = "delegation-fabric"
  location = var.region
}

resource "google_kms_crypto_key" "grant_signing" {
  name            = "execution-grant-signing"
  key_ring        = google_kms_key_ring.grants.id
  purpose         = "ASYMMETRIC_SIGN"
  rotation_period = "7776000s" # 90 days

  version_template {
    algorithm = "EC_SIGN_P256_SHA256"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "services" {
  for_each     = toset(local.services)
  account_id   = "df-${each.value}"
  display_name = "Delegation Fabric ${each.value}"
}

# Signer may only use the key version for asymmetric sign.
resource "google_kms_crypto_key_iam_member" "signer" {
  crypto_key_id = google_kms_crypto_key.grant_signing.id
  role          = "roles/cloudkms.cryptoKeySigner"
  member        = "serviceAccount:${google_service_account.services["control-plane"].email}"
}

output "kms_key_version" {
  value       = "${google_kms_crypto_key.grant_signing.id}/cryptoKeyVersions/1"
  description = "Set as DF_KMS_KEY_VERSION."
}

output "service_accounts" {
  value = { for s, sa in google_service_account.services : s => sa.email }
}

# ─── Firestore (native mode) ──────────────────────────────────────────────────
#
# Stores delegations, grants, approvals, tasks, checkpoints, event receipts
# and audit chain metadata (docs/DEPLOYMENT_OPERATIONS.md §6). Regional
# location matches var.region. If the project already has an ad-hoc default
# database created imperatively, import it first:
#   terraform import google_firestore_database.default projects/PROJECT/databases/(default)
resource "google_firestore_database" "default" {
  project          = var.project_id
  name             = "(default)"
  location_id      = var.region
  type             = "FIRESTORE_NATIVE"
  concurrency_mode = "OPTIMISTIC"

  # Hackathon environment is disposable per cost controls (§13): allow the
  # database to be deleted on destroy instead of tombstoned.
  deletion_policy = "DELETE"
}

variable "worker_push_endpoint" {
  type        = string
  description = "Worker Cloud Run URL used as the Pub/Sub push endpoint."
}

# ─── OPS NOTE (commit 08c3dc5, 2026-08-26): TOPIC RENAMES = DESTROY + RECREATE ───
# These topic/subscription/DLQ names were renamed from underscore style
# ("delegation_fabric_tasks" / "..._dlq" / "...-push") to dotted style. Pub/Sub
# resource names are immutable: Terraform treats a rename as destroy+recreate.
# Consequences and migration path are documented in
# docs/DEPLOYMENT_OPERATIONS.md §8 ("Topic rename migration").
resource "google_pubsub_topic" "main" {
  for_each                   = toset(local.topics)
  name                       = each.value
  message_retention_duration = "604800s"
}

resource "google_pubsub_topic" "dlq" {
  for_each = toset(local.topics)
  name     = "${each.key}.dlq"
}

resource "google_pubsub_subscription" "push" {
  for_each             = toset(local.topics)
  name                 = "${each.key}.push"
  topic                = google_pubsub_topic.main[each.key].id
  ack_deadline_seconds = 30

  expiration_policy {
    ttl = ""
  }

  push_config {
    push_endpoint = var.worker_push_endpoint

    oidc_token {
      service_account_email = google_service_account.services["worker"].email
    }
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dlq[each.key].id
    max_delivery_attempts = 5
  }
}

data "google_project" "current" {}

# REQUIRED for dead_letter_policy forwarding: the Pub/Sub service agent must be
# able to publish forwarded messages to DLQ topics and pull from the source
# topics. Without these bindings GCP silently refuses to forward dead letters.
resource "google_project_iam_member" "pubsub_service_agent_dlq_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_project_iam_member" "pubsub_service_agent_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

# Worker consumes from the DLQ topics (inspection/replay tooling).
resource "google_project_iam_member" "worker_dlq_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.services["worker"].email}"
}

resource "google_project_iam_member" "worker_dlq_viewer" {
  project = var.project_id
  role    = "roles/pubsub.viewer"
  member  = "serviceAccount:${google_service_account.services["worker"].email}"
}

# Allows the push OIDC token to invoke the worker Cloud Run service.
resource "google_project_iam_member" "worker_run_invoker" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "serviceAccount:${google_service_account.services["worker"].email}"
}

# Control plane publishes events onto the task/approval/webhook topics.
resource "google_project_iam_member" "control_plane_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.services["control-plane"].email}"
}

output "pubsub_topics" {
  value       = [for t in google_pubsub_topic.main : t.name]
  description = "Main Pub/Sub topic names."
}

output "pubsub_subscriptions" {
  value       = [for s in google_pubsub_subscription.push : s.name]
  description = "Push subscription names."
}

# ─── Cloud Run services ───────────────────────────────────────────────────────
#
# TWO-STEP DEPLOY FLOW (intentional):
#   1. `make infra`  — Terraform declares the service shell: env vars, service
#      identity, scaling, ingress posture, Pub/Sub wiring (this file).
#   2. `make deploy` — gcloud builds each app from source (apps/<dir>) and
#      replaces the running container image in place.
# The container image attribute is ignored on subsequent applies so that
# re-running Terraform never rolls a live service back to the placeholder
# digest pinned in var.container_image.
#
# INGRESS / AUTH POSTURE (matches `make deploy` exactly):
#   - ingress stays INGRESS_TRAFFIC_ALL because (a) Pub/Sub push delivery to
#     the worker does not traverse a load balancer and is rejected by
#     restricted ingress, and (b) external demo/console clients call the
#     control plane and gateway directly. Tightening requires a Serverless
#     NEG + load balancer fronting each service first.
#   - No public unauthenticated access: no allUsers run.invoker grant exists;
#     every caller needs an authorized identity (OIDC push tokens for
#     Pub/Sub, user/service identities for direct calls).
resource "google_cloud_run_v2_service" "main" {
  # toset() so each.key/each.value are the service NAME (not a list index),
  # matching the var.container_image map keys and SA for_each keys.
  for_each = toset(local.services)

  name                = each.value
  location            = var.region
  deletion_protection = false # hackathon env is disposable (§13)
  ingress             = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.services[each.value].email
    timeout         = each.value == "worker" ? "300s" : "60s"

    scaling {
      max_instance_count = each.value == "execution-gateway" ? 3 : 2
    }

    containers {
      image = var.container_image[each.value]

      resources {
        limits = {
          cpu    = "1000m"
          memory = "512Mi"
        }
      }

      dynamic "env" {
        for_each = merge(local.env_common, lookup(local.env_per_service, each.key, {}))
        content {
          name  = env.key
          value = env.value
        }
      }

      # ERP postgres wiring is intentionally NOT enabled yet: this environment
      # provisions neither Cloud SQL nor Secret Manager, so there is nothing
      # real to reference. When both exist, wire it like:
      #
      # env {
      #   name = "DF_ERP_BACKEND"
      #   value = "postgres"
      # }
      # env {
      #   name      = "DATABASE_URL"
      #   value_source {
      #     secret_key_ref {
      #       secret  = google_secret_manager_secret.database_url.name
      #       version = "latest"
      #     }
      #   }
      # }
    }
  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image]
  }

  depends_on = [
    google_firestore_database.default,
    google_project_iam_member.worker_run_invoker,
  ]
}

output "cloud_run_urls" {
  value       = { for s, svc in google_cloud_run_v2_service.main : s => svc.uri }
  description = "Cloud Run service URLs; feed DF_CONTROL_PLANE_URL / DF_EXECUTION_GATEWAY_URL."
}
