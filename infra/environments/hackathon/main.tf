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

locals {
  services = ["control-plane", "execution-gateway", "worker"]
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

variable "worker_push_endpoint" {
  type        = string
  description = "Worker Cloud Run URL used as the Pub/Sub push endpoint."
}

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
