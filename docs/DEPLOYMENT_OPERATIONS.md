# Deployment and Operations

This document defines the Google Cloud deployment, IAM, networking, configuration and operational requirements.

---

## 1. Terraform modules

Recommended:

```text
infra/modules/
  project_services/
  service_accounts/
  kms/
  firestore/
  cloud_sql/
  pubsub/
  cloud_run_service/
  storage_audit/
  monitoring/
  agent_platform/
```

Environment:

```text
infra/environments/hackathon/
```

Do not mix seed data with Terraform resources.

---

## 2. APIs

Enable only needed APIs, including relevant Agent Platform, Agent Registry, Cloud Run, Firestore, KMS, Pub/Sub, Cloud SQL, Storage, Logging/Monitoring/Trace and Model Armor services.

Keep the exact list generated from the working deployment rather than copying an unverified example forever.

---

## 3. Service accounts

Suggested:

```text
df-control-plane@...
df-execution-gateway@...
df-worker@...
df-console@...
df-deployer@...
```

Agent Runtime uses the platform's agent identity/service identity model as configured.

Each service gets minimum roles.

---

## 4. Cloud Run services

```text
control-plane
execution-gateway
worker
console
```

Configuration:

- min instances: 0 for hackathon cost;
- bounded max instances;
- concurrency tuned conservatively;
- request timeout appropriate per service;
- internal/authenticated where possible;
- dedicated service identity;
- structured JSON logs.

Worker push endpoint must accept only Pub/Sub authenticated delivery identity.

---

## 5. Cloud KMS

Key:

```text
key ring: delegation-fabric
key: execution-grant-signing
purpose: ASYMMETRIC_SIGN
algorithm: EC_SIGN_P256_SHA256
location: asia-south1
```

Only Control Plane signer identity receives signing permission.

Execution Gateway fetches/caches public key material.

Key rotation:

- `kid` references exact key version;
- verifier supports current + prior still-valid versions;
- new grants use primary/latest configured version.

---

## 6. Firestore

Use for:

- delegations;
- grants;
- approvals;
- tasks;
- checkpoints;
- event receipts;
- audit chain metadata.

Create only required indexes.

Use transactions for:

- grant consumption;
- event reservation/receipt;
- critical task state transition.

---

## 7. Cloud SQL

Use private/narrow application connectivity.

Separate:

- migration/admin principal;
- runtime read roles;
- runtime write roles;
- treasury execution role.

No service gets database superuser.

---

## 8. Pub/Sub

Topics:

```text
delegation_fabric.tasks
delegation_fabric.approvals
delegation_fabric.webhooks
delegation_fabric.deadletter
```

Push subscriptions:

- OIDC-authenticated;
- retry policy;
- dead-letter policy;
- application event idempotency.

Do not enable/document exactly-once for push.

### Topic rename migration (2026-08-26)

Commit `08c3dc5` ("align pubsub topic naming across terraform publisher and
docs") renamed the Pub/Sub topology from underscore style to the canonical
dotted style:

```text
delegation_fabric_tasks   → delegation_fabric.tasks
delegation_fabric_approvals → delegation_fabric.approvals
delegation_fabric_webhooks  → delegation_fabric.webhooks
<topic>_dlq               → <topic>.dlq
<topic>-push              → <topic>.push
```

Pub/Sub resource names are immutable: Terraform treats these renames as
destroy + recreate. Consequences:

- undelivered messages on old topics/subscriptions are lost;
- push subscriptions are recreated, so delivery pauses until re-applied;
- publishers using old names fail until redeployed against new names.

Migration path (applied for this environment):

1. Confirm no in-flight traffic: hackathon/demo only, no production queues.
2. Redeploy publishers/services so code builds dotted topic ids (already the
   case in `packages/delegation_fabric_adapters`).
3. `make infra` (`terraform apply`) destroys old topics/DLQs/push subs and
   creates the dotted equivalents; DLQ service-agent IAM is unaffected.
4. Smoke test one task end-to-end before demo use.

Assumption of record: no in-flight traffic existed at migration time.

---

## 9. Configuration

Example environment variables:

```text
GOOGLE_CLOUD_PROJECT
GOOGLE_CLOUD_LOCATION=asia-south1

DF_ENV=hackathon
DF_CONTROL_PLANE_URL
DF_EXECUTION_GATEWAY_URL
DF_CONSOLE_URL

DF_KMS_KEY_VERSION
DF_GRANT_ISSUER
DF_GRANT_AUDIENCE
DF_GRANT_TTL_SECONDS=300
DF_CLOCK_SKEW_SECONDS=30

DF_MODEL_ID=gemini-3.5-flash
DF_SEMANTIC_GOVERNANCE_MODE=dry_run
DF_MODEL_ARMOR_TEMPLATE=...

DF_CLOUD_SQL_INSTANCE
DF_DB_NAME
```

Secrets belong in Secret Manager or managed identity mechanisms; do not put credentials into `.env.example`.

---

## 10. Deployment order

```text
1 project/APIs
2 service accounts
3 KMS
4 Firestore
5 Cloud SQL + schema/grants
6 Pub/Sub
7 Cloud Run control plane/gateway/worker
8 Agent Platform/Registry/Gateway
9 agents
10 console
11 seed
12 smoke tests
```

---

## 11. Observability

### Logs

Structured fields:

```text
severity
service
trace_id
request_id
task_id
delegation_id
grant_id
agent_id
agent_version
tool
decision
reason_code
duration_ms
```

### Traces

Useful spans:

```text
grant.evaluate
policy.resolve_manifest
policy.evaluate_constraints
kms.sign
grant.verify
grant.consume
adapter.execute
response.project
event.reserve
runtime.resume
```

### Metrics

```text
df/grants/issued_count
df/grants/denied_count
df/grants/replay_count
df/gateway/execute_latency
df/tasks/state_transition_count
df/events/duplicate_count
df/tasks/quarantine_count
df/adapter/error_count
```

---

## 12. SLO-style demo targets

Not production commitments; useful engineering targets:

```text
grant evaluation p95 < 500 ms excluding external semantic checks
gateway verification overhead p95 < 250 ms excluding tool execution
duplicate event side effects = 0
replayed grant side effects = 0
forbidden-field leakage = 0
```

Record actual demo measurements instead of claiming these if not measured.

---

## 13. Cost controls

- min instances zero;
- smallest reasonable Cloud SQL;
- budget alerts;
- bounded max instances;
- delete temporary infrastructure after submission if no longer needed;
- avoid provisioned throughput for hackathon unless required.

---

## 14. Operational runbook

### KMS unavailable

- deny grant issuance;
- do not fall back to unsigned tokens.

### Firestore unavailable during grant consumption

- deny execution;
- retry later with a fresh grant if original was not consumed.

### Cloud SQL unavailable

- mark tool attempt transient failure;
- no broad retry loop for mutating operation without idempotency.

### Model Armor unavailable

Decision depends on configured policy:

- fail closed for sensitive surfaces; or
- advisory bypass only if explicitly documented for demo.

Delegation Fabric deterministic authorization still runs.

### Semantic Governance unavailable

If configured as required enforcement, deny.
If configured as dry-run companion, continue deterministic authorization and record unavailable status.

---

## 15. Platform verification notes

At implementation time confirm current official documentation for:

- Agent Platform region support;
- Agent Registry registration behavior;
- Agent Gateway requirements;
- Model Armor regional endpoints;
- Semantic Governance launch stage/limitations;
- model serving locations.

Keep these as dated decisions in `docs/DECISIONS.md`.
