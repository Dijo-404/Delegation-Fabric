# API Contracts

These are Delegation Fabric application APIs, not Google Cloud APIs.

All internal Cloud Run services require authenticated callers. JSON examples omit transport authentication for readability.

---

## 1. Common conventions

Base prefix:

```text
/v1
```

Content type:

```text
application/json
```

IDs:

```text
dlg_<ulid>
task_<ulid>
grt_<ulid>
apr_<ulid>
evt_<ulid>
aud_<ulid>
```

Timestamps:

```text
RFC3339 UTC
```

Currency:

```text
ISO-4217 code + integer minor units
```

Never use floating-point money.

---

## 2. Error envelope

```json
{
  "error": {
    "code": "ARGUMENT_CONSTRAINT_FAILED",
    "message": "Requested action is not authorized.",
    "request_id": "req_01...",
    "details": {
      "path": "amount_minor",
      "constraint": "lte"
    }
  }
}
```

User-facing clients should rely on `code`, not parse `message`.

Do not expose raw policy internals, secrets or stack traces.

---

## 3. Create delegation

```http
POST /v1/delegations
```

Request:

```json
{
  "purpose": "weekly_vendor_settlement",
  "task_id": "task_1001",
  "allowed_agents": [
    "invoice-reconciliation",
    "procurement-exception",
    "treasury-approval"
  ],
  "allowed_regions": ["asia-south1"],
  "expires_at": "2026-09-03T05:30:00Z"
}
```

The sponsor identity comes from authenticated user context, not from a trusted request-body string.

Response `201`:

```json
{
  "delegation_id": "dlg_...",
  "sponsor": "user:priya@example.com",
  "purpose": "weekly_vendor_settlement",
  "status": "active",
  "policy_version": "finance-policy-2026-08-20.1",
  "created_at": "...",
  "expires_at": "..."
}
```

---

## 4. Revoke delegation

```http
POST /v1/delegations/{delegation_id}/revoke
```

Request:

```json
{
  "reason": "workflow_cancelled"
}
```

Semantics:

- future grant issuance fails;
- already-issued but unconsumed grants should be rejected by Execution Gateway after current delegation status check;
- audit event appended.

---

## 5. Evaluate/issue grant

```http
POST /v1/grants/evaluate
```

Request:

```json
{
  "task_id": "task_1001",
  "delegation_id": "dlg_01",
  "agent": {
    "id": "treasury-approval",
    "version": "1.0.3"
  },
  "tool": "payment.instruct",
  "arguments": {
    "batch_id": "PB-88",
    "amount_minor": 74200000,
    "currency": "INR"
  }
}
```

Caller agent identity must be validated independently from body claims where platform identity is available.

Allowed response `201`:

```json
{
  "decision": "allow",
  "grant_id": "grt_01",
  "token": "<compact-jws>",
  "expires_at": "2026-08-24T08:46:00Z",
  "policy_version": "finance-policy-2026-08-20.1"
}
```

Denied response `403`:

```json
{
  "decision": "deny",
  "reason_code": "APPROVAL_REQUIRED",
  "request_id": "req_01"
}
```

Do not mint a token on deny.

---

## 6. Execute protected action

```http
POST /v1/execute
Authorization: Bearer <Execution Grant>
```

Request:

```json
{
  "tool": "payment.instruct",
  "arguments": {
    "batch_id": "PB-88",
    "amount_minor": 74200000,
    "currency": "INR"
  }
}
```

Success:

```json
{
  "grant_id": "grt_01",
  "tool": "payment.instruct",
  "result": {
    "payment_id": "pay_88",
    "status": "accepted",
    "processed_at": "2026-08-24T08:42:10Z"
  }
}
```

Forbidden fields are never included even if the downstream adapter returns them.

---

## 7. Create approval

```http
POST /v1/approvals
```

Request:

```json
{
  "task_id": "task_1001",
  "delegation_id": "dlg_01",
  "approval_type": "payment_batch",
  "subject": {
    "batch_id": "PB-88",
    "amount_minor": 74200000,
    "currency": "INR"
  },
  "decision": "approved"
}
```

Approver identity comes from authenticated user context.

Response:

```json
{
  "approval_id": "apr_44",
  "approver": "user:arun@example.com",
  "decision": "approved",
  "created_at": "...",
  "expires_at": "..."
}
```

The handler publishes `approval.created` after durable write.

---

## 8. Read task

```http
GET /v1/tasks/{task_id}
```

Response:

```json
{
  "task_id": "task_1001",
  "delegation_id": "dlg_01",
  "state": "awaiting_approval",
  "session_id": "session_...",
  "agent": "procurement-exception@1.0.0",
  "version": 4,
  "latest_checkpoint_id": "chk_04",
  "updated_at": "..."
}
```

`version` is a workflow concurrency/version field, not agent version.

---

## 9. Release quarantine

```http
POST /v1/tasks/{task_id}/release
```

Requires authorized human actor.

Request:

```json
{
  "expected_state": "quarantined",
  "reason": "document manually reviewed"
}
```

Use optimistic state/version validation.

---

## 10. Event receiver

Worker endpoint:

```http
POST /internal/events/pubsub
```

After decoding Pub/Sub wrapper, validate:

```json
{
  "event_id": "evt_...",
  "event_type": "approval.created",
  "task_id": "task_1001",
  "occurred_at": "...",
  "source": "control-plane",
  "schema_version": "1",
  "data": {
    "approval_id": "apr_44"
  }
}
```

Return 2xx only when:

- duplicate safely recognized; or
- transition/resumption result is durably checkpointed.

Return retryable non-2xx for transient infrastructure errors.

---

## 11. Registry read facade

Optional application facade for the console:

```http
GET /v1/agents
GET /v1/agents/{agent_id}/versions/{version}
```

Do not make this a competing registry. It should read from Agent Registry or a read-through cache.

---

## 12. Audit API

```http
GET /v1/audit/tasks/{task_id}
GET /v1/audit/tasks/{task_id}/verify
```

Verification response:

```json
{
  "task_id": "task_1001",
  "valid": true,
  "events": 61,
  "first_invalid_index": null,
  "head_hash": "sha256:..."
}
```

---

## 13. API security rules

- reject unknown JSON fields on privileged write APIs where practical;
- request body size limits;
- timeouts on all outbound calls;
- no raw JWS tokens in normal logs;
- redact personal/sensitive data in audit display;
- use server-derived authenticated identities;
- rate limit human-facing mutation endpoints;
- require CSRF-safe/session-safe console design;
- use OIDC/IAM for service-to-service Cloud Run calls.
