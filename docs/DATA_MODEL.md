# Data Model

Delegation Fabric uses Firestore for workflow/authorization metadata and Cloud SQL PostgreSQL for the simulated ERP.

---

## 1. Firestore collections

Recommended collections:

```text
delegations/{delegation_id}
tasks/{task_id}
tasks/{task_id}/checkpoints/{checkpoint_id}
grants/{grant_id}
approvals/{approval_id}
event_receipts/{event_id}
audit_streams/{task_id}/events/{event_id}
agent_authz_cache/{agent_version_key}
policy_versions/{policy_version}
```

Avoid using Firestore as the ERP.

---

## 2. Delegation document

```json
{
  "sponsor_subject": "user:priya@example.com",
  "purpose": "weekly_vendor_settlement",
  "task_id": "task_1001",
  "allowed_agents": ["..."],
  "allowed_regions": ["asia-south1"],
  "policy_version": "finance-policy-2026-08-20.1",
  "status": "active",
  "created_at": "...",
  "expires_at": "...",
  "revoked_at": null,
  "revoked_by": null
}
```

Indexes:

```text
status + expires_at
sponsor_subject + created_at
task_id
```

---

## 3. Task document

```json
{
  "delegation_id": "dlg_01",
  "state": "awaiting_approval",
  "state_version": 4,
  "current_agent_id": "procurement-exception",
  "current_agent_version": "1.0.0",
  "session_id": "session_...",
  "latest_checkpoint_id": "chk_04",
  "policy_version": "finance-policy-2026-08-20.1",
  "created_at": "...",
  "updated_at": "..."
}
```

`state_version` is incremented on each valid transition and used for optimistic concurrency.

---

## 4. Checkpoint document

```json
{
  "checkpoint_id": "chk_04",
  "state": "awaiting_approval",
  "state_version": 4,
  "session_id": "session_...",
  "agent_id": "procurement-exception",
  "agent_version": "1.0.0",
  "memory_refs": ["mem_1", "mem_2"],
  "pending_subject": {
    "exception_id": "exc_12"
  },
  "created_at": "..."
}
```

Do not store:

- active JWS tokens;
- KMS private material;
- database passwords;
- chain-of-thought.

---

## 5. Grant document

```json
{
  "grant_id": "grt_01",
  "delegation_id": "dlg_01",
  "task_id": "task_1001",
  "agent_id": "treasury-approval",
  "agent_version": "1.0.3",
  "tool": "payment.instruct",
  "status": "issued",
  "issued_at": "...",
  "expires_at": "...",
  "consumed_at": null,
  "policy_version": "..."
}
```

Use Firestore transaction to change:

```text
issued -> consumed
```

No reverse transition.

TTL may clean old grant metadata later, but TTL deletion is asynchronous and must never be part of correctness or replay protection.

---

## 6. Event receipt

```json
{
  "event_id": "evt_...",
  "event_type": "approval.created",
  "task_id": "task_1001",
  "status": "complete",
  "first_seen_at": "...",
  "completed_at": "...",
  "attempt_count": 1
}
```

Stable `event_id` comes from the publisher's application event, not Pub/Sub delivery attempt.

A duplicate publish with a different application `event_id` is a new logical event; design publishers to reuse event IDs across publish retries.

---

## 7. Approval document

```json
{
  "task_id": "task_1001",
  "delegation_id": "dlg_01",
  "type": "payment_batch",
  "subject_hash": "sha256:...",
  "subject": {
    "batch_id": "PB-88",
    "amount_minor": 74200000,
    "currency": "INR"
  },
  "decision": "approved",
  "approver_subject": "user:arun@example.com",
  "created_at": "...",
  "expires_at": "..."
}
```

Subject hash allows exact comparison and compact audit references.

---

## 8. Audit event

Minimum:

```json
{
  "audit_event_id": "aud_...",
  "task_id": "task_1001",
  "delegation_id": "dlg_01",
  "grant_id": "grt_01",
  "actor": {
    "type": "agent",
    "id": "treasury-approval",
    "version": "1.0.3"
  },
  "event_type": "tool.execution.completed",
  "tool": "payment.instruct",
  "decision": "allow",
  "reason_code": null,
  "policy_version": "...",
  "approval_ids": ["apr_44"],
  "resource_refs": ["payment:pay_88"],
  "occurred_at": "...",
  "prev_hash": "sha256:...",
  "event_hash": "sha256:..."
}
```

Large payloads/documents belong in object storage or source systems; audit event contains stable references and content hashes.

---

## 9. PostgreSQL ERP schema

Suggested minimum:

```sql
CREATE TABLE vendors (
    vendor_id text PRIMARY KEY,
    legal_name text NOT NULL,
    status text NOT NULL,
    country_code char(2) NOT NULL
);

CREATE TABLE purchase_orders (
    po_id text PRIMARY KEY,
    vendor_id text NOT NULL REFERENCES vendors(vendor_id),
    total_minor bigint NOT NULL CHECK (total_minor >= 0),
    currency char(3) NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE invoices (
    invoice_id text PRIMARY KEY,
    vendor_id text NOT NULL REFERENCES vendors(vendor_id),
    po_id text REFERENCES purchase_orders(po_id),
    total_minor bigint NOT NULL CHECK (total_minor >= 0),
    currency char(3) NOT NULL,
    status text NOT NULL,
    document_uri text,
    created_at timestamptz NOT NULL
);

CREATE TABLE invoice_lines (
    invoice_id text NOT NULL REFERENCES invoices(invoice_id),
    line_no integer NOT NULL,
    description text NOT NULL,
    quantity numeric(18,4) NOT NULL,
    unit_price_minor bigint NOT NULL,
    PRIMARY KEY (invoice_id, line_no)
);

CREATE TABLE vendor_bank_accounts (
    vendor_id text PRIMARY KEY REFERENCES vendors(vendor_id),
    account_name text NOT NULL,
    account_number text NOT NULL,
    bank_code text NOT NULL
);

CREATE TABLE reconciliations (
    reconciliation_id text PRIMARY KEY,
    invoice_id text NOT NULL REFERENCES invoices(invoice_id),
    task_id text NOT NULL,
    result text NOT NULL,
    variance_minor bigint NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE exceptions (
    exception_id text PRIMARY KEY,
    invoice_id text NOT NULL REFERENCES invoices(invoice_id),
    task_id text NOT NULL,
    severity text NOT NULL,
    reason text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE payment_batches (
    batch_id text PRIMARY KEY,
    task_id text NOT NULL,
    total_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE payments (
    payment_id text PRIMARY KEY,
    batch_id text NOT NULL REFERENCES payment_batches(batch_id),
    grant_id text NOT NULL UNIQUE,
    status text NOT NULL,
    created_at timestamptz NOT NULL
);
```

`payments.grant_id UNIQUE` provides downstream idempotency backstop.

---

## 10. Database roles

Example concept:

```sql
CREATE ROLE df_invoice_reader NOLOGIN;
CREATE ROLE df_reconciliation_writer NOLOGIN;
CREATE ROLE df_treasury_executor NOLOGIN;
```

Grant only necessary table/column operations.

Important:

- reconciliation path gets no bank-account access;
- treasury path gets only fields required for payment operation;
- no generic superuser role in the application;
- migrations use a separate deploy-time principal.

Prefer views or stored procedures when that produces a narrower resource contract.

---

## 11. Money and numeric rules

- store minor units in `bigint`;
- `INR 742000.00` -> `74200000`;
- no float;
- currency always explicit;
- check same-currency comparisons;
- amount constraints operate on integer minor units.

---

## 12. Retention

Suggested:

```text
grants: short operational retention, e.g. 30 days
event receipts: >= maximum replay/retry window, e.g. 30 days
task/checkpoints: hackathon/demo retention
approvals: retained with audit evidence
audit export: retention-locked object storage for demo
```

Firestore TTL is cleanup, not transaction logic.

---

## 13. Indexing rules

Index query dimensions actually used by console/worker.

Avoid indexing high-churn monotonic timestamp fields unless required; add single-field exemptions where appropriate, especially TTL-only fields.

No broad speculative composite-index matrix before real queries exist.
