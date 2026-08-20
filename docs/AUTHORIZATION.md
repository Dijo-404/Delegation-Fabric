# Authorization Model

This document defines Delegations, Execution Grants, deterministic policy evaluation, approvals, separation of duties and reason codes.

---

## 1. Delegation

A Delegation is long-lived authorization context created by an authenticated human sponsor.

Example:

```json
{
  "delegation_id": "dlg_01HX...",
  "sponsor": {
    "subject": "user:priya@example.com",
    "display_name": "Priya",
    "department": "finance"
  },
  "purpose": "weekly_vendor_settlement",
  "task_id": "task_1001",
  "allowed_agents": [
    "invoice-reconciliation",
    "procurement-exception",
    "treasury-approval"
  ],
  "allowed_regions": ["asia-south1"],
  "policy_version": "finance-policy-2026-08-20.1",
  "created_at": "2026-08-20T05:30:00Z",
  "expires_at": "2026-09-03T05:30:00Z",
  "status": "active"
}
```

A Delegation authorizes a workflow context. It does **not** authorize a specific side effect.

---

## 2. Execution Grant

An Execution Grant authorizes one protected action.

Recommended claims:

```json
{
  "jti": "grt_01HX...",
  "iss": "delegation-fabric-control-plane",
  "aud": "delegation-fabric-execution-gateway",

  "delegation_id": "dlg_...",
  "task_id": "task_...",

  "agent_id": "treasury-approval",
  "agent_version": "1.0.3",

  "human_sponsor": "user:priya@example.com",
  "purpose": "weekly_vendor_settlement",

  "tool": "payment.instruct",
  "arg_constraints": [
    {"path": "batch_id", "op": "eq", "value": "PB-88"},
    {"path": "amount_minor", "op": "lte", "value": 74200000},
    {"path": "currency", "op": "eq", "value": "INR"}
  ],

  "allowed_response_fields": [
    "payment_id",
    "status",
    "processed_at"
  ],

  "approval_ids": ["apr_44"],
  "region": "asia-south1",
  "policy_version": "finance-policy-2026-08-20.1",

  "single_use": true,
  "iat": 1787202000,
  "nbf": 1787202000,
  "exp": 1787202300
}
```

Recommended JWS header:

```json
{
  "alg": "ES256",
  "typ": "DFG+JWT",
  "kid": "projects/.../cryptoKeyVersions/3"
}
```

Cloud KMS uses `EC_SIGN_P256_SHA256`; JWS representation must be implemented carefully because KMS returns an ECDSA signature representation that must match the JWS library expectations. Keep this conversion isolated and unit-tested with known vectors.

---

## 3. Why grants are narrow

A grant must fail if the caller changes any material authorization dimension:

```text
tool
agent/version
task
delegation
region
approval
arguments outside constraints
time window
single-use state
```

A signed grant is not a permission to improvise. It is proof that one exact class of action was approved.

---

## 4. Constraint model

```python
class Constraint(BaseModel):
    path: str
    op: ConstraintOp
    value: JsonValue | None = None
```

Supported operations:

| Operator | Meaning |
| --- | --- |
| `eq` | exact equality |
| `neq` | inequality |
| `in` | scalar must be member of allow-list |
| `not_in` | scalar must not be member |
| `lt/lte/gt/gte` | typed numeric or temporal comparisons |
| `prefix` | string prefix |
| `subset_of` | list/set is subset of allow-list |
| `matches` | bounded regex |
| `exists` | required path existence |

### Path rules

Use dotted paths:

```text
amount_minor
vendor.id
recipients.0.domain
metadata.classification
```

Do not support arbitrary JSONPath expressions for the hackathon build. Keep the evaluator small and testable.

### Type behavior

Authorization fails closed on type mismatch.

Example:

```text
constraint: amount_minor <= 100000
input:      amount_minor = "100000"
result:     DENY type_mismatch
```

Do not coerce authorization values.

---

## 5. Purpose policy

Purpose policy is deterministic configuration.

Example:

```yaml
purposes:
  invoice_reconciliation:
    agents:
      invoice-reconciliation:
        tools:
          invoice.read:
            allowed_fields:
              - invoice_id
              - vendor_id
              - po_id
              - total_minor
              - currency
              - status
          purchase_order.read:
            allowed_fields:
              - po_id
              - vendor_id
              - total_minor
              - currency
              - status
          reconciliation.write: {}

  weekly_vendor_settlement:
    agents:
      treasury-approval:
        tools:
          payment.instruct:
            requires_approval: true
            sod:
              approver_must_differ_from:
                - delegation_sponsor
                - originating_exception_actor
```

This policy determines whether a grant may be minted. It should be versioned and immutable after publication.

---

## 6. Semantic Governance integration

Semantic Governance can evaluate user intent and natural-language business constraints.

Use it as:

```text
additional evidence / precondition
```

not as the only source of transaction authorization.

Suggested logic:

```python
if semantic_policy_enforced and semantic_verdict != "ALLOW":
    deny(SEMANTIC_POLICY_DENIED)

decision = deterministic_policy.evaluate(...)
if not decision.allowed:
    deny(decision.reason)

issue_grant(...)
```

If semantic governance is in dry-run mode:

- record verdict/rationale metadata;
- do not let it override deterministic authorization.

Never copy raw sensitive policy rationales into user-visible responses.

---

## 7. Approval Record

Example:

```json
{
  "approval_id": "apr_44",
  "task_id": "task_1001",
  "delegation_id": "dlg_01",
  "approval_type": "payment_batch",
  "subject": {
    "batch_id": "PB-88",
    "amount_minor": 74200000,
    "currency": "INR"
  },
  "decision": "approved",
  "approver": "user:arun@example.com",
  "created_at": "2026-08-24T08:41:12Z",
  "expires_at": "2026-08-24T12:41:12Z",
  "policy_version": "finance-policy-2026-08-20.1"
}
```

Approval must bind to the subject being acted upon.

Do not accept a generic `"approved": true` flag.

---

## 8. Separation of duties

Example policy:

```text
payment approver != delegation sponsor
payment approver != exception creator
payment approver belongs to finance-approvers
```

The exact hackathon rule may be simplified, but it must be structurally enforced.

Decision inputs:

```text
delegation sponsor
current agent identity/version
delegation chain
originating agent/human
approval actor
approval subject
tool
```

---

## 9. Agent-to-agent authority

A child agent invocation inherits a constrained context.

Recommended `DelegationContext`:

```json
{
  "root_delegation_id": "dlg_01",
  "parent_task_id": "task_1001",
  "parent_agent": "invoice-reconciliation@1.2.0",
  "child_agent": "procurement-exception@1.0.0",
  "purpose": "invoice_reconciliation",
  "authority_ceiling": [
    "vendor.read",
    "exception.write"
  ]
}
```

Rule:

```text
child authority <= parent delegation ceiling AND child manifest
```

Never union capabilities across agents.

---

## 10. Grant lifecycle

```text
requested
  |
  +--> denied
  |
  +--> issued
          |
          +--> expired
          |
          +--> consumed
                   |
                   +--> execution_succeeded
                   |
                   +--> execution_failed
                   |
                   +--> outcome_unknown
```

`consumed` is terminal for reuse.

---

## 11. Consumption transaction

Firestore pseudocode:

```python
@firestore.transactional
def consume_grant(tx, grant_ref, now):
    doc = grant_ref.get(transaction=tx)

    if not doc.exists:
        raise GrantUnknown()

    if doc["status"] != "issued":
        raise GrantReplay()

    if doc["expires_at"] <= now:
        raise GrantExpired()

    tx.update(
        grant_ref,
        {
            "status": "consumed",
            "consumed_at": now,
        },
    )
```

Use a unique grant document ID. Never implement replay protection as an in-memory cache.

---

## 12. Reason codes

Closed enum, examples:

```text
DELEGATION_NOT_FOUND
DELEGATION_REVOKED
DELEGATION_EXPIRED
TASK_NOT_BOUND_TO_DELEGATION
AGENT_NOT_ALLOWED
AGENT_VERSION_NOT_ALLOWED
CAPABILITY_NOT_DECLARED
OUTSIDE_BUSINESS_PURPOSE
ARGUMENT_CONSTRAINT_FAILED
ARGUMENT_TYPE_MISMATCH
RESPONSE_FIELD_NOT_ALLOWED
APPROVAL_REQUIRED
APPROVAL_NOT_FOUND
APPROVAL_EXPIRED
APPROVAL_SUBJECT_MISMATCH
SEPARATION_OF_DUTIES_VIOLATION
REGION_NOT_ALLOWED
SEMANTIC_POLICY_DENIED
GRANT_INVALID_SIGNATURE
GRANT_INVALID_AUDIENCE
GRANT_NOT_YET_VALID
GRANT_EXPIRED
GRANT_REPLAYED
GRANT_TOOL_MISMATCH
GRANT_AGENT_MISMATCH
GRANT_TASK_MISMATCH
GRANT_REGION_MISMATCH
```

Internal error details may be richer, but external APIs should return a stable code.

---

## 13. Authorization test matrix

Every protected tool requires tests for:

```text
allowed exact case
boundary case
out-of-range
wrong type
unknown field
wrong agent
wrong version
wrong task
revoked delegation
expired delegation
missing approval
wrong approver
expired approval
wrong region
tampered grant
expired grant
replayed grant
```
