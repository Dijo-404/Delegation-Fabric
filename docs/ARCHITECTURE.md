# Architecture

This document defines the runtime architecture, trust boundaries and component responsibilities for Delegation Fabric.

---

## 1. Architectural intent

The system separates four concerns:

1. **Agent reasoning** — probabilistic model/runtime behavior.
2. **Platform governance** — identity, registry, routing, semantic checks and prompt/response security.
3. **Transaction authorization** — deterministic Delegation Fabric rules and signed grants.
4. **Resource enforcement** — narrow database/IAM permissions and idempotent side-effect adapters.

No single layer is treated as sufficient.

---

## 2. Trust boundaries

```text
TB-1 Human/browser boundary
TB-2 Console -> Control Plane
TB-3 Agent Runtime -> platform Agent Gateway
TB-4 Platform gateway -> Delegation Fabric Control Plane
TB-5 Agent/tool client -> Delegation Fabric Execution Gateway
TB-6 Execution Gateway -> protected resource
TB-7 Worker -> task/event stores
TB-8 Audit export -> retention storage
```

### Trust assumptions

Trusted:

- Cloud KMS signing key boundary
- Control Plane deterministic policy code
- Execution Gateway verification code
- Firestore transaction semantics
- database privilege configuration
- Google-signed service identity/OIDC tokens

Potentially compromised/untrusted:

- model output
- supplier documents
- prompts retrieved from external data
- agent tool selection
- cross-agent messages
- Pub/Sub duplicate deliveries
- caller-supplied tool arguments

---

## 3. Components

### 3.1 Console

Responsibilities:

- create/revoke delegations;
- display agent metadata;
- display tasks/checkpoints;
- collect human approvals;
- render audit graph;
- render security denials.

Not responsible for:

- making authorization decisions;
- signing grants;
- directly calling protected resources.

### 3.2 Control Plane

Responsibilities:

- authenticate caller;
- resolve delegation;
- resolve task;
- resolve agent manifest;
- evaluate deterministic rules;
- validate approvals/SOD;
- optionally consume semantic-governance evidence;
- create canonical grant claims;
- call KMS to sign;
- write authorization audit event.

Failure mode: deny closed.

### 3.3 Google Agent Gateway

Responsibilities are platform-level:

- agent identity;
- IAM;
- routing;
- Model Armor integration;
- Semantic Governance integration;
- policy-driven tool connectivity.

Do not confuse this resource with Delegation Fabric's Execution Gateway.

### 3.4 Delegation Fabric Execution Gateway

Responsibilities:

- validate service caller identity;
- parse grant;
- resolve `kid`;
- verify signature;
- validate time;
- validate binding;
- transactionally consume;
- re-evaluate arguments;
- dispatch to registered adapter;
- project response;
- emit audit/telemetry.

It is the final application authorization boundary before the production action.

### 3.5 Worker

Responsibilities:

- receive Pub/Sub push;
- validate event envelope;
- perform idempotency receipt transaction;
- validate state transition;
- rehydrate task/session;
- resume agent;
- write new checkpoint.

### 3.6 Agent Runtime

Responsibilities:

- model execution;
- session continuity;
- tool calling;
- multi-agent orchestration;
- memory-service integration.

It never stores unrestricted production credentials.

### 3.7 Resource adapters

Examples:

```text
invoice.read
purchase_order.read
reconciliation.write
vendor.read
exception.write
payment_batch.read
payment.instruct
email.send
```

Each adapter has:

- typed request schema;
- typed response schema;
- timeout;
- idempotency behavior;
- audit classification;
- least-privilege credential.

---

## 4. Synchronous protected call sequence

```text
Agent
  |
  | 1. tool proposal
  v
Google Agent Gateway
  |
  | 2. IAM / armor / optional semantic policy
  v
Tool client
  |
  | 3. grant evaluation request
  v
Control Plane
  |
  | 4. deterministic ALLOW
  | 5. KMS sign
  v
Tool client
  |
  | 6. execute(grant, tool, args)
  v
Execution Gateway
  |
  | 7. verify + consume
  | 8. adapter
  v
Protected resource
  |
  | 9. response
  v
Execution Gateway
  |
  | 10. field projection
  | 11. audit
  v
Agent
```

---

## 5. Grant issuance sequence

Inputs:

```text
caller identity
task_id
agent_id
agent_version
tool
arguments
current region
delegation
approval state
agent manifest
policy version
semantic verdict evidence (optional)
```

Decision phases:

```text
Phase A: identity and object existence
Phase B: delegation active
Phase C: task/delegation binding
Phase D: agent/version allowed
Phase E: capability allowed
Phase F: purpose allows tool
Phase G: deterministic argument constraints
Phase H: approval requirement
Phase I: separation of duties
Phase J: region and resource scope
Phase K: grant construction/signing
```

Every phase yields a closed reason code on failure.

---

## 6. Execution verification order

Verification order is security-sensitive:

```text
1  caller authentication
2  token syntax/header
3  key id allowed
4  signature valid
5  issuer/audience
6  nbf/iat/exp
7  deployment region
8  delegation/task active
9  agent/version binding
10 exact tool binding
11 single-use consumption
12 actual argument constraints
13 adapter execution
14 response projection
15 audit finalization
```

Why consume before execution?

A resumed/retried workflow cannot reuse the same authorization to repeat a side effect.

Trade-off:

- provides at-most-once grant use;
- does not by itself prove the downstream business operation completed exactly once.

Downstream mutating adapters therefore receive `grant_id` as idempotency key.

---

## 7. Asynchronous sequence

```text
Task -> awaiting_approval
        |
        v
Human approval
        |
        v
Control Plane writes ApprovalRecord
        |
        v
Pub/Sub event
        |
        v
Cloud Run worker
        |
        +--> dedupe event_id
        +--> validate transition
        +--> load checkpoint/session
        +--> resume agent
        +--> fresh grant for next action
        |
        v
Task -> running/completed
```

Push events are at-least-once; duplicate-safe application processing is mandatory.

---

## 8. Service-to-service authentication

Every Cloud Run service uses a dedicated service account.

Recommended call graph:

```text
console-backend SA -> control-plane
worker SA          -> control-plane
agent tool proxy   -> control-plane / execution-gateway
control-plane SA   -> Firestore + KMS + Registry read
gateway SA         -> Firestore + narrow Cloud SQL role/adapters
```

Cloud Run services should remain authenticated. Callers present Google-signed OIDC ID tokens with the receiving service as audience.

Do not grant `roles/run.invoker` project-wide when a per-service binding is sufficient.

---

## 9. Network architecture

Recommended:

- private authenticated Cloud Run services;
- restrict ingress where compatible with platform integrations;
- Cloud SQL private connectivity or connector;
- no generic outbound HTTP tool;
- outbound integrations represented as named broker adapters;
- destination allow-lists enforced as deterministic constraints;
- Google Agent Gateway used as sanctioned agent egress path when configured.

---

## 10. Regionality

Primary region: `asia-south1`.

The claim should be:

```text
Delegation Fabric is deployed with its primary runtime and data-plane services in asia-south1 where the selected service supports that region.
```

Do not claim absolute regionality for a component configured through a global endpoint.

---

## 11. Failure classes

### Authorization failure

Examples:

```text
capability_not_declared
outside_business_purpose
argument_constraint_failed
approval_required
separation_of_duties_violation
grant_expired
grant_replayed
```

No retry.

### Transient infrastructure failure

Examples:

```text
Firestore unavailable
KMS timeout
Cloud SQL connection failure
downstream 503
```

Retry only where safe, with bounded exponential backoff.

### Ambiguous mutation outcome

Example:

```text
payment adapter times out after request transmission
```

Do not mint a second grant immediately. Resolve by idempotency/status lookup using `grant_id`.

---

## 12. Architecture invariants checklist

- [ ] model cannot directly reach DB
- [ ] agent cannot mint its own grant
- [ ] signing key private material never leaves KMS
- [ ] gateway re-evaluates actual args
- [ ] grant consumed transactionally
- [ ] DB role narrower than app intent
- [ ] response projection occurs before model context
- [ ] push events idempotent
- [ ] every service identity is dedicated
- [ ] audit events correlate by task/delegation/grant
