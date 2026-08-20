# Architecture Decisions

Use this file as a dated ADR ledger.

---

## ADR-001 — Separate platform Agent Gateway from Delegation Fabric Execution Gateway

**Status:** accepted  
**Date:** 2026-08-20

### Decision

Use Google Agent Gateway for platform identity/routing/Model Armor/Semantic Governance, and a separate Delegation Fabric Execution Gateway for deterministic grant verification and transactional consumption.

### Why

Current Agent Platform already provides governance controls. Delegation Fabric should complement them with a transaction credential and replay-safe execution boundary.

### Rejected

- Reimplementing all Agent Gateway responsibilities.
- Positioning Delegation Fabric as only a semantic policy engine.

---

## ADR-002 — Use deterministic rules as load-bearing transaction authorization

**Status:** accepted  
**Date:** 2026-08-20

### Decision

Semantic Governance may be a precondition/companion, but deterministic rules decide whether an Execution Grant is minted.

### Why

Semantic policy uses probabilistic LLM evaluation. Financial side-effect authorization needs reproducible argument/approval/identity checks.

---

## ADR-003 — Consume side-effect grants before execution

**Status:** accepted  
**Date:** 2026-08-20

### Decision

Transactionally mark a single-use grant consumed before calling the mutating adapter.

### Benefit

Replay-safe checkpoint resumption and at-most-once authorization use.

### Cost

If downstream outcome is ambiguous, the grant cannot simply be retried. Resolve via downstream idempotency/status using `grant_id`.

---

## ADR-004 — Pub/Sub push + application idempotency

**Status:** accepted  
**Date:** 2026-08-20

### Decision

Use OIDC-authenticated Pub/Sub push subscriptions to a scale-to-zero Cloud Run worker.

### Consequence

Push delivery is at-least-once. Implement stable application `event_id` receipts and state-version transactions.

### Rejected

Claiming Pub/Sub exactly-once for push delivery.

---

## ADR-005 — Keep `gemini-3.5-flash` for regional consistency

**Status:** accepted  
**Date:** 2026-08-20

### Decision

Use `gemini-3.5-flash` in the hackathon build.

### Why

It supports the selected `asia-south1` architecture. Do not upgrade solely for recency if it weakens the residency story.

---

## ADR-006 — Firestore workflow metadata, PostgreSQL ERP

**Status:** accepted  
**Date:** 2026-08-20

### Why

Firestore fits grant/task/event transactions and asynchronous workflow metadata. PostgreSQL better demonstrates real column/table privilege boundaries for ERP data.

---

## ADR template

```text
## ADR-XXX — Title

Status:
Date:

### Context

### Decision

### Alternatives

### Consequences

### Validation
```
