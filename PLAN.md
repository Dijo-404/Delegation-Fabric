# Delegation Fabric — Build Plan

Deadline: **31 August 2026, 17:00 PDT**  
Planning start: **20 August 2026**

This plan is optimized for a one-to-three-person hackathon team. It treats the authorization mechanism as the product and the console as evidence.

---

## 1. Definition of success

The submission is complete when a reviewer can observe:

1. three registered agents performing useful finance work;
2. a human-created delegation governing the workflow;
3. short-lived Execution Grants signed through Cloud KMS;
4. deterministic tool/argument authorization;
5. single-use grant consumption;
6. field-level response projection;
7. approval + separation-of-duties enforcement;
8. a workflow pausing and later resuming from durable state;
9. a poisoned document causing an attempted unauthorized action that is denied;
10. cross-agent capability escalation being denied;
11. a verifiable audit chain;
12. reproducible deployment/test/demo commands.

---

## 2. Current platform decisions

These choices reflect the current Google Cloud platform surface as of 20 August 2026.

### 2.1 Region

Use `asia-south1` for:

- Agent Runtime
- Sessions
- Memory Bank
- Agent Gateway
- Model Armor
- Cloud Run
- Firestore location strategy where compatible
- Cloud SQL
- Cloud KMS key ring

Keep the residency claim factual and tied to deployed resources.

### 2.2 Model

Use `gemini-3.5-flash` for the hackathon build.

Do not upgrade merely because a newer Flash model exists. The selected model supports `asia-south1`, which aligns with the regional architecture.

### 2.3 Google Agent Gateway vs Delegation Fabric Execution Gateway

Use both, with different responsibilities.

**Google Agent Gateway**

- Agent Identity/IAM boundary
- platform routing
- Model Armor integration
- optional Semantic Governance
- agent/tool connectivity

**Delegation Fabric Execution Gateway**

- Execution Grant verification
- deterministic constraints
- transactional grant consumption
- response-field projection
- application audit event
- direct call into the protected adapter

This distinction must be visible in the architecture diagram and demo narration.

### 2.4 Pub/Sub

Use push subscriptions to wake a scale-to-zero Cloud Run worker.

Do **not** claim exactly-once delivery. Push is at-least-once. Implement event-level idempotency with stable `event_id` receipts in Firestore.

---

## 3. Priority model

### P0 — required

- domain schemas
- deterministic constraint engine
- Control Plane
- KMS signing
- Execution Gateway
- grant consumption
- one real Cloud SQL tool path
- three agent manifests
- happy-path reconciliation
- human approval
- checkpoint/resume
- injection attack
- cross-agent escalation attack
- audit chain
- minimal console
- repeatable commands

### P1 — strong scoring value

- Google Agent Gateway integration
- Model Armor
- Semantic Governance dry-run/enforcement evidence
- React Flow audit graph
- Cloud Trace
- Cloud Storage retention export
- portable adapters in CI

### P2 — cut first

- animation/polish
- extra attack scenarios in video
- optional secondary models
- complex analytics dashboards
- broad generic admin features

---

## 4. Suggested ownership

| Area | Owner A | Owner B | Owner C |
| --- | --- | --- | --- |
| Core + policy + grant | primary | review | |
| Control Plane + Gateway | primary | support | |
| Agents + runtime | | primary | support |
| Worker + events | | primary | |
| Console | | support | primary |
| Terraform/IAM | primary | support | support |
| Fixtures/demo/docs | review | support | primary |

For one engineer: build in the exact order below and keep the console minimal.

---

# Day-by-day execution

## Day 0 — 20 August: verify platform and create skeleton

### Objectives

- remove platform uncertainty;
- freeze versions;
- establish code quality before feature work.

### Platform checks

- [ ] Agent Runtime available in `asia-south1`
- [ ] Sessions available in `asia-south1`
- [ ] Memory Bank available in `asia-south1`
- [ ] Agent Gateway available in `asia-south1`
- [ ] Model Armor regional template works in `asia-south1`
- [ ] Agent Runtime agents appear in Agent Registry
- [ ] `gemini-3.5-flash` works in the chosen regional configuration
- [ ] Semantic Governance availability/preview terms understood
- [ ] Cloud KMS `EC_SIGN_P256_SHA256` key can be created

Record verified answers in `docs/DECISIONS.md`.

### Repository

```bash
uv init delegation-fabric
cd delegation-fabric

uv add \
  fastapi uvicorn pydantic \
  google-adk google-cloud-aiplatform \
  google-cloud-firestore google-cloud-kms \
  google-cloud-pubsub google-cloud-storage \
  sqlalchemy asyncpg \
  opentelemetry-sdk opentelemetry-exporter-gcp-trace

uv add --dev \
  ruff mypy pytest pytest-asyncio pytest-cov \
  respx pre-commit

npx create-next-app@latest apps/console \
  --typescript --tailwind --app --eslint
```

### Create directories

```text
apps/control_plane
apps/execution_gateway
apps/worker
apps/agents
packages/delegation_fabric_core
packages/delegation_fabric_adapters
infra
seed
docs
tests
```

### Quality configuration

- [ ] `ruff`
- [ ] `mypy --strict`
- [ ] pytest
- [ ] prettier
- [ ] eslint zero warnings
- [ ] TypeScript strict
- [ ] Terraform fmt/validate
- [ ] pre-commit
- [ ] GitHub Actions `make check`

### Exit criteria

- [ ] hello FastAPI service deployed to Cloud Run
- [ ] hello ADK agent deployed to Agent Runtime
- [ ] agent visible in Agent Registry
- [ ] CI green
- [ ] architecture decisions recorded

---

## Day 1 — 21 August: core domain and deterministic policy

Build `packages/delegation_fabric_core` with **zero Google Cloud imports**.

### Domain models

Implement:

```text
Delegation
ExecutionGrant
Constraint
ApprovalRecord
AgentManifest
TaskCheckpoint
AuditEvent
PolicyDecision
ToolRequest
ToolResponse
EventEnvelope
```

See `docs/AUTHORIZATION.md` and `docs/DATA_MODEL.md`.

### Constraint engine

Required operators:

```text
eq
neq
in
not_in
lt
lte
gt
gte
prefix
subset_of
matches
exists
```

Rules:

- no Python `eval`;
- strict type checks;
- bounded nesting depth;
- bounded regex length;
- precompiled regex;
- unknown paths deny for authorization predicates;
- malformed predicates deny closed;
- deterministic reason code returned for every failure.

API:

```python
def evaluate_constraints(
    constraints: list[Constraint],
    arguments: JsonObject,
) -> PolicyDecision:
    ...
```

### Response projection

```python
def project_fields(
    payload: JsonValue,
    allowed_paths: list[str],
) -> ProjectionResult:
    ...
```

Test nested objects, arrays, absent paths, unknown fields and empty allow-lists.

### Audit hashing

Canonical JSON:

- UTF-8
- sorted keys
- no whitespace differences
- ISO-8601 UTC timestamps
- exclude `event_hash` from hash input

```text
event_hash = SHA256(prev_hash || canonical_json(event_without_hash))
```

### Exit criteria

- [ ] `make test-core`
- [ ] >= 85% package coverage
- [ ] strict typing clean
- [ ] no cloud imports
- [ ] 60+ table-driven constraint tests

---

## Day 2 — 22 August: Control Plane, KMS and Execution Gateway

### Control Plane endpoints

Implement first:

```text
POST /v1/delegations
POST /v1/delegations/{id}/revoke
POST /v1/grants/evaluate
GET  /v1/grants/{id}
POST /v1/approvals
GET  /v1/tasks/{id}
```

Exact contracts are in `docs/API_CONTRACTS.md`.

### Grant signing

Use:

```text
Cloud KMS
purpose: ASYMMETRIC_SIGN
algorithm: EC_SIGN_P256_SHA256
```

Private key material never enters the service container.

The signer service account receives only the permission required to use the key version for signing.

### Execution Gateway

Implement:

```text
POST /v1/execute
```

Verification order:

1. parse JWS/header;
2. resolve `kid`;
3. verify signature;
4. verify `iss`, `nbf`, `exp`;
5. verify expected region;
6. verify task/delegation status;
7. verify agent id/version;
8. verify exact tool;
9. atomically consume grant;
10. re-evaluate actual arguments;
11. execute tool adapter;
12. project response;
13. append audit event;
14. emit trace/log/metric.

A grant that fails after consumption is not silently reusable.

### Consumption trade-off

Default side-effect semantics:

```text
consume first -> execute second
```

This provides **at-most-once authorization use**, not guaranteed exactly-once business completion.

If the underlying business operation times out after possibly committing, resolve using the downstream idempotency key (`grant_id`) or reconciliation/status lookup. Never re-run with the same grant.

### ERP

Create the minimal schema and roles described in `docs/DATA_MODEL.md`.

### Exit criteria

- [ ] valid grant executes `invoice.read`
- [ ] replay fails
- [ ] modified token fails
- [ ] expired token fails
- [ ] wrong tool fails
- [ ] invalid arguments fail
- [ ] projected response excludes forbidden columns

---

## Day 3 — 23 August: agents, registry and platform gateway

### Agents

Create:

```text
invoice-reconciliation
procurement-exception
treasury-approval
```

Each has:

```text
agent.py
manifest.yaml
tools.py
deploy.py
tests/
```

### Critical rule

Agent tools do not connect directly to Cloud SQL.

They request authorization, then invoke the protected route.

```python
async def read_invoice(invoice_id: str, ctx: ToolContext) -> dict:
    req = {
        "task_id": ctx.state["task_id"],
        "tool": "invoice.read",
        "arguments": {"invoice_id": invoice_id},
    }
    grant = await control_plane.evaluate_grant(req)
    return await execution_gateway.execute(
        grant=grant.token,
        tool=req["tool"],
        arguments=req["arguments"],
    )
```

### Agent Registry

Use Agent Registry as the authoritative platform catalog.

Do not reimplement agent discovery. Keep only a read-optimized copy of authorization-relevant metadata if needed by the console.

### Google Agent Gateway

Route agent-to-tool traffic through the Google gateway where possible.

Add:

- agent identity;
- IAM policy;
- Model Armor template;
- optional Semantic Governance policy.

Delegation Fabric remains the final deterministic authorization step.

### Exit criteria

- [ ] all three agents deployed
- [ ] visible in Agent Registry
- [ ] Google Agent Gateway route proven
- [ ] one invoice processed E2E
- [ ] no direct DB credentials in agent runtime

---

## Day 4 — 24 August: durable tasks, Pub/Sub and resumption

### Topics

```text
delegation_fabric.tasks
delegation_fabric.approvals
delegation_fabric.webhooks
```

### Subscription semantics

Use push subscriptions to the private Cloud Run worker with OIDC authentication.

Required idempotency algorithm:

```text
receive event
  -> validate envelope
  -> Firestore transaction:
       if event_receipts/{event_id} exists:
           return duplicate/no-op
       verify current task state
       write receipt(status=processing)
       write transition intent/version
  -> perform resume action
  -> Firestore transaction:
       write new checkpoint
       mark receipt complete
  -> HTTP 2xx
```

Every event carries:

```json
{
  "event_id": "evt_...",
  "event_type": "approval.created",
  "task_id": "task_...",
  "occurred_at": "...",
  "source": "control-plane",
  "schema_version": "1",
  "data": {}
}
```

### State machine

Implement transition validation from `docs/RUNTIME_WORKFLOWS.md`.

### Resumption

A resumed task must mint a new grant.

Never serialize an Execution Grant into a checkpoint for later reuse.

### Exit criteria

- [ ] duplicate Pub/Sub push causes no duplicate transition
- [ ] invalid state transition rejected
- [ ] killed worker can cold-start and resume
- [ ] memory/session continuity visible
- [ ] fresh grant minted after resume

---

## Day 5 — 25 August: adversarial paths and defense in depth

### Model Armor

Apply to:

1. user/delegation content before model context;
2. retrieved supplier-controlled documents;
3. model response/tool-call proposal where integration permits;
4. generated user-facing output for sensitive-data checks.

Store Model Armor finding metadata in the audit event; do not treat the finding as the sole authorization decision.

### Semantic Governance

Use one or two natural-language constraints that overlap with the demo scenario.

Prefer:

- dry-run first;
- then enforcement if stable.

The product story should explicitly say:

```text
Semantic Governance checks intent and business constraints probabilistically.
Delegation Fabric still requires a deterministic signed grant.
```

### Attack 1

Poisoned invoice requests bank-account exfiltration.

Expected:

```text
document screened
-> agent may still attempt forbidden action
-> semantic layer may deny
-> Delegation Fabric deterministic policy denies regardless
-> no grant
-> task quarantined
-> audit reason outside_business_purpose / capability_not_declared
```

For strongest evidence, run a test configuration where semantic enforcement is advisory and show Delegation Fabric still blocks.

### Attack 2

`invoice-reconciliation` attempts `payment.instruct`.

Expected:

```text
manifest lacks capability
-> Control Plane denies
-> no grant
-> no execution request reaches payment adapter
```

### Exit criteria

- [ ] `make attack-injection`
- [ ] `make attack-escalation`
- [ ] both deterministic
- [ ] denial reason visible in console/logs
- [ ] DB/IAM backstop also demonstrable

---

## Day 6 — 26 August: console

Required routes:

```text
/registry
/registry/[agent]
/delegations
/tasks/[id]
/approvals
/audit/[taskId]
/security
```

Minimum useful UI:

### Registry

- version
- owner
- risk
- capabilities
- denied tools
- region
- current deployment revision

### Task

- current state
- agent/session
- checkpoints
- grants
- approvals
- wait duration
- event receipts

### Audit

Graph edges:

```text
human
-> delegation
-> source document
-> agent/version
-> policy decision
-> execution grant
-> approval
-> tool request
-> side effect
```

### Security

Show structured denials by reason code, not raw stack traces.

### Exit criteria

- [ ] completed task graph renders
- [ ] payment node can be traced to approval and delegation
- [ ] denied attack visible
- [ ] UI never displays secret/token material

---

## Day 7 — 27 August: realistic workload, observability and hardening

### Seed

Use one internally consistent dataset and print the final counts in the fixture README.

Example:

```text
240 total invoices
212 clean
26 non-critical mismatches
1 critical exception
1 poisoned invoice
```

If different numbers are used, every screenshot, counter and script must agree.

### Reliability

- [ ] Pub/Sub retry policy
- [ ] dead-letter topic
- [ ] event receipt idempotency
- [ ] downstream adapter idempotency by `grant_id`
- [ ] connection/timeouts
- [ ] structured retry classification
- [ ] no retry on deterministic policy denial

### Observability

Logs must include:

```text
trace_id
task_id
delegation_id
grant_id
agent_id
agent_version
tool
decision
reason_code
latency_ms
```

Metrics:

```text
grant_issued_total
grant_denied_total{reason}
grant_replay_total
tool_execution_total{tool,status}
task_state_transition_total{from,to}
event_duplicate_total
quarantine_total{reason}
grant_issue_latency_ms
gateway_execution_latency_ms
```

### Exit criteria

- [ ] complete batch finishes
- [ ] counters reconcile
- [ ] trace tree readable
- [ ] DLQ path tested
- [ ] cold clone/bootstrap verified

---

## Day 8 — 28 August: rehearsal

Four-minute target:

| Time | Proof |
| --- | --- |
| 0:00–0:25 | Problem + thesis |
| 0:25–0:45 | Registry + three-agent fleet |
| 0:45–1:25 | Delegation + real reconciliation |
| 1:25–1:55 | Approval + protected payment |
| 1:55–2:25 | Pause/resume from checkpoint |
| 2:25–2:55 | Poisoned document blocked |
| 2:55–3:20 | Cross-agent escalation denied |
| 3:20–3:45 | Audit graph |
| 3:45–4:00 | Cloud proof + close |

Do not spend time explaining every cloud service. Explain the authorization invariant.

---

## Day 9 — 29 August: submission assets

- [ ] final unedited video
- [ ] architecture PNG
- [ ] README screenshots
- [ ] Devpost write-up
- [ ] public/shared repository
- [ ] deployment evidence
- [ ] learnings
- [ ] threat-model note
- [ ] technical blog/post if required

Devpost structure:

```text
Problem
Why current agent permissions are dangerous
Delegation Fabric mechanism
Architecture
Long-running behavior
Security attacks
Operational utility
Google Cloud integrations
Reproducibility
Trade-offs
Learnings
```

---

## Day 10 — 30 August: buffer and submit early

No planned feature work.

Use for:

- broken deployment;
- quota issue;
- demo recording issue;
- permission issue;
- docs mismatch;
- final consistency check.

Submit early.

---

# 5. Cross-cutting acceptance gates

## Authorization gate

- [ ] no direct agent DB credentials
- [ ] no protected side effect without grant
- [ ] tool binding exact
- [ ] arguments deterministic
- [ ] response projection
- [ ] approval binding
- [ ] SOD
- [ ] replay rejection

## Durability gate

- [ ] task state persists
- [ ] session state separate
- [ ] event idempotency
- [ ] duplicate delivery harmless
- [ ] fresh grant after resume

## Platform gate

- [ ] Agent Runtime
- [ ] Agent Registry
- [ ] Google Agent Gateway
- [ ] Model Armor
- [ ] regional configuration documented
- [ ] Semantic Governance role accurately described

## Audit gate

- [ ] reason codes closed enum
- [ ] event hash chain verifies
- [ ] source -> side effect traceable
- [ ] no chain-of-thought stored

## Engineering gate

- [ ] core cloud-independent
- [ ] strict typing
- [ ] coverage floors
- [ ] IaC
- [ ] least privilege
- [ ] structured logs
- [ ] repeatable Make targets

---

# 6. Fallback strategy

Ports remain behind `delegation_fabric_adapters`.

```python
class RuntimePort(Protocol):
    async def start(...) -> SessionRef: ...
    async def resume(...) -> RunResult: ...

class MemoryPort(Protocol):
    async def write(...) -> str: ...
    async def search(...) -> list[MemoryHit]: ...

class RegistryPort(Protocol):
    async def get(...) -> AgentManifest: ...
    async def list(...) -> list[AgentManifest]: ...

class ArmorPort(Protocol):
    async def screen(...) -> ScreenResult: ...
```

Fallbacks:

| Managed | Portable |
| --- | --- |
| Agent Runtime | ADK runner on Cloud Run/Jobs |
| Memory Bank | Firestore + pgvector |
| Agent Registry | Firestore registry adapter |
| Model Armor | Sensitive Data Protection + classifier |
| Semantic Governance | deterministic Delegation Fabric rules remain primary |

Do not switch merely because the managed platform takes time to learn. Switch only for a real blocking issue.

---

# 7. Final definition of done

The project is finished only when this command sequence works from a clean environment:

```bash
make bootstrap
make check
make infra
make seed
make deploy-agents
make deploy
make demo
```

and the demo proves:

```text
useful multi-agent work
+ durable execution
+ human-anchored delegation
+ deterministic transaction authorization
+ attack containment
+ auditable causal provenance
```
