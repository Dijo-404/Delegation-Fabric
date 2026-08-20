# Demo Runbook

Target: four minutes, unedited.

The demo must prove mechanisms, not UI polish.

---

## 1. Preflight

```bash
make demo-preflight
```

Open tabs:

1. Delegation Fabric console
2. Agent Registry / Agent Platform
3. Cloud Run
4. Firestore or audit view
5. Cloud Trace
6. terminal

Have the poisoned invoice already seeded.

---

## 2. Opening — 0:00 to 0:25

Say:

```text
Enterprise agents often inherit standing human or service-account permissions.
Delegation Fabric separates long-lived human delegation from short-lived execution authority.
Every protected side effect needs a signed, single-use Execution Grant.
```

Show one architecture diagram.

---

## 3. Fleet — 0:25 to 0:45

Show:

```text
invoice-reconciliation
procurement-exception
treasury-approval
```

Point out distinct capabilities/risk.

---

## 4. Happy path — 0:45 to 1:25

Create/show delegation.

Run batch.

Show:

- invoice count;
- clean reconciliations;
- exception;
- task state.

Mention actual deterministic decision inputs.

---

## 5. Approval/payment — 1:25 to 1:55

Approve critical batch as second human.

Show:

```text
approval record
-> grant issued
-> grant consumed
-> payment accepted
```

Show `grant_id` as business idempotency key, not token.

---

## 6. Pause/resume — 1:55 to 2:25

Show:

- task waiting;
- no resident worker state required;
- event arrives;
- Cloud Run cold start;
- checkpoint/session IDs loaded;
- new grant issued after resume.

Say:

```text
The workflow can keep context for days. It does not keep authority for days.
```

---

## 7. Poisoned invoice — 2:25 to 2:55

Show malicious instruction.

Let the agent attempt forbidden bank-data/tool path in the controlled fixture.

Show deterministic deny:

```text
OUTSIDE_BUSINESS_PURPOSE
or
CAPABILITY_NOT_DECLARED
```

If Model Armor/Semantic Governance also flags it, show that as defense in depth.

Key line:

```text
Even if the model attempts the action, no Execution Grant exists, so the side effect cannot execute.
```

---

## 8. Cross-agent escalation — 2:55 to 3:20

Invoice agent attempts:

```text
payment.instruct
```

Show denial at issuance.

No need to wait for gateway execution because no grant is created.

---

## 9. Audit — 3:20 to 3:45

Click completed payment.

Trace backwards:

```text
payment
<- execution grant
<- policy version
<- approval
<- treasury agent version
<- delegation
<- human sponsor
<- source exception/invoice
```

Show audit-chain verification badge.

---

## 10. Cloud proof — 3:45 to 4:00

Rapidly show:

- Agent Runtime/Registry
- Agent Gateway or platform integration
- Cloud Run
- Pub/Sub
- Firestore
- Trace

Close:

```text
The model encountered the attack. The authorization system prevented it from mattering.
```

---

## 11. Failure recovery

### Console fails

Use terminal/API output. Mechanism proof is more important.

### Trace view slow

Use pre-opened trace or structured logs.

### Agent cold start too slow

Narrate that the cold start demonstrates scale-to-zero and jump to the checkpoint state once available.

### Semantic Governance unexpectedly blocks happy path

Use dry-run mode and disclose it. Delegation Fabric deterministic authorization remains the evaluated control.

### Model Armor false positive

Switch happy path to advisory template; keep attack fixture enforcement/recording. Disclose configuration.

---

## 12. Commands

```bash
make demo-reset
make demo-happy
make demo-approve
make demo-resume
make attack-injection
make attack-escalation
make audit-verify
```

Each command should print:

```text
task_id
delegation_id
grant_id where relevant
decision
reason_code
console URL
```

Never print full bearer tokens in recorded output.
