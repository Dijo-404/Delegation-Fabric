# Runtime and Workflows

This document covers agent orchestration, task state, Pub/Sub delivery, checkpointing, resumption and memory.

---

## 1. Runtime principles

1. Session state and workflow state are different.
2. A task may survive process/runtime shutdown.
3. Grants never survive a long wait for reuse.
4. Pub/Sub push delivery may repeat.
5. Every state transition is validated.
6. Agent-to-agent handoff cannot expand authority.

---

## 2. Session vs task

**Session**

- conversational/model context;
- managed by Agent Platform Sessions;
- useful for continued interaction.

**Task**

- business workflow state;
- stored in Firestore;
- source of truth for `awaiting_approval`, `completed`, etc.

Example:

```text
session says: "We found a payment exception"
task says:    state=awaiting_approval, exception_id=exc_12
```

The worker trusts durable task state, not free-form session text, for orchestration decisions.

---

## 3. State machine

States:

```text
created
running
awaiting_approval
awaiting_webhook
resuming
completed
failed
quarantined
cancelled
```

Allowed transitions:

| From | To | Trigger |
| --- | --- | --- |
| created | running | initial invocation |
| running | awaiting_approval | policy/workflow requirement |
| running | awaiting_webhook | external operation pending |
| running | completed | terminal success |
| running | failed | terminal unrecoverable error |
| running | quarantined | security event |
| awaiting_approval | resuming | valid approval event |
| awaiting_webhook | resuming | valid webhook event |
| resuming | running | runtime/session successfully restored |
| resuming | failed | unrecoverable resume failure |
| quarantined | resuming | authorized human release |
| any non-terminal | cancelled | authorized cancellation |

Any unlisted transition is denied.

---

## 4. Transition API

Pure function:

```python
def transition(
    current: TaskState,
    event: TaskEvent,
) -> TaskState: ...
```

Do not let handlers assign arbitrary state strings.

---

## 5. Checkpoint boundary

Write a checkpoint when:

- entering a wait state;
- before an external asynchronous dependency;
- after a significant agent handoff;
- before scale-to-zero;
- after resume succeeds.

Checkpoint includes business references, not authority tokens.

---

## 6. Pub/Sub event envelope

```json
{
  "event_id": "evt_01...",
  "event_type": "approval.created",
  "schema_version": "1",
  "source": "control-plane",
  "task_id": "task_1001",
  "occurred_at": "2026-08-24T08:41:12Z",
  "data": {
    "approval_id": "apr_44"
  }
}
```

Supported event types:

```text
task.start
approval.created
approval.rejected
external.settlement.completed
external.settlement.failed
task.release
task.cancel
```

---

## 7. Push-delivery idempotency

Pub/Sub push is at-least-once.

Algorithm:

```text
decode -> validate -> dedupe -> transition -> resume -> checkpoint -> ack
```

Use `event_receipts/{event_id}`.

Do not use only Pub/Sub message ID as the business idempotency key; application publishers should emit stable logical event IDs.

---

## 8. Worker concurrency

Two duplicate events can race.

Use Firestore transaction on:

```text
task.state_version
event_receipt
```

Example:

```text
read task version=4
read receipt absent
validate transition
write receipt processing
update task state=resuming, state_version=5
commit
```

A racing worker sees receipt or version mismatch and exits/no-ops.

---

## 9. Resumption algorithm

```python
async def handle_approval(event):
    task = await reserve_event_and_transition(event)

    checkpoint = await checkpoint_store.get(task.latest_checkpoint_id)
    session = await runtime.get_session(checkpoint.session_id)

    await runtime.resume(
        session=session,
        input_event={
            "type": "approval",
            "approval_id": event.data["approval_id"],
        },
    )

    await mark_running_and_checkpoint(task)
```

When resumed agent needs a protected action, normal grant issuance runs again.

---

## 10. Agent handoff

Parent agent:

```text
invoice-reconciliation
```

Child:

```text
procurement-exception
```

Handoff message should carry stable business identifiers:

```json
{
  "task_id": "task_1001",
  "delegation_id": "dlg_01",
  "invoice_id": "INV-042",
  "exception_reason": "amount_mismatch"
}
```

The child resolves its own manifest and receives only authority permitted by the root delegation + child manifest.

---

## 11. Memory policy

Memory Bank is for long-term/contextual memory, not authorization truth.

Never store in agent memory:

- bank account numbers;
- signing tokens;
- Execution Grants;
- secrets;
- unrestricted approval tokens.

Manifest example:

```yaml
memory:
  classes:
    - working_state
    - episodic
  ttl_days: 30
  prohibited_content:
    - bank_account
    - secret
    - execution_grant
```

Authorization decisions always resolve current durable policy/delegation state.

---

## 12. Quarantine

Enter `quarantined` when:

- document is high-confidence malicious;
- agent repeatedly requests outside-purpose actions;
- attempted exfiltration;
- policy explicitly requires human review.

Quarantine is a workflow state, not just a log message.

Release requires:

- authenticated human;
- reason;
- current state match;
- audit event.

---

## 13. Retry classification

Retry:

```text
network timeout before confirmed downstream request
Firestore transient error
KMS transient error
runtime transient unavailable
```

Do not retry:

```text
policy deny
replay
expired grant
wrong tool
invalid approval
SOD violation
malformed event
```

Ambiguous side-effect outcome:

```text
query downstream by idempotency key/status before deciding.
```
