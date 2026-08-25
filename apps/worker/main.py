"""Cloud Run worker service for Pub/Sub push delivery and durable task resumption.

Enforces idempotency algorithm from docs/RUNTIME_WORKFLOWS.md § 7:
1. Decode & validate EventEnvelope
2. Transactional check in event_receipts/{event_id}:
   - If already complete or actively leased -> return HTTP 200 (no-op)
3. Validate and execute state transition
4. Restore runtime from latest checkpoint when entering RESUMING (§ 9)
5. Persist checkpoints and append audit event
6. Mark receipt complete and return HTTP 200 OK

Transient infrastructure failures return HTTP 500 without completing the
receipt; the lease expiry in reserve_event_receipt allows redelivery retries.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import ulid
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_core.audit.chain import GENESIS_HASH, finalize_audit_event
from delegation_fabric_core.errors.exceptions import (
    ConcurrentTaskUpdateError,
    InvalidTransitionError,
)
from delegation_fabric_core.models.audit import AuditActor, AuditActorType, AuditEvent
from delegation_fabric_core.models.checkpoint import TaskCheckpoint
from delegation_fabric_core.models.event import EventEnvelope, EventType
from delegation_fabric_core.models.task import Task, TaskEvent, TaskState
from delegation_fabric_core.policy.state_machine import transition
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import PlainTextResponse

if TYPE_CHECKING:
    from delegation_fabric_adapters.firestore.firestore_store import FirestoreStore
from pydantic import BaseModel


class PubSubMessage(BaseModel):
    data: str  # Base64-encoded JSON of EventEnvelope
    messageId: str = ""
    publishTime: str = ""


class PubSubPushRequest(BaseModel):
    message: PubSubMessage
    subscription: str = ""


def _resolve_task_event(event_type: EventType, current_state: TaskState) -> TaskEvent | None:
    """Map an external EventType to the state-machine TaskEvent.

    EXTERNAL_SETTLEMENT_FAILED is state-dependent: a failure observed while the
    workflow was resuming is a RESUME_FAILED; otherwise it is a TERMINAL_FAILURE.
    """
    if event_type == EventType.TASK_START:
        return TaskEvent.INITIAL_INVOCATION
    if event_type == EventType.APPROVAL_CREATED:
        return TaskEvent.APPROVAL_RECEIVED
    if event_type == EventType.APPROVAL_REJECTED:
        return TaskEvent.CANCELLATION
    if event_type == EventType.EXTERNAL_SETTLEMENT_COMPLETED:
        return TaskEvent.WEBHOOK_RECEIVED
    if event_type == EventType.EXTERNAL_SETTLEMENT_FAILED:
        if current_state == TaskState.RESUMING:
            return TaskEvent.RESUME_FAILED
        return TaskEvent.TERMINAL_FAILURE
    if event_type == EventType.TASK_RELEASE:
        return TaskEvent.HUMAN_RELEASED
    if event_type == EventType.TASK_CANCEL:
        return TaskEvent.CANCELLATION
    return None


def create_app(store: MemoryStore | FirestoreStore | None = None) -> FastAPI:
    from delegation_fabric_adapters.observability import METRICS, configure_logging, log_event

    configure_logging()

    app = FastAPI(title="Delegation Fabric Worker", version="0.1.0")
    db = store or MemoryStore()

    async def _append_transition_audit(
        task_id: str,
        delegation_id: str,
        policy_version: str,
        from_state: str,
        to_state: str,
        event_id: str,
        now: datetime,
    ) -> None:
        chain = await db.get_audit_events(task_id, limit=None)
        prev_hash = chain[-1].event_hash if chain else GENESIS_HASH
        audit_evt = AuditEvent(
            audit_event_id=f"aud_{ulid.ULID()}",
            task_id=task_id,
            delegation_id=delegation_id,
            actor=AuditActor(type=AuditActorType.SYSTEM, id="worker", version="0.1.0"),
            event_type="task.state.transition",
            decision="allow",
            policy_version=policy_version,
            metadata={
                "event_id": event_id,
                "from_state": from_state,
                "to_state": to_state,
            },
            occurred_at=now,
            prev_hash=prev_hash,
        )
        await db.append_audit_event(finalize_audit_event(audit_evt, prev_hash))

    @app.post("/internal/events/pubsub")
    async def handle_pubsub_event(req: PubSubPushRequest) -> dict[str, Any]:
        _t0 = time.perf_counter()
        # Step 1: Decode Pub/Sub wrapper
        try:
            raw_bytes = base64.b64decode(req.message.data)
            envelope_data = json.loads(raw_bytes.decode("utf-8"))
            envelope = EventEnvelope.model_validate(envelope_data)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Malformed Pub/Sub event envelope: {e}",
            ) from e

        # Step 2: Transactional event deduplication with lease-based retry recovery
        try:
            is_new_event = await db.reserve_event_receipt(envelope, lease_seconds=60)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Transient store failure while reserving receipt: {e}",
            ) from e
        if not is_new_event:
            # Duplicate delivery safely acknowledged as a no-op
            METRICS.inc("event_duplicate_total")
            return {"status": "duplicate_ignored", "event_id": envelope.event_id}

        try:
            # Step 3: Fetch task and execute state transition
            task = await db.get_task(envelope.task_id)
            if not task:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Task {envelope.task_id!r} not found",
                )

            t_event = _resolve_task_event(envelope.event_type, task.state)
            if t_event is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unhandled event type: {envelope.event_type}",
                )

            from_state = task.state
            expected_version = task.state_version
            next_state = transition(from_state, t_event)

            now = datetime.now(UTC)
            task.state = next_state
            task.state_version += 1
            task.updated_at = now

            checkpoint_ids: list[str] = []
            resumed = False

            # Step 4: True resume — restore runtime refs from the last checkpoint (§ 9)
            if next_state == TaskState.RESUMING:
                resumed = True
                prior_checkpoint = (
                    await db.get_checkpoint(task.latest_checkpoint_id)
                    if task.latest_checkpoint_id
                    else None
                )
                if prior_checkpoint is not None:
                    task.current_agent_id = prior_checkpoint.agent_id
                    task.current_agent_version = prior_checkpoint.agent_version
                    task.session_id = prior_checkpoint.session_id
                elif not task.session_id:
                    task.session_id = f"session_{ulid.ULID()}"

                resume_checkpoint_id = f"chk_{ulid.ULID()}"
                await db.put_checkpoint(
                    TaskCheckpoint(
                        checkpoint_id=resume_checkpoint_id,
                        task_id=task.task_id,
                        state=task.state.value,
                        state_version=task.state_version,
                        session_id=task.session_id,
                        agent_id=task.current_agent_id,
                        agent_version=task.current_agent_version,
                        memory_refs=[],
                        pending_subject=envelope.data,
                        created_at=now,
                    )
                )
                checkpoint_ids.append(resume_checkpoint_id)

                restored_state = transition(TaskState.RESUMING, TaskEvent.RUNTIME_RESTORED)
                task.state = restored_state
                task.state_version += 1

            running_checkpoint_id = f"chk_{ulid.ULID()}"
            await db.put_checkpoint(
                TaskCheckpoint(
                    checkpoint_id=running_checkpoint_id,
                    task_id=task.task_id,
                    state=task.state.value,
                    state_version=task.state_version,
                    session_id=task.session_id,
                    agent_id=task.current_agent_id,
                    agent_version=task.current_agent_version,
                    memory_refs=[],
                    pending_subject=envelope.data if not resumed else None,
                    created_at=datetime.now(UTC),
                )
            )
            checkpoint_ids.append(running_checkpoint_id)

            # Atomic compare-and-swap: reject if another delivery mutated the
            # task between our read and write (optimistic concurrency).
            def _apply_final(t: Task) -> None:
                t.state = task.state
                t.state_version = task.state_version
                t.updated_at = task.updated_at
                t.current_agent_id = task.current_agent_id
                t.current_agent_version = task.current_agent_version
                t.session_id = task.session_id
                t.latest_checkpoint_id = running_checkpoint_id

            try:
                await db.mutate_task_atomic(
                    envelope.task_id, _apply_final, expected_version=expected_version
                )
            except ConcurrentTaskUpdateError as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Concurrent task modification for {envelope.task_id}: {e}",
                ) from e

            # Step 5: Append tamper-evident audit record for the transition
            await _append_transition_audit(
                task_id=task.task_id,
                delegation_id=task.delegation_id,
                policy_version=task.policy_version,
                from_state=from_state.value,
                to_state=task.state.value,
                event_id=envelope.event_id,
                now=now,
            )
        except InvalidTransitionError as e:
            # Permanent: includes duplicate / out-of-order deliveries already covered by state.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid state transition: {e}",
            ) from e
        except HTTPException:
            raise
        except Exception as e:
            # Retryable: leave the receipt in "processing" so lease expiry re-admits this event.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Transient failure processing event {envelope.event_id}: {e}",
            ) from e

        # Step 6: Mark event receipt complete only after full durable success
        await db.mark_event_complete(envelope.event_id)

        # Resume intentionally collapses awaiting_webhook/awaiting_approval/
        # quarantined -> running into a single reported hop: the intermediate
        # RESUMING state is not emitted, mirroring the from/to audit metadata.
        METRICS.inc(
            "task_state_transition_total",
            **{"from": from_state.value, "to": task.state.value},
        )
        log_event(
            "task transitioned",
            task_id=task.task_id,
            delegation_id=task.delegation_id,
            agent_id=task.current_agent_id,
            agent_version=task.current_agent_version,
            event_type=envelope.event_type.value,
            from_state=from_state.value,
            to_state=task.state.value,
            decision="allow",
            latency_ms=round((time.perf_counter() - _t0) * 1000.0, 2),
        )

        response: dict[str, Any] = {
            "status": "processed",
            "event_id": envelope.event_id,
            "task_id": task.task_id,
            "new_state": task.state.value,
            "checkpoint_id": running_checkpoint_id,
            "resume": {
                "resumed": resumed,
                "restored_agent": task.current_agent_id,
                "restored_session_id": task.session_id,
                "checkpoint_ids": checkpoint_ids,
            },
        }
        return response

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        return PlainTextResponse(
            METRICS.prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return app


def create_app_from_env() -> FastAPI:
    from delegation_fabric_adapters.config import build_store
    from delegation_fabric_adapters.tracing import configure_tracing, instrument_fastapi_app

    configure_tracing("worker")
    application = create_app(store=build_store())
    instrument_fastapi_app(application)
    return application


app = create_app_from_env()
