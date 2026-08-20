"""Cloud Run worker service for Pub/Sub push delivery and durable task resumption.

Enforces idempotency algorithm from docs/RUNTIME_WORKFLOWS.md § 7:
1. Decode & validate EventEnvelope
2. Transactional check in event_receipts/{event_id}:
   - If already complete or duplicate -> return HTTP 200 (no-op)
3. Validate and execute state transition
4. Resume session / agent task
5. Mint checkpoint and mark receipt complete
6. Return HTTP 200 OK
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

import ulid
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_core.errors.exceptions import InvalidTransitionError
from delegation_fabric_core.models.checkpoint import TaskCheckpoint
from delegation_fabric_core.models.event import EventEnvelope, EventType
from delegation_fabric_core.models.task import TaskEvent
from delegation_fabric_core.policy.state_machine import transition
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel


class PubSubMessage(BaseModel):
    data: str  # Base64-encoded JSON of EventEnvelope
    messageId: str = ""
    publishTime: str = ""


class PubSubPushRequest(BaseModel):
    message: PubSubMessage
    subscription: str = ""


def create_app(store: MemoryStore | None = None) -> FastAPI:
    app = FastAPI(title="Delegation Fabric Worker", version="0.1.0")
    db = store or MemoryStore()

    @app.post("/internal/events/pubsub")
    async def handle_pubsub_event(req: PubSubPushRequest) -> dict[str, Any]:
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

        # Step 2: Transactional event deduplication
        is_new_event = await db.reserve_event_receipt(envelope)
        if not is_new_event:
            # Duplicate delivery safely acknowledged as a no-op
            return {"status": "duplicate_ignored", "event_id": envelope.event_id}

        # Step 3: Fetch task and execute state transition
        task = await db.get_task(envelope.task_id)
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Task {envelope.task_id!r} not found",
            )

        # Map event_type to TaskEvent
        task_event_map = {
            EventType.TASK_START: TaskEvent.INITIAL_INVOCATION,
            EventType.APPROVAL_CREATED: TaskEvent.APPROVAL_RECEIVED,
            EventType.EXTERNAL_SETTLEMENT_COMPLETED: TaskEvent.WEBHOOK_RECEIVED,
            EventType.TASK_RELEASE: TaskEvent.HUMAN_RELEASED,
            EventType.TASK_CANCEL: TaskEvent.CANCELLATION,
        }

        t_event = task_event_map.get(envelope.event_type)
        if not t_event:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unhandled event type: {envelope.event_type}",
            )

        try:
            next_state = transition(task.state, t_event)
        except InvalidTransitionError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid state transition: {e}",
            ) from e

        # Step 4: Advance task state
        now = datetime.now(UTC)
        task.state = next_state
        task.state_version += 1
        task.updated_at = now

        # Step 5: Persist checkpoint
        checkpoint_id = f"chk_{ulid.ULID()}"
        checkpoint = TaskCheckpoint(
            checkpoint_id=checkpoint_id,
            task_id=task.task_id,
            state=task.state.value,
            state_version=task.state_version,
            session_id=task.session_id or f"session_{ulid.ULID()}",
            agent_id=task.current_agent_id,
            agent_version=task.current_agent_version,
            memory_refs=[],
            pending_subject=envelope.data,
            created_at=now,
        )
        await db.put_checkpoint(checkpoint)
        await db.put_task(task)

        # Step 6: Mark event receipt complete
        await db.mark_event_complete(envelope.event_id)

        return {
            "status": "processed",
            "event_id": envelope.event_id,
            "task_id": task.task_id,
            "new_state": task.state.value,
            "checkpoint_id": checkpoint_id,
        }

    return app
