"""Integration tests for Pub/Sub worker idempotency and durable task resumption."""

import base64
import json
from datetime import UTC, datetime

import pytest
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_core.models.task import Task, TaskState
from httpx import ASGITransport, AsyncClient

from apps.worker.main import create_app as create_worker


def _make_pubsub_payload(
    event_id: str, event_type: str, task_id: str, data: dict | None = None
) -> dict:
    envelope = {
        "event_id": event_id,
        "event_type": event_type,
        "schema_version": "1",
        "source": "control-plane",
        "task_id": task_id,
        "occurred_at": datetime.now(UTC).isoformat(),
        "data": data or {},
    }
    encoded = base64.b64encode(json.dumps(envelope).encode("utf-8")).decode("ascii")
    return {
        "message": {
            "data": encoded,
            "messageId": "msg_001",
            "publishTime": "2026-08-20T12:00:00Z",
        },
        "subscription": "projects/test/subscriptions/worker-push",
    }


@pytest.mark.asyncio
async def test_worker_resumption_and_idempotent_duplicate_handling():
    store = MemoryStore()
    now = datetime.now(UTC)

    # Seed Task in awaiting_approval state
    task = Task(
        task_id="task_resume_01",
        delegation_id="dlg_01",
        state=TaskState.AWAITING_APPROVAL,
        state_version=2,
        current_agent_id="treasury-approval",
        current_agent_version="1.0.3",
        created_at=now,
        updated_at=now,
    )
    await store.put_task(task)

    worker_app = create_worker(store=store)

    async with AsyncClient(
        transport=ASGITransport(app=worker_app), base_url="http://worker.test"
    ) as client:
        payload = _make_pubsub_payload(
            event_id="evt_unique_101",
            event_type="approval.created",
            task_id="task_resume_01",
            data={"approval_id": "apr_01"},
        )

        # 1. First event push: transitions state awaiting_approval -> resuming and stores checkpoint
        resp1 = await client.post("/internal/events/pubsub", json=payload)
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["status"] == "processed"
        assert data1["new_state"] == "resuming"

        updated_task = await store.get_task("task_resume_01")
        assert updated_task is not None
        assert updated_task.state == TaskState.RESUMING
        assert updated_task.state_version == 3
        assert updated_task.latest_checkpoint_id != ""

        # 2. Duplicate delivery of same event_id: must return 200 OK with duplicate_ignored without mutating task again
        resp2 = await client.post("/internal/events/pubsub", json=payload)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["status"] == "duplicate_ignored"

        task_after_dup = await store.get_task("task_resume_01")
        assert task_after_dup is not None
        assert task_after_dup.state_version == 3  # Unchanged
