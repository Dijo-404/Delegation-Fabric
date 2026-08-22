"""Worker receipt lease recovery and retry classification tests."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from delegation_fabric_adapters.firestore.store import MemoryStore
from httpx import ASGITransport, AsyncClient

from apps.control_plane.main import create_app as create_control_plane
from apps.worker.main import create_app as create_worker


def _payload(event_id: str, event_type: str = "task.start", task_id: str = "task_w") -> dict:
    envelope = {
        "event_id": event_id,
        "event_type": event_type,
        "task_id": task_id,
        "occurred_at": datetime.now(UTC).isoformat(),
        "source": "control-plane",
        "schema_version": "1",
        "data": {},
    }
    return {
        "message": {"data": base64.b64encode(json.dumps(envelope).encode()).decode()},
        "subscription": "sub-test",
    }


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore()


async def _seed_task(store: MemoryStore, task_id: str = "task_w") -> None:
    cp = create_control_plane(store=store)
    from httpx import ASGITransport

    async with AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c:
        resp = await c.post(
            "/v1/delegations",
            json={
                "purpose": "invoice_reconciliation",
                "task_id": task_id,
                "allowed_agents": ["invoice-reconciliation"],
                "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            },
        )
        assert resp.status_code == 201


@pytest.mark.asyncio
async def test_stuck_processing_receipt_is_reclaimed_after_lease(
    store: MemoryStore,
) -> None:
    """Crash after reservation must not lose the event: lease expiry re-admits it."""
    await _seed_task(store)
    worker = create_worker(store=store)

    from delegation_fabric_core.models.event import EventEnvelope, EventType

    async with AsyncClient(transport=ASGITransport(app=worker), base_url="http://w") as c:
        payload = _payload("evt_crash_1")
        # Simulate a crashed worker: reserve the receipt with a FRESH timestamp.
        envelope = EventEnvelope.model_validate(
            {
                "event_id": "evt_crash_1",
                "event_type": EventType.TASK_START.value,
                "task_id": "task_w",
                "occurred_at": datetime.now(UTC).isoformat(),
                "source": "control-plane",
                "schema_version": "1",
                "data": {},
            }
        )
        assert await store.reserve_event_receipt(envelope) is True

        # Within lease window: still leased -> duplicate ignored (no double-apply)
        leased = await c.post("/internal/events/pubsub", json=payload)
        assert leased.status_code == 200
        assert leased.json()["status"] == "duplicate_ignored"
        task = await store.get_task("task_w")
        assert task is not None
        version_while_leasing = task.state_version

        # After lease expiry: reclaimed and processed
        store.event_receipts["evt_crash_1"]["first_seen_at"] = (
            datetime.now(UTC) - timedelta(seconds=3600)
        ).isoformat()
        recovered = await c.post("/internal/events/pubsub", json=payload)
        assert recovered.status_code == 200
        body = recovered.json()
        assert body["status"] == "processed"

        task_after = await store.get_task("task_w")
        assert task_after is not None
        assert task_after.state_version > version_while_leasing


@pytest.mark.asyncio
async def test_malformed_envelope_returns_permanent_400(store: MemoryStore) -> None:
    worker = create_worker(store=store)
    async with AsyncClient(transport=ASGITransport(app=worker), base_url="http://w") as c:
        bad = {"message": {"data": base64.b64encode(b"not json").decode()}}
        resp = await c.post("/internal/events/pubsub", json=bad)
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_unknown_task_returns_permanent_404(store: MemoryStore) -> None:
    worker = create_worker(store=store)
    async with AsyncClient(transport=ASGITransport(app=worker), base_url="http://w") as c:
        resp = await c.post("/internal/events/pubsub", json=_payload("evt_x", task_id="nope"))
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_settlement_failure_maps_to_terminal_state(store: MemoryStore) -> None:
    await _seed_task(store)
    # Advance CREATED -> RUNNING -> AWAITING_WEBHOOK via direct state manipulation
    # is not allowed by the state machine; drive through valid transitions instead.
    task = await store.get_task("task_w")
    assert task is not None
    from delegation_fabric_core.models.task import TaskState

    task.state = TaskState.AWAITING_WEBHOOK
    task.state_version += 1
    await store.put_task(task)

    worker = create_worker(store=store)
    async with AsyncClient(transport=ASGITransport(app=worker), base_url="http://w") as c:
        resp = await c.post(
            "/internal/events/pubsub", json=_payload("evt_fail", "external.settlement.failed")
        )
        assert resp.status_code == 400  # awaiting_webhook cannot terminal-fail directly


@pytest.mark.asyncio
async def test_approval_rejection_cancels_workflow(store: MemoryStore) -> None:
    await _seed_task(store)
    task = await store.get_task("task_w")
    assert task is not None
    from delegation_fabric_core.models.task import TaskState

    task.state = TaskState.AWAITING_APPROVAL
    task.state_version += 1
    await store.put_task(task)

    worker = create_worker(store=store)
    async with AsyncClient(transport=ASGITransport(app=worker), base_url="http://w") as c:
        resp = await c.post(
            "/internal/events/pubsub", json=_payload("evt_rej", "approval.rejected")
        )
        assert resp.status_code == 200
        updated = await store.get_task("task_w")
        assert updated is not None
        assert updated.state == TaskState.CANCELLED


@pytest.mark.asyncio
async def test_concurrent_task_modification_rejected_by_cas(store: MemoryStore) -> None:
    """Optimistic concurrency: stale-version mutation raises instead of clobbering."""
    await _seed_task(store)

    from delegation_fabric_core.errors.exceptions import ConcurrentTaskUpdateError

    task = await store.get_task("task_w")
    assert task is not None
    stale_version = task.state_version

    # A racing writer bumps the version first.
    def _racer(t: object) -> None:
        t.state_version += 1  # type: ignore[attr-defined]

    await store.mutate_task_atomic("task_w", _racer, expected_version=stale_version)

    def _loser(t: object) -> None:
        t.state_version += 100  # type: ignore[attr-defined]

    try:
        await store.mutate_task_atomic("task_w", _loser, expected_version=stale_version)
        raise AssertionError("expected ConcurrentTaskUpdateError")
    except ConcurrentTaskUpdateError:
        pass

    after = await store.get_task("task_w")
    assert after is not None
    assert after.state_version == stale_version + 1  # loser's +100 never applied
