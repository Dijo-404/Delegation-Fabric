"""Unit tests for the read-only listing accessors added for the console.

Covers MemoryStore only; FirestoreStore mirrors the same signatures via
Firestore queries and is exercised in integration environments.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_core.models.approval import ApprovalDecision, ApprovalRecord
from delegation_fabric_core.models.checkpoint import TaskCheckpoint
from delegation_fabric_core.models.delegation import Delegation, DelegationStatus, Sponsor
from delegation_fabric_core.models.event import EventEnvelope, EventType
from delegation_fabric_core.models.grant import GrantRecord, GrantStatus


def _delegation(delegation_id: str = "dlg_1", task_id: str = "task_1") -> Delegation:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return Delegation(
        delegation_id=delegation_id,
        sponsor=Sponsor(subject="user:priya@example.com"),
        purpose="weekly_vendor_settlement",
        task_id=task_id,
        policy_version="finance-policy-2026-08-20.1",
        status=DelegationStatus.ACTIVE,
        created_at=now,
        expires_at=now.replace(day=2),
    )


def _approval(approval_id: str = "apr_1", task_id: str = "task_1") -> ApprovalRecord:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return ApprovalRecord(
        approval_id=approval_id,
        task_id=task_id,
        delegation_id="dlg_1",
        approval_type="payment_batch",
        subject={"batch": "B-001"},
        subject_hash="sha256:abc",
        decision=ApprovalDecision.APPROVED,
        approver_subject="user:arun@example.com",
        created_at=now,
        expires_at=now.replace(hour=12),
    )


def _checkpoint(checkpoint_id: str = "cp_1", task_id: str = "task_1") -> TaskCheckpoint:
    return TaskCheckpoint(
        checkpoint_id=checkpoint_id,
        task_id=task_id,
        state="awaiting_approval",
        state_version=3,
        session_id="session_1",
        agent_id="invoice-reconciliation",
        agent_version="1.0.0",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _grant(grant_id: str = "grt_1", task_id: str = "task_1") -> GrantRecord:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return GrantRecord(
        grant_id=grant_id,
        delegation_id="dlg_1",
        task_id=task_id,
        agent_id="invoice-reconciliation",
        agent_version="1.0.0",
        tool="invoice.read",
        status=GrantStatus.ISSUED,
        issued_at=now,
        expires_at=now.replace(minute=5),
        policy_version="finance-policy-2026-08-20.1",
    )


async def test_list_delegations_returns_copies_not_live_refs() -> None:
    store = MemoryStore()
    await store.put_delegation(_delegation())

    listed = await store.list_delegations()
    assert len(listed) == 1
    assert listed[0].sponsor.subject == "user:priya@example.com"

    listed[0].status = DelegationStatus.REVOKED
    fresh = await store.get_delegation("dlg_1")
    assert fresh is not None
    assert fresh.status == DelegationStatus.ACTIVE


async def test_list_all_approvals_ignores_task_filter() -> None:
    store = MemoryStore()
    await store.put_approval(_approval("apr_1", task_id="task_1"))
    await store.put_approval(_approval("apr_2", task_id="task_2"))
    await store.put_approval(_approval("apr_3", task_id="task_2"))

    all_approvals = await store.list_all_approvals()
    assert {a.approval_id for a in all_approvals} == {"apr_1", "apr_2", "apr_3"}
    # Existing per-task signature is untouched.
    per_task = await store.list_approvals("task_2")
    assert {a.approval_id for a in per_task} == {"apr_2", "apr_3"}


async def test_list_grants_and_checkpoints_filter_by_task() -> None:
    store = MemoryStore()
    await store.put_grant(_grant("grt_1", task_id="task_1"))
    await store.put_grant(_grant("grt_2", task_id="task_other"))
    await store.put_checkpoint(_checkpoint("cp_1", task_id="task_1"))
    await store.put_checkpoint(_checkpoint("cp_2", task_id="task_other"))

    assert {g.grant_id for g in await store.list_grants("task_1")} == {"grt_1"}
    assert {c.checkpoint_id for c in await store.list_checkpoints("task_1")} == {"cp_1"}
    assert await store.list_grants("missing") == []
    assert await store.list_checkpoints("missing") == []


async def test_list_event_receipts_filters_by_task_and_copies_dicts() -> None:
    store = MemoryStore()
    now = datetime(2026, 1, 1, tzinfo=UTC)

    async def reserve(event_id: str, task_id: str) -> bool:
        envelope = EventEnvelope(
            event_id=event_id,
            event_type=EventType.APPROVAL_CREATED,
            task_id=task_id,
            source="test",
            occurred_at=now,
            data={},
        )
        return await store.reserve_event_receipt(envelope, now=now)

    assert await reserve("evt_1", "task_1") is True
    assert await reserve("evt_2", "task_other") is True
    await store.mark_event_complete("evt_1")

    receipts: list[dict[str, Any]] = await store.list_event_receipts("task_1")
    assert [r["event_id"] for r in receipts] == ["evt_1"]
    assert receipts[0]["status"] == "complete"

    # Copy-on-read: mutating the returned dict must not affect the store.
    receipts[0]["status"] = "tampered"
    again = await store.list_event_receipts("task_1")
    assert again[0]["status"] == "complete"


async def test_list_accessors_on_empty_store_return_empty_lists() -> None:
    store = MemoryStore()
    assert await store.list_delegations() == []
    assert await store.list_all_approvals() == []
    assert await store.list_grants("t") == []
    assert await store.list_checkpoints("t") == []
    assert await store.list_event_receipts("t") == []


async def test_list_accessors_honor_default_and_explicit_limits() -> None:
    store = MemoryStore()
    for i in range(3):
        await store.put_delegation(_delegation(f"dlg_{i}"))
        await store.put_approval(_approval(f"apr_{i}", task_id=f"task_{i}"))
        await store.put_checkpoint(_checkpoint(f"cp_{i}", task_id=f"task_{i}"))
        await store.put_grant(_grant(f"grt_{i}", task_id=f"task_{i}"))

    assert len(await store.list_delegations()) == 3
    assert len(await store.list_delegations(limit=None)) == 3
    assert len(await store.list_delegations(limit=1)) == 1
    assert {a.approval_id for a in await store.list_all_approvals(limit=2)} == {
        "apr_0",
        "apr_1",
    }
    assert len(await store.list_grants("task_2", limit=1)) == 1
    assert len(await store.list_checkpoints("task_2", limit=1)) == 1
