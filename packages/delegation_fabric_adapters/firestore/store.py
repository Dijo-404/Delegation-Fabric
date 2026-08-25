"""In-memory and transactional Firestore stores for Delegation Fabric."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from delegation_fabric_core.errors.exceptions import (
    ConcurrentTaskUpdateError,
    GrantExpiredError,
    GrantReplayError,
    GrantUnknownError,
    TaskNotFoundError,
)
from delegation_fabric_core.models.approval import ApprovalRecord
from delegation_fabric_core.models.audit import AuditEvent
from delegation_fabric_core.models.checkpoint import TaskCheckpoint
from delegation_fabric_core.models.delegation import Delegation
from delegation_fabric_core.models.event import EventEnvelope
from delegation_fabric_core.models.grant import GrantRecord, GrantStatus
from delegation_fabric_core.models.task import Task

DEFAULT_LIST_LIMIT = 200


class MemoryStore:
    """Thread/Async-safe in-memory store simulating Firestore for tests and local runtime."""

    def __init__(self) -> None:
        self.delegations: dict[str, Delegation] = {}
        self.tasks: dict[str, Task] = {}
        self.checkpoints: dict[str, TaskCheckpoint] = {}
        self.grants: dict[str, GrantRecord] = {}
        self.approvals: dict[str, ApprovalRecord] = {}
        self.event_receipts: dict[str, dict[str, Any]] = {}
        self.audit_events_by_task: dict[str, list[AuditEvent]] = {}
        self._lock = asyncio.Lock()

    # ─── Delegation CRUD ───────────────────────────────────────────────────────

    async def put_delegation(self, delegation: Delegation) -> None:
        async with self._lock:
            self.delegations[delegation.delegation_id] = delegation

    async def get_delegation(self, delegation_id: str) -> Delegation | None:
        async with self._lock:
            d = self.delegations.get(delegation_id)
            return d.model_copy() if d else None

    async def list_delegations(self, limit: int | None = DEFAULT_LIST_LIMIT) -> list[Delegation]:
        """Read-only listing for the console Delegations view (unsorted)."""
        async with self._lock:
            listed = [d.model_copy() for d in self.delegations.values()]
            return listed if limit is None else listed[:limit]

    # ─── Task CRUD & Transitions ───────────────────────────────────────────────

    async def put_task(self, task: Task) -> None:
        async with self._lock:
            self.tasks[task.task_id] = task

    async def get_task(self, task_id: str) -> Task | None:
        async with self._lock:
            task = self.tasks.get(task_id)
            # Copy-on-read: callers never hold a live reference into the store,
            # so read-modify-write cycles must go through put_task/mutate_task_atomic.
            return task.model_copy() if task else None

    async def mutate_task_atomic(
        self,
        task_id: str,
        mutator: Callable[[Task], None],
        expected_version: int | None = None,
    ) -> Task:
        """Apply mutator to the task atomically (lock + optional CAS on state_version)."""
        async with self._lock:
            task = self.tasks.get(task_id)
            if task is None:
                raise TaskNotFoundError(f"Task {task_id!r} not found")
            if expected_version is not None and task.state_version != expected_version:
                raise ConcurrentTaskUpdateError(
                    f"Task {task_id!r} changed: expected v{expected_version}, "
                    f"actual v{task.state_version}"
                )
            mutator(task)
            return task

    async def put_checkpoint(self, checkpoint: TaskCheckpoint) -> None:
        # Checkpoints are immutable history records. Task state transitions go
        # exclusively through mutate_task_atomic (single writer).
        async with self._lock:
            self.checkpoints[checkpoint.checkpoint_id] = checkpoint

    async def get_checkpoint(self, checkpoint_id: str) -> TaskCheckpoint | None:
        async with self._lock:
            return self.checkpoints.get(checkpoint_id)

    async def list_checkpoints(
        self, task_id: str, limit: int | None = DEFAULT_LIST_LIMIT
    ) -> list[TaskCheckpoint]:
        """Read-only checkpoint history for the console Task Inspector."""
        async with self._lock:
            listed = [c.model_copy() for c in self.checkpoints.values() if c.task_id == task_id]
            return listed if limit is None else listed[:limit]

    # ─── Grant Lifecycle & Atomic Consumption ───────────────────────────────────

    async def put_grant(self, grant: GrantRecord) -> None:
        async with self._lock:
            self.grants[grant.grant_id] = grant

    async def get_grant(self, grant_id: str) -> GrantRecord | None:
        async with self._lock:
            return self.grants.get(grant_id)

    async def list_grants(
        self, task_id: str, limit: int | None = DEFAULT_LIST_LIMIT
    ) -> list[GrantRecord]:
        """Read-only grant history for the console Task Inspector."""
        async with self._lock:
            listed = [g.model_copy() for g in self.grants.values() if g.task_id == task_id]
            return listed if limit is None else listed[:limit]

    async def consume_grant_atomic(self, grant_id: str, now: datetime | None = None) -> GrantRecord:
        """Atomically transition grant status from ISSUED to CONSUMED."""
        if now is None:
            now = datetime.now(UTC)

        async with self._lock:
            if grant_id not in self.grants:
                raise GrantUnknownError(f"Grant {grant_id!r} not found")

            grant = self.grants[grant_id]
            if grant.status != GrantStatus.ISSUED:
                raise GrantReplayError(f"Grant {grant_id!r} already {grant.status.value}")

            if grant.expires_at <= now:
                grant.status = GrantStatus.EXPIRED
                raise GrantExpiredError(f"Grant {grant_id!r} expired at {grant.expires_at}")

            grant.status = GrantStatus.CONSUMED
            grant.consumed_at = now
            return grant

    # ─── Approvals ─────────────────────────────────────────────────────────────

    async def put_approval(self, approval: ApprovalRecord) -> None:
        async with self._lock:
            self.approvals[approval.approval_id] = approval

    async def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        async with self._lock:
            return self.approvals.get(approval_id)

    async def list_approvals(self, task_id: str) -> list[ApprovalRecord]:
        async with self._lock:
            return [a for a in self.approvals.values() if a.task_id == task_id]

    async def list_all_approvals(
        self, limit: int | None = DEFAULT_LIST_LIMIT
    ) -> list[ApprovalRecord]:
        """Read-only approval queue listing for the console Approvals view (unsorted)."""
        async with self._lock:
            listed = [a.model_copy() for a in self.approvals.values()]
            return listed if limit is None else listed[:limit]

    async def list_event_receipts(
        self, task_id: str, limit: int | None = DEFAULT_LIST_LIMIT
    ) -> list[dict[str, Any]]:
        """Read-only idempotency receipts for the console Task Inspector."""
        async with self._lock:
            listed = [dict(r) for r in self.event_receipts.values() if r.get("task_id") == task_id]
            return listed if limit is None else listed[:limit]

    # ─── Event Receipt Idempotency ─────────────────────────────────────────────

    async def reserve_event_receipt(
        self,
        envelope: EventEnvelope,
        now: datetime | None = None,
        lease_seconds: int = 300,
    ) -> bool:
        """Transactionally record event_id.

        Returns True when processing may proceed (new receipt, or a stale
        "processing" receipt whose lease has expired). Returns False when the
        event is already complete or still actively leased.
        """
        if now is None:
            now = datetime.now(UTC)

        async with self._lock:
            existing = self.event_receipts.get(envelope.event_id)
            if existing is None:
                self.event_receipts[envelope.event_id] = {
                    "event_id": envelope.event_id,
                    "event_type": envelope.event_type.value,
                    "task_id": envelope.task_id,
                    "status": "processing",
                    "attempt_count": 1,
                    "first_seen_at": now.isoformat(),
                }
                return True

            if existing.get("status") == "complete":
                return False

            raw_first_seen = existing.get("first_seen_at")
            first_seen = (
                datetime.fromisoformat(raw_first_seen) if isinstance(raw_first_seen, str) else now
            )
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=UTC)

            age = now - first_seen
            if age >= timedelta(seconds=lease_seconds):
                attempt_count = int(existing.get("attempt_count", 1))
                existing["attempt_count"] = attempt_count + 1
                existing["first_seen_at"] = now.isoformat()
                return True

            return False

    async def mark_event_complete(self, event_id: str) -> None:
        async with self._lock:
            if event_id in self.event_receipts:
                self.event_receipts[event_id]["status"] = "complete"
                self.event_receipts[event_id]["completed_at"] = datetime.now(UTC).isoformat()

    # ─── Audit Events Chain ────────────────────────────────────────────────────

    async def append_audit_event(self, event: AuditEvent) -> None:
        async with self._lock:
            if event.task_id not in self.audit_events_by_task:
                self.audit_events_by_task[event.task_id] = []
            self.audit_events_by_task[event.task_id].append(event)

    async def get_audit_events(self, task_id: str) -> list[AuditEvent]:
        async with self._lock:
            return list(self.audit_events_by_task.get(task_id, []))
