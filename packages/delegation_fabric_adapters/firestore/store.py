"""In-memory and transactional Firestore stores for Delegation Fabric."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from delegation_fabric_core.errors.exceptions import (
    GrantExpiredError,
    GrantReplayError,
    GrantUnknownError,
)
from delegation_fabric_core.models.approval import ApprovalRecord
from delegation_fabric_core.models.audit import AuditEvent
from delegation_fabric_core.models.checkpoint import TaskCheckpoint
from delegation_fabric_core.models.delegation import Delegation
from delegation_fabric_core.models.event import EventEnvelope
from delegation_fabric_core.models.grant import GrantRecord, GrantStatus
from delegation_fabric_core.models.task import Task, TaskState


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
            return self.delegations.get(delegation_id)

    # ─── Task CRUD & Transitions ───────────────────────────────────────────────

    async def put_task(self, task: Task) -> None:
        async with self._lock:
            self.tasks[task.task_id] = task

    async def get_task(self, task_id: str) -> Task | None:
        async with self._lock:
            return self.tasks.get(task_id)

    async def put_checkpoint(self, checkpoint: TaskCheckpoint) -> None:
        async with self._lock:
            self.checkpoints[checkpoint.checkpoint_id] = checkpoint
            if checkpoint.task_id in self.tasks:
                task = self.tasks[checkpoint.task_id]
                task.latest_checkpoint_id = checkpoint.checkpoint_id
                task.state = TaskState(checkpoint.state)
                task.state_version = checkpoint.state_version

    async def get_checkpoint(self, checkpoint_id: str) -> TaskCheckpoint | None:
        async with self._lock:
            return self.checkpoints.get(checkpoint_id)

    # ─── Grant Lifecycle & Atomic Consumption ───────────────────────────────────

    async def put_grant(self, grant: GrantRecord) -> None:
        async with self._lock:
            self.grants[grant.grant_id] = grant

    async def get_grant(self, grant_id: str) -> GrantRecord | None:
        async with self._lock:
            return self.grants.get(grant_id)

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

    # ─── Event Receipt Idempotency ─────────────────────────────────────────────

    async def reserve_event_receipt(self, envelope: EventEnvelope) -> bool:
        """Transactionally record event_id. Returns False if already processed."""
        async with self._lock:
            if envelope.event_id in self.event_receipts:
                return False
            self.event_receipts[envelope.event_id] = {
                "event_id": envelope.event_id,
                "event_type": envelope.event_type.value,
                "task_id": envelope.task_id,
                "status": "processing",
                "first_seen_at": datetime.now(UTC).isoformat(),
            }
            return True

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
