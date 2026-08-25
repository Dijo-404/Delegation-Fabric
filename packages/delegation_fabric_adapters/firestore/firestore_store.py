"""Transactional Firestore store mirroring the MemoryStore async surface.

All Google Cloud Firestore access is imported lazily and blocking SDK calls
are wrapped with asyncio.to_thread so the store is safe to use from async
code. Grant consumption, event receipt reservation, and audit sequencing run
inside Firestore transactions for cross-process atomicity.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

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
from google.cloud.firestore import FieldFilter

from delegation_fabric_adapters.firestore.store import DEFAULT_LIST_LIMIT

if TYPE_CHECKING:
    from google.cloud.firestore_v1.base_document import DocumentSnapshot
    from google.cloud.firestore_v1.transaction import Transaction


def _snapshot(result: Any) -> DocumentSnapshot:
    return cast("DocumentSnapshot", result)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class FirestoreStore:
    """Durable Firestore-backed implementation of the MemoryStore interface."""

    def __init__(self, project_id: str | None = None) -> None:
        from google.cloud import firestore

        self._db = firestore.Client(project=project_id)

    def _doc(self, collection: str, doc_id: str) -> Any:
        """Typed as Any: the SDK stubs union sync/async returns and omit txn kwargs."""
        return self._db.collection(collection).document(doc_id)

    # ─── Delegation CRUD ───────────────────────────────────────────────────────

    async def put_delegation(self, delegation: Delegation) -> None:
        await asyncio.to_thread(
            self._doc("delegations", delegation.delegation_id).set,
            delegation.model_dump(mode="json"),
        )

    async def get_delegation(self, delegation_id: str) -> Delegation | None:
        def _get() -> Delegation | None:
            snap = self._doc("delegations", delegation_id).get()
            if not snap.exists:
                return None
            data = snap.to_dict() or {}
            return Delegation.model_validate(data)

        return await asyncio.to_thread(_get)

    async def list_delegations(self, limit: int | None = DEFAULT_LIST_LIMIT) -> list[Delegation]:
        def _list() -> list[Delegation]:
            query = self._db.collection("delegations").order_by(
                "created_at", direction="DESCENDING"
            )
            if limit is not None:
                query = query.limit(limit)
            docs = query.stream()
            return [Delegation.model_validate(d.to_dict() or {}) for d in docs]

        return await asyncio.to_thread(_list)

    # ─── Task CRUD & Transitions ───────────────────────────────────────────────

    async def put_task(self, task: Task) -> None:
        await asyncio.to_thread(
            self._doc("tasks", task.task_id).set,
            task.model_dump(mode="json"),
        )

    async def get_task(self, task_id: str) -> Task | None:
        def _get() -> Task | None:
            snap = self._doc("tasks", task_id).get()
            if not snap.exists:
                return None
            data = snap.to_dict() or {}
            return Task.model_validate(data)

        return await asyncio.to_thread(_get)

    async def mutate_task_atomic(
        self,
        task_id: str,
        mutator: Callable[[Task], None],
        expected_version: int | None = None,
    ) -> Task:
        """Transactionally apply mutator with optimistic CAS on state_version."""

        def _mutate(transaction: Transaction) -> Task:
            ref = self._doc("tasks", task_id)
            snap = _snapshot(ref.get(transaction=transaction))
            if not snap.exists:
                raise TaskNotFoundError(f"Task {task_id!r} not found")
            data = snap.to_dict() or {}
            current_version = int(data.get("state_version", 0))
            if expected_version is not None and current_version != expected_version:
                raise ConcurrentTaskUpdateError(
                    f"Task {task_id!r} changed: expected v{expected_version}, "
                    f"actual v{current_version}"
                )
            task = Task.model_validate(data)
            mutator(task)
            merged = task.model_dump(mode="json")
            merged["state_version"] = task.state_version
            ref.set(merged, transaction=transaction)
            return task

        def _run() -> Task:
            from google.cloud import firestore

            txn = self._db.transaction()
            return cast("Task", firestore.transactional(_mutate)(txn))

        return await asyncio.to_thread(_run)

    async def put_checkpoint(self, checkpoint: TaskCheckpoint) -> None:
        # Checkpoints are immutable history records; task state is written
        # exclusively via mutate_task_atomic (single writer).

        def _put() -> None:
            payload = checkpoint.model_dump(mode="json")
            self._doc("checkpoints", checkpoint.checkpoint_id).set(payload)

        await asyncio.to_thread(_put)

    async def get_checkpoint(self, checkpoint_id: str) -> TaskCheckpoint | None:
        def _get() -> TaskCheckpoint | None:
            snap = self._doc("checkpoints", checkpoint_id).get()
            if not snap.exists:
                return None
            data = snap.to_dict() or {}
            return TaskCheckpoint.model_validate(data)

        return await asyncio.to_thread(_get)

    async def list_checkpoints(
        self, task_id: str, limit: int | None = DEFAULT_LIST_LIMIT
    ) -> list[TaskCheckpoint]:
        def _list() -> list[TaskCheckpoint]:
            query = (
                self._db.collection("checkpoints")
                .where(filter=FieldFilter("task_id", "==", task_id))
                .order_by("__name__")
            )
            if limit is not None:
                query = query.limit(limit)
            docs = query.stream()
            return [TaskCheckpoint.model_validate(d.to_dict() or {}) for d in docs]

        return await asyncio.to_thread(_list)

    # ─── Grant Lifecycle & Atomic Consumption ───────────────────────────────────

    async def put_grant(self, grant: GrantRecord) -> None:
        await asyncio.to_thread(
            self._doc("grants", grant.grant_id).set,
            grant.model_dump(mode="json"),
        )

    async def get_grant(self, grant_id: str) -> GrantRecord | None:
        def _get() -> GrantRecord | None:
            snap = self._doc("grants", grant_id).get()
            if not snap.exists:
                return None
            data = snap.to_dict() or {}
            return GrantRecord.model_validate(data)

        return await asyncio.to_thread(_get)

    async def list_grants(
        self, task_id: str, limit: int | None = DEFAULT_LIST_LIMIT
    ) -> list[GrantRecord]:
        def _list() -> list[GrantRecord]:
            query = (
                self._db.collection("grants")
                .where(filter=FieldFilter("task_id", "==", task_id))
                .order_by("__name__")
            )
            if limit is not None:
                query = query.limit(limit)
            docs = query.stream()
            return [GrantRecord.model_validate(d.to_dict() or {}) for d in docs]

        return await asyncio.to_thread(_list)

    async def consume_grant_atomic(self, grant_id: str, now: datetime | None = None) -> GrantRecord:
        """Atomically transition grant status from ISSUED to CONSUMED in a transaction."""
        if now is None:
            now = datetime.now(UTC)
        now_iso = now.isoformat()

        def _consume(transaction: Transaction) -> tuple[str, dict[str, Any]]:
            ref = self._doc("grants", grant_id)
            snap = _snapshot(ref.get(transaction=transaction))
            if not snap.exists:
                return "unknown", {}
            data = snap.to_dict() or {}
            grant = GrantRecord.model_validate(data)
            if grant.status != GrantStatus.ISSUED:
                return "replay", data
            if grant.expires_at <= now:
                updated = {**data, "status": GrantStatus.EXPIRED.value}
                ref.set(updated, transaction=transaction)
                return "expired", updated
            updated = {**data, "status": GrantStatus.CONSUMED.value, "consumed_at": now_iso}
            ref.set(updated, transaction=transaction)
            return "ok", updated

        def _run() -> tuple[str, dict[str, Any]]:
            from google.cloud import firestore

            txn = self._db.transaction()
            decorated = firestore.transactional(_consume)
            return cast("tuple[str, dict[str, Any]]", decorated(txn))

        outcome, data = await asyncio.to_thread(_run)

        if outcome == "unknown":
            raise GrantUnknownError(f"Grant {grant_id!r} not found")

        grant = GrantRecord.model_validate(data)
        if outcome == "replay":
            raise GrantReplayError(f"Grant {grant_id!r} already {grant.status.value}")
        if outcome == "expired":
            raise GrantExpiredError(f"Grant {grant_id!r} expired at {grant.expires_at}")

        return grant.model_copy(update={"status": GrantStatus.CONSUMED, "consumed_at": now})

    # ─── Approvals ─────────────────────────────────────────────────────────────

    async def put_approval(self, approval: ApprovalRecord) -> None:
        def _put() -> None:
            self._doc("approvals", approval.approval_id).set(approval.model_dump(mode="json"))

        await asyncio.to_thread(_put)

    async def list_approvals(
        self, task_id: str, limit: int | None = DEFAULT_LIST_LIMIT
    ) -> list[ApprovalRecord]:
        def _list() -> list[ApprovalRecord]:
            query = (
                self._db.collection("approvals")
                .where(filter=FieldFilter("task_id", "==", task_id))
                .order_by("__name__")
            )
            if limit is not None:
                query = query.limit(limit)
            docs = query.stream()
            return [ApprovalRecord.model_validate(d.to_dict() or {}) for d in docs]

        return await asyncio.to_thread(_list)

    async def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        def _get() -> ApprovalRecord | None:
            snap = self._doc("approvals", approval_id).get()
            if not snap.exists:
                return None
            data = snap.to_dict() or {}
            return ApprovalRecord.model_validate(data)

        return await asyncio.to_thread(_get)

    async def list_all_approvals(
        self, limit: int | None = DEFAULT_LIST_LIMIT
    ) -> list[ApprovalRecord]:
        def _list() -> list[ApprovalRecord]:
            query = self._db.collection("approvals").order_by("created_at", direction="DESCENDING")
            if limit is not None:
                query = query.limit(limit)
            docs = query.stream()
            return [ApprovalRecord.model_validate(d.to_dict() or {}) for d in docs]

        return await asyncio.to_thread(_list)

    async def list_event_receipts(
        self, task_id: str, limit: int | None = DEFAULT_LIST_LIMIT
    ) -> list[dict[str, Any]]:
        def _list() -> list[dict[str, Any]]:
            query = (
                self._db.collection("event_receipts")
                .where(filter=FieldFilter("task_id", "==", task_id))
                .order_by("__name__")
            )
            if limit is not None:
                query = query.limit(limit)
            docs = query.stream()
            return [d.to_dict() or {} for d in docs]

        return await asyncio.to_thread(_list)

    # ─── Event Receipt Idempotency ─────────────────────────────────────────────

    async def reserve_event_receipt(
        self, envelope: EventEnvelope, now: datetime | None = None, lease_seconds: int = 300
    ) -> bool:
        """Transactionally record event_id (create-if-not-exists).

        Returns True when newly reserved; False when the receipt already exists.
        A stale 'processing' lease older than the reclaim window may be reclaimed.
        """
        event_id = envelope.event_id

        def _reserve(transaction: Transaction) -> bool:
            ref = self._doc("event_receipts", event_id)
            snap = _snapshot(ref.get(transaction=transaction))
            if snap.exists:
                data = snap.to_dict() or {}
                status = data.get("status")
                first_seen_at = data.get("first_seen_at")
                if status == "complete":
                    return False
                try:
                    first_seen = datetime.fromisoformat(str(first_seen_at))
                except (TypeError, ValueError):
                    # Corrupted receipt: treat as stale so the event is reclaimable.
                    first_seen = datetime.min.replace(tzinfo=UTC)
                now_dt = now or datetime.now(UTC)
                lease_expired = (now_dt - first_seen).total_seconds() > lease_seconds
                if status == "processing" and lease_expired:
                    ref.set(
                        {
                            "event_id": event_id,
                            "event_type": envelope.event_type.value,
                            "task_id": envelope.task_id,
                            "status": "processing",
                            "attempt_count": int(data.get("attempt_count", 0)) + 1,
                            "first_seen_at": _now_iso(),
                        },
                        transaction=transaction,
                    )
                    return True
                return False
            ref.set(
                {
                    "event_id": event_id,
                    "event_type": envelope.event_type.value,
                    "task_id": envelope.task_id,
                    "status": "processing",
                    "first_seen_at": _now_iso(),
                },
                transaction=transaction,
            )
            return True

        def _run() -> bool:
            from google.cloud import firestore

            txn = self._db.transaction()
            decorated = firestore.transactional(_reserve)
            return bool(decorated(txn))

        return await asyncio.to_thread(_run)

    async def mark_event_complete(self, event_id: str) -> None:
        def _mark() -> None:
            ref = self._doc("event_receipts", event_id)
            snap = _snapshot(ref.get())
            if snap.exists:
                ref.update({"status": "complete", "completed_at": _now_iso()})

        await asyncio.to_thread(_mark)

    # ─── Audit Events Chain ────────────────────────────────────────────────────

    async def append_audit_event(self, event: AuditEvent) -> None:
        """Append an audit event under a transactionally assigned sequence number.

        Doc id f"{task_id}:{seq:08d}" guarantees deterministic ordering for the
        hash chain when events are read back ordered by document name.
        """

        def _append(transaction: Transaction) -> None:
            counter_ref = self._doc("audit_counters", event.task_id)
            snap = _snapshot(counter_ref.get(transaction=transaction))
            seq = 0
            if snap.exists:
                seq = int((snap.to_dict() or {}).get("next_seq", 0))
            counter_ref.set(
                {"task_id": event.task_id, "next_seq": seq + 1}, transaction=transaction
            )
            self._doc("audit_events", f"{event.task_id}:{seq:08d}").set(
                event.model_dump(mode="json"), transaction=transaction
            )

        def _run() -> None:
            from google.cloud import firestore

            txn = self._db.transaction()
            decorated = firestore.transactional(_append)
            decorated(txn)

        await asyncio.to_thread(_run)

    async def get_audit_events(
        self, task_id: str, limit: int | None = DEFAULT_LIST_LIMIT
    ) -> list[AuditEvent]:
        def _query() -> list[AuditEvent]:
            query = (
                self._db.collection("audit_events")
                .where(filter=FieldFilter("task_id", "==", task_id))
                .order_by("__name__")
            )
            if limit is not None:
                query = query.limit(limit)
            return [AuditEvent.model_validate(doc.to_dict() or {}) for doc in query.stream()]

        return await asyncio.to_thread(_query)
