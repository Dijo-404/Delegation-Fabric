"""HTTP-level redaction tests for unauthenticated read facades.

The server must never ship raw approval subjects or sponsor PII on read
endpoints; subjects are reduced to their SHA-256 hashes at the serialization
boundary while write paths and internal stores keep full payloads.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_core.models.checkpoint import TaskCheckpoint
from delegation_fabric_core.models.task import Task, TaskState
from httpx import ASGITransport, AsyncClient

from apps.control_plane.main import create_app as create_control_plane

PII_SUBJECT = {
    "display_name": "Priya Sharma",
    "department": "Finance",
    "batch_id": "PB-2026-08-001",
}
SPONSOR_EMAIL = "user:priya@example.com"


def _checkpoint() -> TaskCheckpoint:
    return TaskCheckpoint(
        checkpoint_id="cp_pii_1",
        task_id="task_redact",
        state="awaiting_approval",
        state_version=2,
        session_id="session_redact",
        agent_id="invoice-reconciliation",
        agent_version="1.0.0",
        created_at=datetime.now(UTC),
        pending_subject=dict(PII_SUBJECT),
    )


async def test_read_facades_never_expose_raw_subject_or_sponsor_pii() -> None:
    store = MemoryStore()
    await store.put_checkpoint(_checkpoint())
    app = create_control_plane(store=store)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://cp.test") as cp:
        resp = await cp.post(
            "/v1/delegations",
            json={
                "purpose": "weekly_vendor_settlement",
                "task_id": "task_redact",
                "allowed_agents": ["invoice-reconciliation"],
                "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            },
            headers={"x-authenticated-user": SPONSOR_EMAIL},
        )
        assert resp.status_code == 201
        delegation_id = resp.json()["delegation_id"]

        approval_resp = await cp.post(
            "/v1/approvals",
            json={
                "task_id": "task_redact",
                "delegation_id": delegation_id,
                "approval_type": "payment_batch",
                "subject": dict(PII_SUBJECT),
            },
            headers={"x-authenticated-user": "user:arun@example.com"},
        )
        assert approval_resp.status_code == 201
        stored = await store.get_approval(approval_resp.json()["approval_id"])
        assert stored is not None
        approval_hash = stored.subject_hash

        delegations = (await cp.get("/v1/delegations")).json()
        assert len(delegations) == 1
        sponsor = delegations[0]["sponsor"]
        assert set(sponsor) == {"subject_hash"}
        assert sponsor["subject_hash"].startswith("sha256:")
        assert "display_name" not in sponsor and "department" not in sponsor
        body = str(delegations)
        assert SPONSOR_EMAIL not in body
        assert "Priya Sharma" not in body and "Finance" not in body

        detail = (await cp.get(f"/v1/delegations/{delegation_id}")).json()
        assert detail["sponsor"] == {"subject_hash": sponsor["subject_hash"]}

        approvals = (await cp.get("/v1/approvals")).json()
        assert len(approvals) == 1
        listed = approvals[0]
        assert "subject" not in listed
        assert listed["subject_hash"] == approval_hash
        body = str(approvals)
        assert "Priya Sharma" not in body and "Finance" not in body
        assert PII_SUBJECT["batch_id"] not in body

        depth = (await cp.get("/v1/tasks/task_redact/depth")).json()
        assert len(depth["checkpoints"]) == 1
        checkpoint_view = depth["checkpoints"][0]
        assert "pending_subject" not in checkpoint_view
        assert checkpoint_view["pending_subject_hash"].startswith("sha256:")
        assert all("subject" not in a for a in depth["approvals"])
        assert all(a["subject_hash"].startswith("sha256:") for a in depth["approvals"])
        depth_body = str(depth)
        assert "Priya Sharma" not in depth_body and "Finance" not in depth_body


async def test_depth_checkpoint_without_pending_subject_has_no_hash_key() -> None:
    store = MemoryStore()
    bare = _checkpoint().model_copy(update={"pending_subject": None})
    now = datetime.now(UTC)
    await store.put_checkpoint(bare)
    await store.put_task(
        Task(
            task_id=bare.task_id,
            delegation_id="dlg_redact",
            state=TaskState.CREATED,
            state_version=1,
            policy_version="finance-policy-2026-08-20.1",
            created_at=now,
            updated_at=now,
        )
    )
    app = create_control_plane(store=store)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://cp.test") as cp:
        depth = (await cp.get(f"/v1/tasks/{bare.task_id}/depth")).json()
        assert depth["checkpoints"][0].get("pending_subject") is None
        assert "pending_subject_hash" not in depth["checkpoints"][0]
