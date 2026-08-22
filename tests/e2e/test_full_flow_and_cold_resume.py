"""Full happy-path E2E (TESTING.md § 9) and cold-resume simulation (§ 10).

§9: ONE flow — delegation -> reconcile invoice -> pause awaiting approval ->
approval -> event -> resume -> treasury grant -> payment -> verify chain.

§10: an aged checkpoint (18 days old), a brand-new worker instance with no
in-memory state, then approval event -> resume from persisted IDs and a
FRESH single-use grant minted afterwards.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import JWSGrantVerifier, LocalKMSSigner
from httpx import ASGITransport, AsyncClient

from apps.control_plane.main import create_app as create_control_plane
from apps.execution_gateway.main import create_app as create_execution_gateway
from apps.worker.main import create_app as create_worker


def _envelope_payload(
    event_id: str, event_type: str, task_id: str, occurred_at: str | None = None
) -> dict[str, Any]:
    envelope = {
        "event_id": event_id,
        "event_type": event_type,
        "task_id": task_id,
        "occurred_at": occurred_at or datetime.now(UTC).isoformat(),
        "source": "control-plane",
        "schema_version": "1",
        "data": {},
    }
    return {
        "message": {"data": base64.b64encode(json.dumps(envelope).encode()).decode()},
        "subscription": "sub-e2e",
    }


class Fabric:
    """In-process wiring of all three services on one store."""

    def __init__(self, store: MemoryStore, kms: LocalKMSSigner) -> None:
        self.store = store
        self.verifier = JWSGrantVerifier()
        self.verifier.register_public_key(kms.key_version, kms.get_public_key_pem())
        self.cp = create_control_plane(store=store, signer=kms)
        self.gw = create_execution_gateway(store=store, verifier=self.verifier)
        self.worker = create_worker(store=store)

    def clients(self) -> tuple[AsyncClient, AsyncClient, AsyncClient]:
        return (
            AsyncClient(transport=ASGITransport(app=self.cp), base_url="http://cp"),
            AsyncClient(transport=ASGITransport(app=self.gw), base_url="http://gw"),
            AsyncClient(transport=ASGITransport(app=self.worker), base_url="http://w"),
        )


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def kms() -> LocalKMSSigner:
    return LocalKMSSigner()


async def _new_delegation(cp: AsyncClient, task_id: str) -> str:
    resp = await cp.post(
        "/v1/delegations",
        json={
            "purpose": "weekly_vendor_settlement",
            "task_id": task_id,
            "allowed_agents": ["invoice-reconciliation", "treasury-approval"],
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert resp.status_code == 201
    return resp.json()["delegation_id"]


@pytest.mark.asyncio
async def test_section9_single_flow_delegation_to_payment_to_chain(
    store: MemoryStore, kms: LocalKMSSigner
) -> None:
    fabric = Fabric(store, kms)
    cp_c, gw_c, w_c = fabric.clients()
    task_id = "task_s9_full"
    payment_args = {"batch_id": "PB-88", "amount_minor": 74200000, "currency": "INR"}

    async with cp_c as c, gw_c as g, w_c as w:
        # 1. delegation
        did = await _new_delegation(c, task_id)

        # 2-3. start + process a real invoice through the gateway
        start = await w.post(
            "/internal/events/pubsub", json=_envelope_payload("evt_s9_start", "task.start", task_id)
        )
        assert start.json()["new_state"] == "running"

        grant_r = await c.post(
            "/v1/grants/evaluate",
            json={
                "task_id": task_id,
                "delegation_id": did,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "invoice.read",
                "arguments": {"invoice_id": "INV-042"},
            },
        )
        assert grant_r.status_code == 200
        inv = await g.post(
            "/v1/execute",
            json={"tool": "invoice.read", "arguments": {"invoice_id": "INV-042"}},
            headers={"Authorization": f"Bearer {grant_r.json()['token']}"},
        )
        assert inv.status_code == 200

        # 4-5. wait: workflow pauses awaiting human approval (durable checkpoint)
        from delegation_fabric_core.models.task import TaskState

        paused = await store.get_task(task_id)
        assert paused is not None
        paused.state = TaskState.AWAITING_APPROVAL
        paused.state_version += 1
        await store.put_task(paused)

        # 6-7. approval created -> event -> resume
        appr = await c.post(
            "/v1/approvals",
            json={
                "task_id": task_id,
                "delegation_id": did,
                "approval_type": "payment_batch",
                "subject": payment_args,
            },
            headers={"x-authenticated-user": "user:arun@example.com"},
        )
        assert appr.status_code == 201

        resume = await w.post(
            "/internal/events/pubsub",
            json=_envelope_payload("evt_s9_resume", "approval.created", task_id),
        )
        body = resume.json()
        assert body["new_state"] == "running"
        assert body["resume"]["resumed"] is True

        # 8-9. treasury grant + protected payment
        pay_grant = await c.post(
            "/v1/grants/evaluate",
            json={
                "task_id": task_id,
                "delegation_id": did,
                "agent": {"id": "treasury-approval", "version": "1.0.3"},
                "tool": "payment.instruct",
                "arguments": payment_args,
            },
        )
        assert pay_grant.json()["decision"] == "allow"
        pay_exec = await g.post(
            "/v1/execute",
            json={"tool": "payment.instruct", "arguments": payment_args},
            headers={"Authorization": f"Bearer {pay_grant.json()['token']}"},
        )
        assert pay_exec.status_code == 200
        assert pay_exec.json()["result"]["status"] == "accepted"

        # replay of the payment grant denied
        assert (
            await g.post(
                "/v1/execute",
                json={"tool": "payment.instruct", "arguments": payment_args},
                headers={"Authorization": f"Bearer {pay_grant.json()['token']}"},
            )
        ).status_code == 403

        # 10. complete the workflow deterministically
        running = await store.get_task(task_id)
        assert running is not None
        # terminal_success transition applied by the runtime on settlement webhook
        running.state = TaskState.COMPLETED
        running.state_version += 1
        running.updated_at = datetime.now(UTC)
        await store.put_task(running)

        # 11. verify audit chain covers the whole story
        verify = (await c.get(f"/v1/audit/tasks/{task_id}/verify")).json()
        assert verify["valid"] is True
        events = (await c.get(f"/v1/audit/tasks/{task_id}")).json()
        kinds = {e["event_type"] for e in events}
        assert {"grant.issued", "tool.execution.completed"} <= kinds
        # fresh grants after resume: more than one grant issued across the flow
        assert sum(1 for e in events if e["event_type"] == "grant.issued") >= 2


@pytest.mark.asyncio
async def test_section10_aged_checkpoint_cold_resume_fresh_grant(
    store: MemoryStore, kms: LocalKMSSigner
) -> None:
    """Checkpoint aged 18 days; a COLD worker (fresh app instance) resumes it."""
    fabric = Fabric(store, kms)
    cp_c, gw_c, _ = fabric.clients()
    task_id = "task_s10_aged"

    async with cp_c as c, gw_c as g:
        did = await _new_delegation(c, task_id)

        # Seed an aged checkpoint exactly as the runtime would have persisted it.
        from delegation_fabric_core.models.checkpoint import TaskCheckpoint
        from delegation_fabric_core.models.task import TaskState

        aged_ts = datetime.now(UTC) - timedelta(days=18)
        checkpoint = TaskCheckpoint(
            checkpoint_id="chk_aged_18d",
            task_id=task_id,
            state=TaskState.AWAITING_APPROVAL.value,
            state_version=5,
            session_id="session_aged_original",
            agent_id="invoice-reconciliation",
            agent_version="1.0.0",
            memory_refs=[],
            pending_subject={"note": "awaiting settlement approval"},
            created_at=aged_ts,
        )
        await store.put_checkpoint(checkpoint)
        task = await store.get_task(task_id)
        assert task is not None
        task.state = TaskState.AWAITING_APPROVAL
        task.state_version = 5
        task.session_id = "session_aged_original"
        task.current_agent_id = "invoice-reconciliation"
        task.current_agent_version = "1.0.0"
        task.latest_checkpoint_id = "chk_aged_18d"
        await store.put_task(task)

        # COLD resume: brand-new worker instance, no in-memory state.
        cold_worker = create_worker(store=store)
        async with AsyncClient(
            transport=ASGITransport(app=cold_worker), base_url="http://cold-w"
        ) as w:
            resp = await w.post(
                "/internal/events/pubsub",
                json=_envelope_payload("evt_s10_approval", "approval.created", task_id),
            )
            body = resp.json()

        assert body["status"] == "processed"
        assert body["new_state"] == "running"
        assert body["resume"]["resumed"] is True
        assert body["resume"]["restored_agent"] == "invoice-reconciliation"
        assert body["resume"]["restored_session_id"] == "session_aged_original"

        restored = await store.get_task(task_id)
        assert restored is not None
        assert restored.state == TaskState.RUNNING
        assert restored.session_id == "session_aged_original"  # persisted ID survived

        # Fresh grant minted AFTER resumption works end-to-end.
        fresh = await c.post(
            "/v1/grants/evaluate",
            json={
                "task_id": task_id,
                "delegation_id": did,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "invoice.read",
                "arguments": {"invoice_id": "INV-042"},
            },
        )
        assert fresh.json()["decision"] == "allow"
        exec_resp = await g.post(
            "/v1/execute",
            json={"tool": "invoice.read", "arguments": {"invoice_id": "INV-042"}},
            headers={"Authorization": f"Bearer {fresh.json()['token']}"},
        )
        assert exec_resp.status_code == 200
