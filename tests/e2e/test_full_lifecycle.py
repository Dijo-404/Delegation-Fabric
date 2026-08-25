"""End-to-end lifecycle tests.

Exercises the full Delegation Fabric flow in-process across Control Plane,
Execution Gateway and Worker on a shared store:

1. Human delegation -> grant issuance -> single-use execution -> replay denial.
2. Approval + separation of duties gating for payment.instruct.
3. Audit chain verification after execution.
4. Worker Pub/Sub event processing with duplicate-delivery idempotency.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import JWSGrantVerifier, LocalKMSSigner
from httpx import ASGITransport, AsyncClient

from apps.control_plane.main import create_app as create_control_plane
from apps.execution_gateway.main import create_app as create_execution_gateway
from apps.worker.main import create_app as create_worker


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def kms_signer() -> LocalKMSSigner:
    return LocalKMSSigner()


@pytest.fixture
def jws_verifier(kms_signer: LocalKMSSigner) -> JWSGrantVerifier:
    verifier = JWSGrantVerifier()
    verifier.register_public_key(kms_signer.key_version, kms_signer.get_public_key_pem())
    return verifier


async def _create_delegation(cp: AsyncClient, task_id: str) -> str:
    resp = await cp.post(
        "/v1/delegations",
        json={
            "purpose": "weekly_vendor_settlement",
            "task_id": task_id,
            "allowed_agents": [
                "invoice-reconciliation",
                "procurement-exception",
                "treasury-approval",
            ],
            "allowed_regions": ["asia-south1"],
            "expires_at": "2026-09-01T00:00:00Z",
        },
        headers={"x-authenticated-user": "user:priya@example.com"},
    )
    assert resp.status_code == 201
    return resp.json()["delegation_id"]


async def _issue_grant(
    cp: AsyncClient,
    delegation_id: str,
    task_id: str,
    tool: str,
    arguments: dict[str, Any],
    agent_id: str = "invoice-reconciliation",
    agent_version: str = "1.0.0",
) -> dict[str, Any]:
    return (
        await cp.post(
            "/v1/grants/evaluate",
            json={
                "task_id": task_id,
                "delegation_id": delegation_id,
                "agent": {"id": agent_id, "version": agent_version},
                "tool": tool,
                "arguments": arguments,
            },
        )
    ).json()


async def _execute(
    gw: AsyncClient,
    token: str,
    tool: str,
    arguments: dict[str, Any],
    agent_id: str = "invoice-reconciliation",
    agent_version: str = "1.0.0",
) -> dict[str, Any]:
    return (
        await gw.post(
            "/v1/execute",
            json={"tool": tool, "arguments": arguments},
            headers={
                "Authorization": f"Bearer {token}",
                "X-Agent-Id": agent_id,
                "X-Agent-Version": agent_version,
            },
        )
    ).json()


@pytest.mark.asyncio
async def test_e2e_happy_path_replay_denial_and_audit_chain(
    store: MemoryStore,
    kms_signer: LocalKMSSigner,
    jws_verifier: JWSGrantVerifier,
) -> None:
    """Delegation -> read invoice -> projected fields -> replay denied -> chain verifies."""
    task_id = "task_e2e_001"
    cp = create_control_plane(store=store, signer=kms_signer)
    gw = create_execution_gateway(store=store, verifier=jws_verifier)

    async with (
        AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp.test") as cp_c,
        AsyncClient(transport=ASGITransport(app=gw), base_url="http://gw.test") as gw_c,
    ):
        delegation_id = await _create_delegation(cp_c, task_id)

        grant = await _issue_grant(
            cp_c,
            delegation_id,
            task_id,
            "invoice.read",
            {"invoice_id": "INV-042"},
        )
        assert grant["decision"] == "allow"
        token = grant["token"]

        result = await _execute(gw_c, token, "invoice.read", {"invoice_id": "INV-042"})
        # Field-level projection must exclude internal bank account data
        assert result["result"] == {
            "invoice_id": "INV-042",
            "vendor_id": "V-1001",
            "po_id": "PO-882",
            "total_minor": 74200000,
            "currency": "INR",
            "status": "pending",
        }
        assert "bank_account_internal" not in result["result"]

        # Single-use: exact same token replayed must be denied
        replay_status = (
            await gw_c.post(
                "/v1/execute",
                json={"tool": "invoice.read", "arguments": {"invoice_id": "INV-042"}},
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Agent-Id": "invoice-reconciliation",
                    "X-Agent-Version": "1.0.0",
                },
            )
        ).status_code
        assert replay_status == 403

        # Wrong-tool binding with a valid-looking token shape is denied at CP
        escalation = await _issue_grant(
            cp_c,
            delegation_id,
            task_id,
            "payment.instruct",
            {"batch_id": "PB-99", "amount_minor": 100, "currency": "INR"},
        )
        assert escalation["decision"] == "deny"

        verify = (await cp_c.get(f"/v1/audit/tasks/{task_id}/verify")).json()
        assert verify["valid"] is True
        assert verify["events"] >= 1


@pytest.mark.asyncio
async def test_e2e_payment_requires_approval_and_sod(
    store: MemoryStore,
    kms_signer: LocalKMSSigner,
    jws_verifier: JWSGrantVerifier,
) -> None:
    """payment.instruct denied without approval; allowed only with SOD-valid approval."""
    task_id = "task_e2e_002"
    payment_args = {"batch_id": "PB-88", "amount_minor": 74200000, "currency": "INR"}
    cp = create_control_plane(store=store, signer=kms_signer)
    gw = create_execution_gateway(store=store, verifier=jws_verifier)

    async with (
        AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp.test") as cp_c,
        AsyncClient(transport=ASGITransport(app=gw), base_url="http://gw.test") as gw_c,
    ):
        delegation_id = await _create_delegation(cp_c, task_id)

        # Denied: no approval yet
        pre = await _issue_grant(
            cp_c,
            delegation_id,
            task_id,
            "payment.instruct",
            payment_args,
            agent_id="treasury-approval",
            agent_version="1.0.3",
        )
        assert pre["decision"] == "deny"
        assert pre["reason_code"] == "APPROVAL_REQUIRED"

        # Sponsor cannot self-approve (separation of duties)
        self_resp = await cp_c.post(
            "/v1/approvals",
            json={
                "task_id": task_id,
                "delegation_id": delegation_id,
                "approval_type": "payment_batch",
                "subject": payment_args,
            },
            headers={"x-authenticated-user": "user:priya@example.com"},
        )
        assert self_resp.status_code == 201
        sod_denied = await _issue_grant(
            cp_c,
            delegation_id,
            task_id,
            "payment.instruct",
            payment_args,
            agent_id="treasury-approval",
            agent_version="1.0.3",
        )
        assert sod_denied["decision"] == "deny"
        assert sod_denied["reason_code"] == "SEPARATION_OF_DUTIES_VIOLATION"

        # Distinct human approver unlocks the grant; payment executes once
        other_resp = await cp_c.post(
            "/v1/approvals",
            json={
                "task_id": task_id,
                "delegation_id": delegation_id,
                "approval_type": "payment_batch",
                "subject": payment_args,
            },
            headers={"x-authenticated-user": "user:arun@example.com"},
        )
        assert other_resp.status_code == 201

        pay_grant = await _issue_grant(
            cp_c,
            delegation_id,
            task_id,
            "payment.instruct",
            payment_args,
            agent_id="treasury-approval",
            agent_version="1.0.3",
        )
        assert pay_grant["decision"] == "allow"
        pay_result = await _execute(
            gw_c,
            pay_grant["token"],
            "payment.instruct",
            payment_args,
            agent_id="treasury-approval",
            agent_version="1.0.3",
        )
        assert pay_result["result"]["status"] == "accepted"


@pytest.mark.asyncio
async def test_e2e_worker_event_idempotency_and_checkpoint_resume(
    store: MemoryStore,
) -> None:
    """Pub/Sub push advances task state; duplicate delivery is a harmless no-op."""
    task_id = "task_e2e_003"
    cp = create_control_plane(store=store)
    worker = create_worker(store=store)

    # Task must exist before the worker can transition it
    async with AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp.test") as cp_c:
        await _create_delegation(cp_c, task_id)

    envelope: dict[str, Any] = {
        "event_id": "evt_test_003",
        "event_type": "task.start",
        "task_id": task_id,
        "occurred_at": "2026-08-22T00:00:00Z",
        "source": "control-plane",
        "schema_version": "1",
        "data": {},
    }

    def push_body() -> dict[str, Any]:
        encoded = base64.b64encode(json.dumps(envelope).encode()).decode()
        return {"message": {"data": encoded}, "subscription": "sub-test"}

    async with (
        AsyncClient(transport=ASGITransport(app=worker), base_url="http://w.test") as w_c,
    ):
        first = (await w_c.post("/internal/events/pubsub", json=push_body())).json()
        assert first["status"] == "processed"

        dup = (await w_c.post("/internal/events/pubsub", json=push_body())).json()
        assert dup["status"] == "duplicate_ignored"

    # Task state advanced exactly once despite duplicate delivery
    async with AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp.test") as cp_c:
        task = (await cp_c.get(f"/v1/tasks/{task_id}")).json()

    from delegation_fabric_core.models.task import TaskState

    assert task["state"] == TaskState.RUNNING.value
    assert task["version"] == 2  # CREATED(1) -> RUNNING(2)
