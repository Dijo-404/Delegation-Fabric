"""Quarantine and human-release flow (PLAN.md Day 5, API_CONTRACTS § 9)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import JWSGrantVerifier, LocalKMSSigner
from httpx import ASGITransport, AsyncClient

from apps.control_plane.main import create_app as create_control_plane
from apps.execution_gateway.main import create_app as create_execution_gateway


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def kms() -> LocalKMSSigner:
    return LocalKMSSigner()


@pytest.fixture
def verifier(kms: LocalKMSSigner) -> JWSGrantVerifier:
    v = JWSGrantVerifier()
    v.register_public_key(kms.key_version, kms.get_public_key_pem())
    return v


async def _setup(cp: AsyncClient) -> str:
    resp = await cp.post(
        "/v1/delegations",
        json={
            "purpose": "weekly_vendor_settlement",
            "task_id": "task_poison_01",
            "allowed_agents": ["invoice-reconciliation", "treasury-approval"],
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert resp.status_code == 201
    return resp.json()["delegation_id"]


@pytest.mark.asyncio
async def test_poisoned_request_quarantines_task_and_release_restores(
    store: MemoryStore, kms: LocalKMSSigner, verifier: JWSGrantVerifier
) -> None:
    cp = create_control_plane(store=store, signer=kms)
    gw = create_execution_gateway(store=store, verifier=verifier)
    from apps.worker.main import create_app as create_worker

    worker = create_worker(store=store)

    async with (
        AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c,
        AsyncClient(transport=ASGITransport(app=gw), base_url="http://gw") as _g,
        AsyncClient(transport=ASGITransport(app=worker), base_url="http://w") as w,
    ):
        did = await _setup(c)

        # Advance task to RUNNING via a task.start event (worker)
        import base64 as b64
        import json as jsonlib

        envelope = {
            "event_id": "evt_start_01",
            "event_type": "task.start",
            "task_id": "task_poison_01",
            "occurred_at": datetime.now(UTC).isoformat(),
            "source": "control-plane",
            "schema_version": "1",
            "data": {},
        }
        start_resp = await w.post(
            "/internal/events/pubsub",
            json={"message": {"data": b64.b64encode(jsonlib.dumps(envelope).encode()).decode()}},
        )
        assert start_resp.status_code == 200

        grant = (
            await c.post(
                "/v1/grants/evaluate",
                json={
                    "task_id": "task_poison_01",
                    "delegation_id": did,
                    "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                    "tool": "invoice.read",
                    "arguments": {"invoice_id": "INV-042"},
                },
            )
        ).json()
        assert grant["decision"] == "allow"
        assert (await c.get("/v1/tasks/task_poison_01")).json()["state"] == "running"

        # Poisoned document drives a capability-violating request -> deny + quarantine
        poison = await c.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_poison_01",
                "delegation_id": did,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "vendor_bank_account.read",
                "arguments": {"vendor_id": "V-1001"},
            },
        )
        assert poison.status_code == 403
        assert poison.json()["reason_code"] == "CAPABILITY_NOT_DECLARED"

        task = (await c.get("/v1/tasks/task_poison_01")).json()
        assert task["state"] == "quarantined"

        # Denial evidence is in the audit chain; chain verifies
        audit = (await c.get("/v1/audit/tasks/task_poison_01")).json()
        assert any(
            e["event_type"] == "policy.denied" and e["reason_code"] == "CAPABILITY_NOT_DECLARED"
            for e in audit
        )
        verify = (await c.get("/v1/audit/tasks/task_poison_01/verify")).json()
        assert verify["valid"] is True

        # Release requires matching expected_state (optimistic validation)
        conflict = await c.post(
            "/v1/tasks/task_poison_01/release",
            json={"expected_state": "running", "reason": "bad expectation"},
        )
        assert conflict.status_code == 409

        release = await c.post(
            "/v1/tasks/task_poison_01/release",
            json={"expected_state": "quarantined", "reason": "document manually reviewed"},
            headers={"x-authenticated-user": "user:priya@example.com"},
        )
        assert release.status_code == 200
        body = release.json()
        assert body["state"] == "resuming"

        released_audit = (await c.get("/v1/audit/tasks/task_poison_01")).json()
        assert any(e["event_type"] == "task.released" for e in released_audit)
