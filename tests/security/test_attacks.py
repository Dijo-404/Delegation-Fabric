"""Adversarial Security Tests.

Proves the two critical hackathon attack containment properties:
1. Attack 1: Poisoned invoice prompts exfiltration/unauthorized tool calls -> Deterministically DENIED (CAPABILITY_NOT_DECLARED / OUTSIDE_BUSINESS_PURPOSE).
2. Attack 2: Cross-agent capability escalation (invoice-reconciliation attempts payment.instruct) -> Deterministically DENIED without grant.
"""

import base64 as b64
import json as jsonlib

import pytest
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import JWSGrantVerifier, LocalKMSSigner
from httpx import ASGITransport, AsyncClient

from apps.control_plane.main import create_app as create_control_plane
from apps.execution_gateway.main import create_app as create_execution_gateway


@pytest.fixture
def shared_store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def kms_signer() -> LocalKMSSigner:
    return LocalKMSSigner()


@pytest.fixture
def jws_verifier(kms_signer: LocalKMSSigner) -> JWSGrantVerifier:
    verifier = JWSGrantVerifier()
    verifier.register_public_key(kms_signer.key_version, kms_signer.get_public_key_pem())
    return verifier


@pytest.mark.asyncio
async def test_attack_1_prompt_injection_denied(
    shared_store: MemoryStore,
    kms_signer: LocalKMSSigner,
    jws_verifier: JWSGrantVerifier,
):
    """Attack 1: Poisoned document instructs agent to read vendor bank account.

    Manifest for invoice-reconciliation explicitly denies vendor_bank_account.read.
    Control Plane denies grant issuance deterministically AND quarantines the task;
    a fresh valid grant on the same task is still blocked at execution time.
    """
    cp_app = create_control_plane(store=shared_store, signer=kms_signer)
    gw_app = create_execution_gateway(store=shared_store, verifier=jws_verifier)

    from apps.worker.main import create_app as create_worker

    worker_app = create_worker(store=shared_store)

    async with (
        AsyncClient(transport=ASGITransport(app=cp_app), base_url="http://cp.test") as cp_client,
        AsyncClient(transport=ASGITransport(app=gw_app), base_url="http://gw.test") as gw_client,
        AsyncClient(
            transport=ASGITransport(app=worker_app), base_url="http://worker.test"
        ) as worker_client,
    ):
        # Create active delegation
        del_resp = await cp_client.post(
            "/v1/delegations",
            json={
                "purpose": "invoice_reconciliation",
                "task_id": "task_poison_001",
                "allowed_agents": ["invoice-reconciliation"],
                "allowed_regions": ["asia-south1"],
                "expires_at": "2026-09-01T00:00:00Z",
            },
            headers={"x-authenticated-user": "user:priya@example.com"},
        )
        delegation_id = del_resp.json()["delegation_id"]

        # Advance the task to RUNNING (quarantine transition is legal only from running)
        envelope = {
            "event_id": "evt_poison_start_001",
            "event_type": "task.start",
            "task_id": "task_poison_001",
            "occurred_at": "2026-08-26T00:00:00Z",
            "source": "control-plane",
            "schema_version": "1",
            "data": {},
        }
        start_resp = await worker_client.post(
            "/internal/events/pubsub",
            json={"message": {"data": b64.b64encode(jsonlib.dumps(envelope).encode()).decode()}},
        )
        assert start_resp.status_code == 200

        # Poisoned model attempts to invoke forbidden tool: vendor_bank_account.read
        attack_resp = await cp_client.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_poison_001",
                "delegation_id": delegation_id,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "vendor_bank_account.read",
                "arguments": {"vendor_id": "V-1001"},
            },
        )

        assert attack_resp.status_code == 403
        data = attack_resp.json()
        # MUST BE DENIED CLOSED
        assert data["decision"] == "deny"
        assert data["reason_code"] == "CAPABILITY_NOT_DECLARED"
        assert "token" not in data

        # Quarantine outcome: the poisoned attempt must move the task to quarantined
        task_resp = await cp_client.get("/v1/tasks/task_poison_001")
        assert task_resp.status_code == 200
        assert task_resp.json()["state"] == "quarantined"

        # Audit chain must carry the quarantine evidence for this task
        audit_resp = await cp_client.get("/v1/audit/tasks/task_poison_001")
        audit_events = audit_resp.json()
        assert any(e["event_type"] == "task.quarantined" for e in audit_events)
        verify = (await cp_client.get("/v1/audit/tasks/task_poison_001/verify")).json()
        assert verify["valid"] is True

        # Defense-in-depth: a fresh, otherwise-valid grant on the quarantined task
        # is still blocked at execution time by gateway task-liveness enforcement.
        fresh = await cp_client.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_poison_001",
                "delegation_id": delegation_id,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "invoice.read",
                "arguments": {"invoice_id": "INV-042"},
            },
        )
        fresh_data = fresh.json()
        if fresh_data.get("decision") == "allow":
            exec_resp = await gw_client.post(
                "/v1/execute",
                json={"tool": "invoice.read", "arguments": {"invoice_id": "INV-042"}},
                headers={
                    "Authorization": f"Bearer {fresh_data['token']}",
                    "X-Agent-Id": "invoice-reconciliation",
                    "X-Agent-Version": "1.0.0",
                },
            )
            assert exec_resp.status_code == 403
            assert exec_resp.json()["detail"]["code"] == "TASK_NOT_LIVE"
        else:
            pytest.fail("Control plane issued no decision for a benign follow-up grant")


@pytest.mark.asyncio
async def test_attack_2_cross_agent_escalation_denied(
    shared_store: MemoryStore,
    kms_signer: LocalKMSSigner,
    jws_verifier: JWSGrantVerifier,
):
    """Attack 2: Invoice reconciliation agent attempts payment.instruct.

    Cross-agent escalation is blocked by manifest capability & delegation ceiling.
    """
    cp_app = create_control_plane(store=shared_store, signer=kms_signer)

    async with AsyncClient(
        transport=ASGITransport(app=cp_app), base_url="http://cp.test"
    ) as cp_client:
        del_resp = await cp_client.post(
            "/v1/delegations",
            json={
                "purpose": "invoice_reconciliation",
                "task_id": "task_escalate_002",
                "allowed_agents": ["invoice-reconciliation"],
                "allowed_regions": ["asia-south1"],
                "expires_at": "2026-09-01T00:00:00Z",
            },
            headers={"x-authenticated-user": "user:priya@example.com"},
        )
        delegation_id = del_resp.json()["delegation_id"]

        # invoice-reconciliation agent attempts payment instruction
        attack_resp = await cp_client.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_escalate_002",
                "delegation_id": delegation_id,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "payment.instruct",
                "arguments": {"batch_id": "PB-88", "amount_minor": 74200000, "currency": "INR"},
            },
        )

        assert attack_resp.status_code == 403
        data = attack_resp.json()
        assert data["decision"] == "deny"
        assert data["reason_code"] == "CAPABILITY_NOT_DECLARED"
        assert "token" not in data
