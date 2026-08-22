"""Adversarial Security Tests.

Proves the two critical hackathon attack containment properties:
1. Attack 1: Poisoned invoice prompts exfiltration/unauthorized tool calls -> Deterministically DENIED (CAPABILITY_NOT_DECLARED / OUTSIDE_BUSINESS_PURPOSE).
2. Attack 2: Cross-agent capability escalation (invoice-reconciliation attempts payment.instruct) -> Deterministically DENIED without grant.
"""

import pytest
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import JWSGrantVerifier, LocalKMSSigner
from httpx import ASGITransport, AsyncClient

from apps.control_plane.main import create_app as create_control_plane


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
    Control Plane denies grant issuance deterministically.
    """
    cp_app = create_control_plane(store=shared_store, signer=kms_signer)

    async with AsyncClient(
        transport=ASGITransport(app=cp_app), base_url="http://cp.test"
    ) as cp_client:
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
