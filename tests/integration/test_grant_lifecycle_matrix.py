"""Integration tests for the grant lifecycle matrix (AUTHORIZATION § 13)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import JWSGrantVerifier, LocalKMSSigner
from httpx import ASGITransport, AsyncClient

from apps.control_plane.main import create_app as create_control_plane
from apps.execution_gateway.main import create_app as create_execution_gateway

PAYMENT_ARGS = {"batch_id": "PB-88", "amount_minor": 74200000, "currency": "INR"}


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


async def _setup(
    cp: AsyncClient,
    task_id: str = "task_matrix",
    purpose: str = "weekly_vendor_settlement",
) -> str:
    resp = await cp.post(
        "/v1/delegations",
        json={
            "purpose": purpose,
            "task_id": task_id,
            "allowed_agents": ["invoice-reconciliation", "treasury-approval"],
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert resp.status_code == 201
    return resp.json()["delegation_id"]


async def _evaluate(
    cp: AsyncClient,
    delegation_id: str,
    task_id: str,
    tool: str,
    arguments: dict[str, Any],
    agent_id: str = "treasury-approval",
    agent_version: str = "1.0.3",
) -> Any:
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
) -> Any:
    return await gw.post(
        "/v1/execute",
        json={"tool": tool, "arguments": arguments},
        headers={
            "Authorization": f"Bearer {token}",
            "X-Agent-Id": agent_id,
            "X-Agent-Version": agent_version,
        },
    )


@pytest.mark.asyncio
async def test_agent_version_mismatch_denied(store: MemoryStore, kms: LocalKMSSigner) -> None:
    cp = create_control_plane(store=store, signer=kms)
    async with AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c:
        did = await _setup(c)
        res = await _evaluate(
            c, did, "task_matrix", "payment.instruct", PAYMENT_ARGS, agent_version="9.9.9"
        )
        assert res["decision"] == "deny"
        assert res["reason_code"] == "AGENT_VERSION_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_unknown_purpose_rejected_at_delegation_creation(
    store: MemoryStore, kms: LocalKMSSigner
) -> None:
    cp = create_control_plane(store=store, signer=kms)
    async with AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c:
        resp = await c.post(
            "/v1/delegations",
            json={
                "purpose": "crypto_airdrop_frenzy",
                "task_id": "t1",
                "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            },
        )
        assert resp.status_code == 422


@pytest.mark.asyncio
async def test_expired_grant_rejected_at_gateway(
    store: MemoryStore, kms: LocalKMSSigner, verifier: JWSGrantVerifier
) -> None:
    from delegation_fabric_core.models.grant import ExecutionGrant

    gw = create_execution_gateway(store=store, verifier=verifier)
    expired_grant = ExecutionGrant.model_validate(
        {
            "jti": "grt_old",
            "iss": "delegation-fabric-control-plane",
            "aud": "delegation-fabric-execution-gateway",
            "delegation_id": "dlg_x",
            "task_id": "t1",
            "agent_id": "invoice-reconciliation",
            "agent_version": "1.0.0",
            "human_sponsor": "u",
            "purpose": "p",
            "tool": "invoice.read",
            "allowed_response_fields": ["invoice_id"],
            "region": "asia-south1",
            "iat": 1000,
            "nbf": 1000,
            "exp": 2000,
            "policy_version": "v1",
        }
    )
    token = kms.sign_grant(expired_grant)
    async with AsyncClient(transport=ASGITransport(app=gw), base_url="http://gw") as g:
        resp = await _execute(g, token, "invoice.read", {"invoice_id": "INV-042"})
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_revoked_delegation_blocks_gateway_execution(
    store: MemoryStore, kms: LocalKMSSigner, verifier: JWSGrantVerifier
) -> None:
    cp = create_control_plane(store=store, signer=kms)
    gw = create_execution_gateway(store=store, verifier=verifier)
    async with (
        AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c,
        AsyncClient(transport=ASGITransport(app=gw), base_url="http://gw") as g,
    ):
        did = await _setup(c)
        grant = await _evaluate(
            c,
            did,
            "task_matrix",
            "invoice.read",
            {"invoice_id": "INV-042"},
            agent_id="invoice-reconciliation",
            agent_version="1.0.0",
        )
        assert grant["decision"] == "allow"

        revoke = await c.post(f"/v1/delegations/{did}/revoke", json={"reason": "fraud_watch"})
        assert revoke.status_code == 200

        resp = await _execute(g, grant["token"], "invoice.read", {"invoice_id": "INV-042"})
        assert resp.status_code == 403  # stale-revocation defense

        # Further issuance also denied
        again = await _evaluate(
            c,
            did,
            "task_matrix",
            "invoice.read",
            {"invoice_id": "INV-042"},
            agent_id="invoice-reconciliation",
            agent_version="1.0.0",
        )
        assert again["decision"] == "deny"


@pytest.mark.asyncio
async def test_wrong_arguments_at_gateway_denied_and_grant_not_reusable(
    store: MemoryStore, kms: LocalKMSSigner, verifier: JWSGrantVerifier
) -> None:
    cp = create_control_plane(store=store, signer=kms)
    gw = create_execution_gateway(store=store, verifier=verifier)
    async with (
        AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c,
        AsyncClient(transport=ASGITransport(app=gw), base_url="http://gw") as g,
    ):
        did = await _setup(c)
        grant = await _evaluate(
            c,
            did,
            "task_matrix",
            "invoice.read",
            {"invoice_id": "INV-042"},
            agent_id="invoice-reconciliation",
            agent_version="1.0.0",
        )
        token = grant["token"]

        # Arguments differ from the pinned grant claims -> deny WITHOUT consuming
        resp = await _execute(g, token, "invoice.read", {"invoice_id": "INV-OTHER"})
        assert resp.status_code == 403

        # Grant was NOT burned by the malformed attempt: correct args succeed
        good = await _execute(g, token, "invoice.read", {"invoice_id": "INV-042"})
        assert good.status_code == 200

        # But it is still strictly single-use: replay now denied
        replay = await _execute(g, token, "invoice.read", {"invoice_id": "INV-042"})
        assert replay.status_code == 403


@pytest.mark.asyncio
async def test_payment_over_policy_cap_denied(
    store: MemoryStore, kms: LocalKMSSigner, verifier: JWSGrantVerifier
) -> None:
    cp = create_control_plane(store=store, signer=kms)
    gw = create_execution_gateway(store=store, verifier=verifier)
    async with (
        AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c,
        AsyncClient(transport=ASGITransport(app=gw), base_url="http://gw"),
    ):
        did = await _setup(c)
        await c.post(
            "/v1/approvals",
            json={
                "task_id": "task_matrix",
                "delegation_id": did,
                "approval_type": "payment_batch",
                "subject": {"batch_id": "PB-BIG", "amount_minor": 500_000_000, "currency": "INR"},
            },
            headers={"x-authenticated-user": "user:arun@example.com"},
        )

        big = dict(PAYMENT_ARGS, batch_id="PB-BIG", amount_minor=500_000_000)
        res = await _evaluate(c, did, "task_matrix", "payment.instruct", big)
        assert res["decision"] == "deny"
        assert res["reason_code"] in {
            "ARGUMENT_CONSTRAINT_FAILED",
            "APPROVAL_SUBJECT_MISMATCH",
        }


@pytest.mark.asyncio
async def test_approval_subject_mismatch_denied(store: MemoryStore, kms: LocalKMSSigner) -> None:
    cp = create_control_plane(store=store, signer=kms)
    async with AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c:
        did = await _setup(c)
        await c.post(
            "/v1/approvals",
            json={
                "task_id": "task_matrix",
                "delegation_id": did,
                "approval_type": "payment_batch",
                "subject": {"batch_id": "PB-DIFFERENT", "amount_minor": 1, "currency": "INR"},
            },
            headers={"x-authenticated-user": "user:arun@example.com"},
        )

        res = await _evaluate(c, did, "task_matrix", "payment.instruct", PAYMENT_ARGS)
        assert res["decision"] == "deny"
        assert res["reason_code"] == "APPROVAL_REQUIRED"


@pytest.mark.asyncio
async def test_wrong_currency_denied_by_policy(store: MemoryStore, kms: LocalKMSSigner) -> None:
    cp = create_control_plane(store=store, signer=kms)
    async with AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c:
        did = await _setup(c)
        usd_args = dict(PAYMENT_ARGS, currency="USD")
        await c.post(
            "/v1/approvals",
            json={
                "task_id": "task_matrix",
                "delegation_id": did,
                "approval_type": "payment_batch",
                "subject": usd_args,
            },
            headers={"x-authenticated-user": "user:arun@example.com"},
        )

        res = await _evaluate(c, did, "task_matrix", "payment.instruct", usd_args)
        assert res["decision"] == "deny"


@pytest.mark.asyncio
async def test_region_mismatch_denied_at_gateway(
    store: MemoryStore, kms: LocalKMSSigner, verifier: JWSGrantVerifier
) -> None:
    gw_us = create_execution_gateway(store=store, verifier=verifier, region="us-central1")
    cp = create_control_plane(store=store, signer=kms)
    async with (
        AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c,
        AsyncClient(transport=ASGITransport(app=gw_us), base_url="http://gw") as g,
    ):
        did = await _setup(c)
        grant = await _evaluate(
            c,
            did,
            "task_matrix",
            "invoice.read",
            {"invoice_id": "INV-042"},
            agent_id="invoice-reconciliation",
            agent_version="1.0.0",
        )
        resp = await _execute(g, grant["token"], "invoice.read", {"invoice_id": "INV-042"})
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_grant_record_endpoint_lifecycle(
    store: MemoryStore, kms: LocalKMSSigner, verifier: JWSGrantVerifier
) -> None:
    cp = create_control_plane(store=store, signer=kms)
    gw = create_execution_gateway(store=store, verifier=verifier)
    async with (
        AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c,
        AsyncClient(transport=ASGITransport(app=gw), base_url="http://gw") as g,
    ):
        did = await _setup(c)
        grant = await _evaluate(
            c,
            did,
            "task_matrix",
            "invoice.read",
            {"invoice_id": "INV-042"},
            agent_id="invoice-reconciliation",
            agent_version="1.0.0",
        )
        gid = grant["grant_id"]

        issued = (await c.get(f"/v1/grants/{gid}")).json()
        assert issued["status"] == "issued"
        assert issued["agent"] == "invoice-reconciliation@1.0.0"

        await _execute(g, grant["token"], "invoice.read", {"invoice_id": "INV-042"})
        consumed = (await c.get(f"/v1/grants/{gid}")).json()
        assert consumed["status"] == "consumed"
