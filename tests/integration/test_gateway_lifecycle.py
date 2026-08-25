"""Integration tests for Control Plane, KMS, and Execution Gateway lifecycle."""

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


@pytest.fixture(autouse=True)
def _reset_metrics() -> None:
    from delegation_fabric_adapters.observability import METRICS

    METRICS.reset()


@pytest.fixture
def jws_verifier(kms_signer: LocalKMSSigner) -> JWSGrantVerifier:
    verifier = JWSGrantVerifier()
    verifier.register_public_key(kms_signer.key_version, kms_signer.get_public_key_pem())
    return verifier


@pytest.mark.asyncio
async def test_full_grant_evaluation_and_execution_lifecycle(
    shared_store: MemoryStore,
    kms_signer: LocalKMSSigner,
    jws_verifier: JWSGrantVerifier,
):
    cp_app = create_control_plane(store=shared_store, signer=kms_signer)
    gw_app = create_execution_gateway(store=shared_store, verifier=jws_verifier)

    async with (
        AsyncClient(transport=ASGITransport(app=cp_app), base_url="http://cp.test") as cp_client,
        AsyncClient(transport=ASGITransport(app=gw_app), base_url="http://gw.test") as gw_client,
    ):
        # 1. Create Delegation
        del_resp = await cp_client.post(
            "/v1/delegations",
            json={
                "purpose": "invoice_reconciliation",
                "task_id": "task_1001",
                "allowed_agents": ["invoice-reconciliation", "treasury-approval"],
                "allowed_regions": ["asia-south1"],
                "expires_at": "2026-09-01T00:00:00Z",
            },
            headers={"x-authenticated-user": "user:priya@example.com"},
        )
        assert del_resp.status_code == 201
        delegation_id = del_resp.json()["delegation_id"]

        # 2. Evaluate Grant for invoice.read
        grant_eval_resp = await cp_client.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_1001",
                "delegation_id": delegation_id,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "invoice.read",
                "arguments": {"invoice_id": "INV-042"},
            },
        )
        assert grant_eval_resp.status_code == 200
        grant_data = grant_eval_resp.json()
        assert grant_data["decision"] == "allow"
        token = grant_data["token"]

        # 3. Execute invoice.read through Execution Gateway
        exec_resp = await gw_client.post(
            "/v1/execute",
            json={
                "tool": "invoice.read",
                "arguments": {"invoice_id": "INV-042"},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert exec_resp.status_code == 200
        result = exec_resp.json()["result"]
        assert result["invoice_id"] == "INV-042"
        assert result["total_minor"] == 74200000
        # Check forbidden field was redacted by response projection
        assert "bank_account_internal" not in result

        # 4. Replay test: second execution with same grant must fail (GRANT_REPLAYED)
        replay_resp = await gw_client.post(
            "/v1/execute",
            json={
                "tool": "invoice.read",
                "arguments": {"invoice_id": "INV-042"},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert replay_resp.status_code == 403
        assert replay_resp.json()["detail"]["code"] == "GRANT_REPLAYED"

        # 5. Verify Audit Chain
        audit_verify_resp = await cp_client.get("/v1/audit/tasks/task_1001/verify")
        assert audit_verify_resp.status_code == 200
        audit_res = audit_verify_resp.json()
        assert audit_res["valid"] is True
        assert audit_res["events"] == 2

        # 6. Day-7 observability: gateway metrics in Prometheus text format
        gw_metrics = (await gw_client.get("/metrics")).text
        assert "# TYPE gateway_execution_latency_ms histogram" in gw_metrics
        assert 'gateway_execution_latency_ms_bucket{le="+Inf"} 1' in gw_metrics
        assert "gateway_execution_latency_ms_count 1" in gw_metrics
        assert "gateway_execution_latency_ms_sum" in gw_metrics
        assert 'tool_execution_total{status="success",tool="invoice.read"} 1' in gw_metrics
        assert "grant_replay_total 1" in gw_metrics

        cp_metrics = (await cp_client.get("/metrics")).text
        assert "# TYPE grant_issue_latency_ms histogram" in cp_metrics
        assert "grant_issue_latency_ms_count 1" in cp_metrics
        assert "grant_issued_total 1" in cp_metrics
        assert "grant_denied_total" not in cp_metrics


@pytest.mark.asyncio
async def test_treasury_payment_requires_approval_and_sod(
    shared_store: MemoryStore,
    kms_signer: LocalKMSSigner,
    jws_verifier: JWSGrantVerifier,
):
    cp_app = create_control_plane(store=shared_store, signer=kms_signer)
    gw_app = create_execution_gateway(store=shared_store, verifier=jws_verifier)

    async with (
        AsyncClient(transport=ASGITransport(app=cp_app), base_url="http://cp.test") as cp_client,
        AsyncClient(transport=ASGITransport(app=gw_app), base_url="http://gw.test") as gw_client,
    ):
        # 1. Create Delegation sponsored by Priya
        del_resp = await cp_client.post(
            "/v1/delegations",
            json={
                "purpose": "weekly_vendor_settlement",
                "task_id": "task_2002",
                "allowed_agents": ["treasury-approval"],
                "allowed_regions": ["asia-south1"],
                "expires_at": "2026-09-01T00:00:00Z",
            },
            headers={"x-authenticated-user": "user:priya@example.com"},
        )
        delegation_id = del_resp.json()["delegation_id"]

        # 2. Attempt payment.instruct before approval -> must DENY (APPROVAL_REQUIRED)
        deny_resp = await cp_client.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_2002",
                "delegation_id": delegation_id,
                "agent": {"id": "treasury-approval", "version": "1.0.3"},
                "tool": "payment.instruct",
                "arguments": {"batch_id": "PB-88", "amount_minor": 74200000, "currency": "INR"},
            },
        )
        assert deny_resp.json()["decision"] == "deny"
        assert deny_resp.json()["reason_code"] == "APPROVAL_REQUIRED"

        # 3. Create Approval by SAME user (Priya) -> must fail SOD
        await cp_client.post(
            "/v1/approvals",
            json={
                "task_id": "task_2002",
                "delegation_id": delegation_id,
                "approval_type": "payment_batch",
                "subject": {"batch_id": "PB-88", "amount_minor": 74200000, "currency": "INR"},
            },
            headers={"x-authenticated-user": "user:priya@example.com"},
        )

        sod_resp = await cp_client.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_2002",
                "delegation_id": delegation_id,
                "agent": {"id": "treasury-approval", "version": "1.0.3"},
                "tool": "payment.instruct",
                "arguments": {"batch_id": "PB-88", "amount_minor": 74200000, "currency": "INR"},
            },
        )
        assert sod_resp.json()["decision"] == "deny"
        assert sod_resp.json()["reason_code"] == "SEPARATION_OF_DUTIES_VIOLATION"

        # 4. Create Approval by DIFFERENT user (Arun) -> SOD succeeds!
        await cp_client.post(
            "/v1/approvals",
            json={
                "task_id": "task_2002",
                "delegation_id": delegation_id,
                "approval_type": "payment_batch",
                "subject": {"batch_id": "PB-88", "amount_minor": 74200000, "currency": "INR"},
            },
            headers={"x-authenticated-user": "user:arun@example.com"},
        )

        allow_resp = await cp_client.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_2002",
                "delegation_id": delegation_id,
                "agent": {"id": "treasury-approval", "version": "1.0.3"},
                "tool": "payment.instruct",
                "arguments": {"batch_id": "PB-88", "amount_minor": 74200000, "currency": "INR"},
            },
        )
        assert allow_resp.json()["decision"] == "allow"
        token = allow_resp.json()["token"]

        # 5. Execute payment
        pay_exec = await gw_client.post(
            "/v1/execute",
            json={
                "tool": "payment.instruct",
                "arguments": {"batch_id": "PB-88", "amount_minor": 74200000, "currency": "INR"},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert pay_exec.status_code == 200
        assert pay_exec.json()["result"]["status"] == "accepted"
