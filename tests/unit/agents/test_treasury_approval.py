"""Unit tests for the treasury-approval agent (approval-gated payment flow).

Covers: manifest schema validation, control-plane-before-gateway authorization
ordering, amount binding to the approved batch, and absence of direct database
imports in tools. Manifest YAML/Python parity lives in test_manifest_parity.py.
"""

from __future__ import annotations

import importlib

import httpx
import respx
from delegation_fabric_core.models.manifest import AgentManifest, RiskClass

from tests.unit.agents.conftest import agent_paths, forbidden_db_imports, load_manifest_dict

AGENT_DIR, MANIFEST_MODULE, TOOLS_MODULE = agent_paths("treasury_approval")

CP_BASE = "https://cp.test"
GW_BASE = "https://gw.test"


def test_manifest_validates_against_core_schema() -> None:
    manifest = AgentManifest.model_validate(load_manifest_dict(MANIFEST_MODULE))
    assert manifest.agent_id == "treasury-approval"
    assert manifest.risk_class is RiskClass.CRITICAL
    assert manifest.can_request_tool("payment_batch.read")
    assert manifest.can_request_tool("payment.instruct")


@respx.mock
async def test_tools_request_grant_before_gateway_execution() -> None:
    call_order: list[str] = []

    def cp_handler(request: httpx.Request) -> httpx.Response:
        call_order.append("control_plane")
        body = request.read()
        assert b"payment.instruct" in body
        assert b"treasury-approval" in body
        return httpx.Response(200, json={"decision": "allow", "token": "grant-token-xyz"})

    def gw_handler(request: httpx.Request) -> httpx.Response:
        call_order.append("gateway")
        assert request.headers["X-Agent-Id"] == "treasury-approval"
        assert request.headers["X-Agent-Version"] == "1.0.3"
        return httpx.Response(200, json={"result": {"instruction_id": "PI-1"}})

    cp_route = respx.post(f"{CP_BASE}/v1/grants/evaluate").mock(side_effect=cp_handler)
    gw_route = respx.post(f"{GW_BASE}/v1/execute").mock(side_effect=gw_handler)

    tools_module = importlib.import_module(TOOLS_MODULE)
    async with (
        httpx.AsyncClient(base_url=CP_BASE) as cp_client,
        httpx.AsyncClient(base_url=GW_BASE) as gw_client,
    ):
        tools = tools_module.TreasuryApprovalTools(
            control_plane_client=cp_client,
            execution_gateway_client=gw_client,
            task_id="task-5",
            delegation_id="del-5",
        )
        result = await tools.instruct_payment("PB-88", 74200000, "INR")

    assert result == {"instruction_id": "PI-1"}
    assert cp_route.call_count == 1
    assert gw_route.call_count == 1
    assert call_order.index("control_plane") < call_order.index("gateway")
    auth_header = gw_route.calls.last.request.headers["Authorization"]
    assert auth_header == "Bearer grant-token-xyz"


@respx.mock
async def test_tools_denied_by_control_plane_never_reach_gateway() -> None:
    respx.post(f"{CP_BASE}/v1/grants/evaluate").respond(
        json={"decision": "deny", "reason_code": "OUTSIDE_BUSINESS_PURPOSE"},
        status_code=403,
    )
    gw_route = respx.post(f"{GW_BASE}/v1/execute").respond(json={})

    tools_module = importlib.import_module(TOOLS_MODULE)
    async with (
        httpx.AsyncClient(base_url=CP_BASE) as cp_client,
        httpx.AsyncClient(base_url=GW_BASE) as gw_client,
    ):
        tools = tools_module.TreasuryApprovalTools(
            control_plane_client=cp_client,
            execution_gateway_client=gw_client,
            task_id="task-6",
            delegation_id="del-6",
        )
        result = await tools.instruct_payment("PB-88", 74200000)

    assert result == {"error": "OUTSIDE_BUSINESS_PURPOSE", "detail": None}
    assert gw_route.call_count == 0


def _make_stub_tools(batch_data: dict[str, object], instructed: list[str]) -> object:
    class StubTools:
        async def read_payment_batch(self, batch_id: str) -> dict[str, object]:
            return batch_data

        async def instruct_payment(
            self, batch_id: str, amount_minor: int, currency: str = "INR"
        ) -> dict[str, object]:
            instructed.append(batch_id)
            return {"instruction_id": f"PI-{batch_id}"}

    return StubTools()


async def test_workflow_blocks_unapproved_batch() -> None:
    instructed: list[str] = []
    stub_tools = _make_stub_tools(
        {
            "batch_id": "PB-99",
            "approval_status": "pending_approval",
            "amount_minor": 100,
            "currency": "INR",
        },
        instructed,
    )

    agent_module = importlib.import_module("apps.agents.treasury_approval.agent")
    outcome = await agent_module.run_payment_approval_workflow(
        tools=stub_tools,  # type: ignore[arg-type]
        batch_id="PB-99",
        amount_minor=100,
    )
    assert outcome == {
        "status": "blocked",
        "reason": "batch_not_approved",
        "batch_id": "PB-99",
        "approval_status": "pending_approval",
    }
    assert instructed == []


async def test_workflow_instructs_approved_batch_with_matching_terms() -> None:
    instructed: list[str] = []
    stub_tools = _make_stub_tools(
        {
            "batch_id": "PB-88",
            "approval_status": "approved",
            "amount_minor": 74200000,
            "currency": "INR",
        },
        instructed,
    )

    agent_module = importlib.import_module("apps.agents.treasury_approval.agent")
    outcome = await agent_module.run_payment_approval_workflow(
        tools=stub_tools,  # type: ignore[arg-type]
        batch_id="PB-88",
        amount_minor=74200000,
        currency="INR",
    )
    assert outcome["status"] == "completed"
    assert outcome["payment_instructed"] == {"instruction_id": "PI-PB-88"}
    assert instructed == ["PB-88"]


async def test_workflow_blocks_when_batch_lacks_approved_terms() -> None:
    instructed: list[str] = []
    stub_tools = _make_stub_tools({"batch_id": "PB-77", "approval_status": "approved"}, instructed)

    agent_module = importlib.import_module("apps.agents.treasury_approval.agent")
    outcome = await agent_module.run_payment_approval_workflow(
        tools=stub_tools,  # type: ignore[arg-type]
        batch_id="PB-77",
        amount_minor=500,
    )
    assert outcome["status"] == "blocked"
    assert outcome["reason"] == "batch_missing_approved_terms"
    assert instructed == []


async def test_workflow_blocks_amount_mismatch_against_approved_batch() -> None:
    """Caller-supplied amounts that disagree with the approved batch never reach the gateway."""
    instructed: list[str] = []
    stub_tools = _make_stub_tools(
        {
            "batch_id": "PB-88",
            "approval_status": "approved",
            "amount_minor": 74200000,
            "currency": "INR",
        },
        instructed,
    )

    agent_module = importlib.import_module("apps.agents.treasury_approval.agent")
    outcome = await agent_module.run_payment_approval_workflow(
        tools=stub_tools,  # type: ignore[arg-type]
        batch_id="PB-88",
        amount_minor=999999999,
    )
    assert outcome["status"] == "blocked"
    assert outcome["reason"] == "payment_terms_mismatch"
    assert outcome["approved_amount_minor"] == 74200000
    assert outcome["requested_amount_minor"] == 999999999
    assert instructed == []


async def test_workflow_blocks_currency_mismatch_against_approved_batch() -> None:
    instructed: list[str] = []
    stub_tools = _make_stub_tools(
        {
            "batch_id": "PB-88",
            "approval_status": "approved",
            "amount_minor": 74200000,
            "currency": "INR",
        },
        instructed,
    )

    agent_module = importlib.import_module("apps.agents.treasury_approval.agent")
    outcome = await agent_module.run_payment_approval_workflow(
        tools=stub_tools,  # type: ignore[arg-type]
        batch_id="PB-88",
        amount_minor=74200000,
        currency="USD",
    )
    assert outcome["status"] == "blocked"
    assert outcome["reason"] == "payment_terms_mismatch"
    assert instructed == []


def test_tools_have_no_direct_database_imports() -> None:
    assert forbidden_db_imports(AGENT_DIR) == set()
