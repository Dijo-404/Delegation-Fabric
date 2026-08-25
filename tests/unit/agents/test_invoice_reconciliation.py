"""Unit tests for the invoice-reconciliation agent.

Covers: manifest schema validation, control-plane-before-gateway authorization
ordering, variance computation, and absence of direct database imports in
tools. Manifest YAML/Python parity lives in test_manifest_parity.py.
"""

from __future__ import annotations

import importlib

import httpx
import respx
from delegation_fabric_core.models.manifest import AgentManifest, RiskClass

from tests.unit.agents.conftest import agent_paths, forbidden_db_imports, load_manifest_dict

AGENT_DIR, MANIFEST_MODULE, TOOLS_MODULE = agent_paths("invoice_reconciliation")

CP_BASE = "https://cp.test"
GW_BASE = "https://gw.test"


def test_manifest_validates_against_core_schema() -> None:
    manifest = AgentManifest.model_validate(load_manifest_dict(MANIFEST_MODULE))
    assert manifest.agent_id == "invoice-reconciliation"
    assert manifest.risk_class is RiskClass.MEDIUM
    assert manifest.can_request_tool("invoice.read")
    assert not manifest.can_request_tool("payment.instruct")
    assert not manifest.can_request_tool("vendor_bank_account.read")


@respx.mock
async def test_tools_request_grant_before_gateway_execution() -> None:
    call_order: list[str] = []

    def cp_handler(request: httpx.Request) -> httpx.Response:
        call_order.append("control_plane")
        body = request.read()
        assert b"invoice.read" in body
        assert b"invoice-reconciliation" in body
        return httpx.Response(200, json={"decision": "allow", "token": "grant-token-123"})

    def gw_handler(request: httpx.Request) -> httpx.Response:
        call_order.append("gateway")
        return httpx.Response(200, json={"result": {"invoice_id": "INV-1"}})

    cp_route = respx.post(f"{CP_BASE}/v1/grants/evaluate").mock(side_effect=cp_handler)
    gw_route = respx.post(f"{GW_BASE}/v1/execute").mock(side_effect=gw_handler)

    tools_module = importlib.import_module(TOOLS_MODULE)
    async with (
        httpx.AsyncClient(base_url=CP_BASE) as cp_client,
        httpx.AsyncClient(base_url=GW_BASE) as gw_client,
    ):
        tools = tools_module.InvoiceReconciliationTools(
            control_plane_client=cp_client,
            execution_gateway_client=gw_client,
            task_id="task-1",
            delegation_id="del-1",
        )
        result = await tools.read_invoice("INV-1")

    assert result == {"invoice_id": "INV-1"}
    assert cp_route.call_count == 1
    assert gw_route.call_count == 1
    assert call_order.index("control_plane") < call_order.index("gateway")
    auth_header = gw_route.calls.last.request.headers["Authorization"]
    assert auth_header == "Bearer grant-token-123"


@respx.mock
async def test_tools_denied_by_control_plane_never_reach_gateway() -> None:
    respx.post(f"{CP_BASE}/v1/grants/evaluate").respond(
        json={"decision": "deny", "reason_code": "CAPABILITY_NOT_DECLARED"},
        status_code=403,
    )
    gw_route = respx.post(f"{GW_BASE}/v1/execute").respond(json={})

    tools_module = importlib.import_module(TOOLS_MODULE)
    async with (
        httpx.AsyncClient(base_url=CP_BASE) as cp_client,
        httpx.AsyncClient(base_url=GW_BASE) as gw_client,
    ):
        tools = tools_module.InvoiceReconciliationTools(
            control_plane_client=cp_client,
            execution_gateway_client=gw_client,
            task_id="task-2",
            delegation_id="del-2",
        )
        result = await tools.write_reconciliation("INV-9", "mismatch", 100)

    assert result == {"error": "CAPABILITY_NOT_DECLARED", "detail": None}
    assert gw_route.call_count == 0


async def test_workflow_completes_via_protected_tools() -> None:
    class StubTools:
        async def read_invoice(self, invoice_id: str) -> dict[str, object]:
            return {"invoice_id": invoice_id, "po_id": "PO-7", "total_minor": 500}

        async def read_purchase_order(self, po_id: str) -> dict[str, object]:
            return {"po_id": po_id, "total_minor": 500}

        async def write_reconciliation(
            self, invoice_id: str, result: str, variance_minor: int
        ) -> dict[str, object]:
            return {"reconciliation_id": "REC-1"}

    agent_module = importlib.import_module("apps.agents.invoice_reconciliation.agent")
    outcome = await agent_module.run_reconciliation_workflow(
        tools=StubTools(),  # type: ignore[arg-type]
        invoice_id="INV-1",
    )
    assert outcome == {
        "status": "completed",
        "invoice_id": "INV-1",
        "result": "matched",
        "variance_minor": 0,
        "reconciliation": {"reconciliation_id": "REC-1"},
    }


def test_tools_have_no_direct_database_imports() -> None:
    assert forbidden_db_imports(AGENT_DIR) == set()
