"""Unit tests for the treasury-approval agent (approval-gated payment flow).

Covers: manifest schema validation, manifest.yaml/manifest.py agreement,
control-plane-before-gateway authorization ordering, and absence of direct
database imports in tools.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import httpx
import respx
import yaml
from delegation_fabric_core.models.manifest import AgentManifest, RiskClass

AGENT_DIR = Path(__file__).resolve().parents[3] / "apps" / "agents" / "treasury_approval"
MANIFEST_MODULE = "apps.agents.treasury_approval.manifest"
TOOLS_MODULE = "apps.agents.treasury_approval.tools"

CP_BASE = "https://cp.test"
GW_BASE = "https://gw.test"


def _load_manifest_dict() -> dict[str, object]:
    module = importlib.import_module(MANIFEST_MODULE)
    data: dict[str, object] = module.manifest
    return data


def _forbidden_db_imports(agent_dir: Path) -> set[str]:
    """Collect DB driver imports via AST so sys.modules pollution cannot false-positive."""
    forbidden_roots = {"sqlalchemy", "asyncpg", "psycopg", "psycopg2"}
    found: set[str] = set()
    for py_file in agent_dir.glob("*.py"):
        tree = ast.parse(py_file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in forbidden_roots:
                        found.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root in forbidden_roots:
                    found.add(node.module)
    return found


def test_manifest_validates_against_core_schema() -> None:
    manifest = AgentManifest(
        **_load_manifest_dict(),  # type: ignore[arg-type]
    )
    assert manifest.agent_id == "treasury-approval"
    assert manifest.risk_class is RiskClass.CRITICAL
    assert manifest.can_request_tool("payment_batch.read")
    assert manifest.can_request_tool("payment.instruct")


def test_manifest_yaml_matches_manifest_py() -> None:
    py_data = _load_manifest_dict()
    yaml_data = yaml.safe_load((AGENT_DIR / "manifest.yaml").read_text())
    assert yaml_data == py_data


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


async def test_workflow_blocks_unapproved_batch() -> None:
    instructed_batches: list[str] = []

    class StubTools:
        async def read_payment_batch(self, batch_id: str) -> dict[str, object]:
            return {"batch_id": batch_id, "approval_status": "pending_approval"}

        async def instruct_payment(
            self, batch_id: str, amount_minor: int, currency: str = "INR"
        ) -> dict[str, object]:
            instructed_batches.append(batch_id)
            return {}

    agent_module = importlib.import_module("apps.agents.treasury_approval.agent")
    outcome = await agent_module.run_payment_approval_workflow(
        tools=StubTools(),  # type: ignore[arg-type]
        batch_id="PB-99",
        amount_minor=100,
    )
    assert outcome == {
        "status": "blocked",
        "reason": "batch_not_approved",
        "batch_id": "PB-99",
        "approval_status": "pending_approval",
    }
    assert instructed_batches == []


async def test_workflow_instructs_approved_batch() -> None:
    class StubTools:
        async def read_payment_batch(self, batch_id: str) -> dict[str, object]:
            return {"batch_id": batch_id, "approval_status": "approved"}

        async def instruct_payment(
            self, batch_id: str, amount_minor: int, currency: str = "INR"
        ) -> dict[str, object]:
            return {"instruction_id": f"PI-{batch_id}"}

    agent_module = importlib.import_module("apps.agents.treasury_approval.agent")
    outcome = await agent_module.run_payment_approval_workflow(
        tools=StubTools(),  # type: ignore[arg-type]
        batch_id="PB-88",
        amount_minor=74200000,
        currency="INR",
    )
    assert outcome["status"] == "completed"
    assert outcome["payment_instructed"] == {"instruction_id": "PI-PB-88"}


def test_tools_have_no_direct_database_imports() -> None:
    assert _forbidden_db_imports(AGENT_DIR) == set()
