"""Invoice Reconciliation Agent tools.

CRITICAL RULE: Tools never connect directly to Cloud SQL or production DB.
Every tool:
1. Calls Control Plane: POST /v1/grants/evaluate
2. Calls Execution Gateway: POST /v1/execute with Bearer <ExecutionGrant>
"""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient


class InvoiceReconciliationTools:

    def __init__(
        self,
        control_plane_client: AsyncClient,
        execution_gateway_client: AsyncClient,
        task_id: str,
        delegation_id: str,
    ) -> None:
        self.cp = control_plane_client
        self.gw = execution_gateway_client
        self.task_id = task_id
        self.delegation_id = delegation_id
        self.agent_id = "invoice-reconciliation"
        self.agent_version = "1.0.0"

    async def _evaluate_and_execute(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Core protected-call pattern."""
        grant_resp = await self.cp.post(
            "/v1/grants/evaluate",
            json={
                "task_id": self.task_id,
                "delegation_id": self.delegation_id,
                "agent": {"id": self.agent_id, "version": self.agent_version},
                "tool": tool,
                "arguments": arguments,
            },
        )
        data = grant_resp.json()
        if data.get("decision") != "allow":
            return {"error": data.get("reason_code", "DENIED"), "detail": data.get("detail")}

        token = data["token"]
        exec_resp = await self.gw.post(
            "/v1/execute",
            json={"tool": tool, "arguments": arguments},
            headers={"Authorization": f"Bearer {token}"},
        )
        if exec_resp.status_code != 200:
            return {"error": "EXECUTION_FAILED", "detail": exec_resp.json()}

        return exec_resp.json().get("result", {})

    async def read_invoice(self, invoice_id: str) -> dict[str, Any]:
        return await self._evaluate_and_execute("invoice.read", {"invoice_id": invoice_id})

    async def read_purchase_order(self, po_id: str) -> dict[str, Any]:
        return await self._evaluate_and_execute("purchase_order.read", {"po_id": po_id})

    async def write_reconciliation(self, invoice_id: str, result: str, variance_minor: int) -> dict[str, Any]:
        return await self._evaluate_and_execute(
            "reconciliation.write",
            {"invoice_id": invoice_id, "result": result, "variance_minor": variance_minor},
        )
