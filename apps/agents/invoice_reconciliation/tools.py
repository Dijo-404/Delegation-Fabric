"""Invoice Reconciliation Agent tools.

CRITICAL RULE: Tools never connect directly to Cloud SQL or production DB.
Every tool goes through the shared protected-call pattern in
apps.agents._protected_tools.
"""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient

from apps.agents._protected_tools import ProtectedTools


class InvoiceReconciliationTools(ProtectedTools):
    def __init__(
        self,
        control_plane_client: AsyncClient,
        execution_gateway_client: AsyncClient,
        task_id: str,
        delegation_id: str,
    ) -> None:
        super().__init__(
            control_plane_client,
            execution_gateway_client,
            task_id,
            delegation_id,
            agent_id="invoice-reconciliation",
            agent_version="1.0.0",
        )

    async def read_invoice(self, invoice_id: str) -> dict[str, Any]:
        return await self._evaluate_and_execute("invoice.read", {"invoice_id": invoice_id})

    async def read_purchase_order(self, po_id: str) -> dict[str, Any]:
        return await self._evaluate_and_execute("purchase_order.read", {"po_id": po_id})

    async def write_reconciliation(
        self, invoice_id: str, result: str, variance_minor: int
    ) -> dict[str, Any]:
        return await self._evaluate_and_execute(
            "reconciliation.write",
            {"invoice_id": invoice_id, "result": result, "variance_minor": variance_minor},
        )
