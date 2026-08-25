"""Procurement Exception Agent tools."""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient

from apps.agents._protected_tools import ProtectedTools


class ProcurementExceptionTools(ProtectedTools):
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
            agent_id="procurement-exception",
            agent_version="1.0.0",
        )

    async def read_vendor(self, vendor_id: str) -> dict[str, Any]:
        return await self._evaluate_and_execute("vendor.read", {"vendor_id": vendor_id})

    async def write_exception(self, invoice_id: str, severity: str, reason: str) -> dict[str, Any]:
        return await self._evaluate_and_execute(
            "exception.write",
            {"invoice_id": invoice_id, "severity": severity, "reason": reason},
        )
