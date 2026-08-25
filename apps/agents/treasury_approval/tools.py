"""Treasury Approval Agent tools."""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient

from apps.agents._protected_tools import ProtectedTools


class TreasuryApprovalTools(ProtectedTools):
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
            agent_id="treasury-approval",
            agent_version="1.0.3",
        )

    async def read_payment_batch(self, batch_id: str) -> dict[str, Any]:
        return await self._evaluate_and_execute("payment_batch.read", {"batch_id": batch_id})

    async def instruct_payment(
        self, batch_id: str, amount_minor: int, currency: str = "INR"
    ) -> dict[str, Any]:
        return await self._evaluate_and_execute(
            "payment.instruct",
            {"batch_id": batch_id, "amount_minor": amount_minor, "currency": currency},
        )
