"""Treasury Approval Agent tools."""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient


class TreasuryApprovalTools:
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
        self.agent_id = "treasury-approval"
        self.agent_version = "1.0.3"

    async def _evaluate_and_execute(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
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

        res = exec_resp.json().get("result", {})
        return dict(res) if isinstance(res, dict) else {}

    async def read_payment_batch(self, batch_id: str) -> dict[str, Any]:
        return await self._evaluate_and_execute("payment_batch.read", {"batch_id": batch_id})

    async def instruct_payment(
        self, batch_id: str, amount_minor: int, currency: str = "INR"
    ) -> dict[str, Any]:
        return await self._evaluate_and_execute(
            "payment.instruct",
            {"batch_id": batch_id, "amount_minor": amount_minor, "currency": currency},
        )
