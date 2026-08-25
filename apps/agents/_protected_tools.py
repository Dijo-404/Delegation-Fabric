"""Shared protected-call pattern for agent tools.

CRITICAL RULE: Tools never connect directly to Cloud SQL or production DB.
Every tool call:
1. Calls Control Plane: POST /v1/grants/evaluate
2. Calls Execution Gateway: POST /v1/execute with Bearer <ExecutionGrant>
"""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient


class ProtectedTools:
    """Base class binding agent tools to Control Plane grant evaluation.

    Subclasses set their agent identity via ``agent_id``/``agent_version`` and
    inherit ``_evaluate_and_execute``; no tool may bypass grant evaluation.
    """

    def __init__(
        self,
        control_plane_client: AsyncClient,
        execution_gateway_client: AsyncClient,
        task_id: str,
        delegation_id: str,
        *,
        agent_id: str,
        agent_version: str,
    ) -> None:
        self.cp = control_plane_client
        self.gw = execution_gateway_client
        self.task_id = task_id
        self.delegation_id = delegation_id
        self.agent_id = agent_id
        self.agent_version = agent_version

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

        res = exec_resp.json().get("result", {})
        return dict(res) if isinstance(res, dict) else {}
