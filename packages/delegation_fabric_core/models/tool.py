"""Tool request/response domain models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ToolRequest(BaseModel):
    """A request to execute a protected tool action."""

    task_id: str
    delegation_id: str
    agent: dict[str, str]  # {id, version}
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolResponse(BaseModel):
    """Response from a tool execution, after field projection."""

    grant_id: str
    tool: str
    result: Any  # projected response payload
