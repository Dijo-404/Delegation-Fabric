"""Task checkpoint domain model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class TaskCheckpoint(BaseModel):
    """Durable snapshot of workflow state used to resume a long-running task.

    MUST NOT contain:
    - Active JWS tokens / Execution Grants
    - KMS private material
    - Database passwords
    - Model chain-of-thought
    """

    checkpoint_id: str
    task_id: str
    state: str
    state_version: int

    session_id: str
    agent_id: str
    agent_version: str

    # Stable business references only — never secrets
    memory_refs: list[str] = Field(default_factory=list)
    pending_subject: dict[str, Any] | None = None

    created_at: datetime
