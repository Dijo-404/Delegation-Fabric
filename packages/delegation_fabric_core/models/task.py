"""Task and state machine domain models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class TaskState(str, Enum):
    """Valid task workflow states."""

    CREATED = "created"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    AWAITING_WEBHOOK = "awaiting_webhook"
    RESUMING = "resuming"
    COMPLETED = "completed"
    FAILED = "failed"
    QUARANTINED = "quarantined"
    CANCELLED = "cancelled"

    def is_terminal(self) -> bool:
        return self in {
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.CANCELLED,
        }


class TaskEvent(str, Enum):
    """Events that drive task state transitions."""

    INITIAL_INVOCATION = "initial_invocation"
    APPROVAL_REQUIRED = "approval_required"
    WEBHOOK_PENDING = "webhook_pending"
    TERMINAL_SUCCESS = "terminal_success"
    TERMINAL_FAILURE = "terminal_failure"
    SECURITY_EVENT = "security_event"
    APPROVAL_RECEIVED = "approval_received"
    WEBHOOK_RECEIVED = "webhook_received"
    RUNTIME_RESTORED = "runtime_restored"
    RESUME_FAILED = "resume_failed"
    HUMAN_RELEASED = "human_released"
    CANCELLATION = "cancellation"


class Task(BaseModel):
    """Business workflow state stored in Firestore.

    This is the durable source of truth for orchestration.
    Session state is separate (managed by Agent Platform Sessions).
    """

    task_id: str
    delegation_id: str
    state: TaskState = TaskState.CREATED
    state_version: int = 0  # optimistic concurrency

    current_agent_id: str = ""
    current_agent_version: str = ""
    session_id: str = ""
    latest_checkpoint_id: str = ""

    policy_version: str = ""
    created_at: datetime
    updated_at: datetime
