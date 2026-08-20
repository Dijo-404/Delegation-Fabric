"""Pub/Sub event envelope domain model."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    TASK_START = "task.start"
    APPROVAL_CREATED = "approval.created"
    APPROVAL_REJECTED = "approval.rejected"
    EXTERNAL_SETTLEMENT_COMPLETED = "external.settlement.completed"
    EXTERNAL_SETTLEMENT_FAILED = "external.settlement.failed"
    TASK_RELEASE = "task.release"
    TASK_CANCEL = "task.cancel"


class EventEnvelope(BaseModel):
    """Stable event envelope for Pub/Sub messages.

    event_id must be stable across publish retries.
    It is the application-level idempotency key, not Pub/Sub's message ID.
    """

    event_id: str  # e.g. 'evt_<ulid>'
    event_type: EventType
    schema_version: str = "1"
    source: str  # e.g. 'control-plane'
    task_id: str
    occurred_at: datetime
    data: dict[str, Any] = Field(default_factory=dict)
