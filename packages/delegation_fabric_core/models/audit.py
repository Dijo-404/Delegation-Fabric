"""Audit event domain model for the tamper-evident chain."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AuditActorType(str, Enum):
    AGENT = "agent"
    HUMAN = "human"
    SYSTEM = "system"


class AuditActor(BaseModel):
    type: AuditActorType
    id: str
    version: str = ""


class AuditEvent(BaseModel):
    """Structured provenance event in the tamper-evident audit chain.

    The hash chain is: event_hash = SHA256(prev_hash || canonical_json(event_without_hash))
    """

    audit_event_id: str
    task_id: str
    delegation_id: str
    grant_id: str | None = None

    actor: AuditActor
    event_type: str  # e.g. 'tool.execution.completed', 'grant.denied'
    tool: str | None = None

    decision: str  # 'allow' | 'deny' | 'quarantine'
    reason_code: str | None = None
    policy_version: str

    approval_ids: list[str] = Field(default_factory=list)
    resource_refs: list[str] = Field(default_factory=list)

    # Metadata (not full payloads)
    metadata: dict[str, Any] = Field(default_factory=dict)

    occurred_at: datetime

    # Chain fields
    prev_hash: str  # 'sha256:...' or 'genesis' for first event
    event_hash: str = ""  # computed after construction
