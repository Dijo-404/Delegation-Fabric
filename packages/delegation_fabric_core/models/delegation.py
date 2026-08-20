"""Delegation domain model."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class DelegationStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Sponsor(BaseModel):
    """The authenticated human who created the delegation."""

    subject: str  # e.g. 'user:priya@example.com'
    display_name: str = ""
    department: str = ""


class Delegation(BaseModel):
    """Long-lived authorization context anchored to a human sponsor.

    A Delegation authorizes a workflow context. It does NOT authorize
    a specific side effect — that requires an Execution Grant.
    """

    delegation_id: str
    sponsor: Sponsor
    purpose: str
    task_id: str

    allowed_agents: list[str] = Field(default_factory=list)
    allowed_regions: list[str] = Field(default_factory=list)

    policy_version: str
    status: DelegationStatus = DelegationStatus.ACTIVE

    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_by: str | None = None

    def is_active(self, now: datetime) -> bool:
        """Check if delegation is currently active."""
        return self.status == DelegationStatus.ACTIVE and self.expires_at > now
