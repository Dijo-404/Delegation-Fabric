"""Approval record domain model."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel


class ApprovalDecision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalRecord(BaseModel):
    """Human approval satisfying a policy requirement.

    Must bind to the exact subject being acted upon.
    A generic 'approved=True' flag is not accepted.
    """

    approval_id: str
    task_id: str
    delegation_id: str

    approval_type: str  # e.g. 'payment_batch'
    subject: dict[str, Any]  # the specific item approved
    subject_hash: str  # SHA-256 of canonical subject JSON

    decision: ApprovalDecision
    approver_subject: str  # e.g. 'user:arun@example.com'

    created_at: datetime
    expires_at: datetime
    policy_version: str = ""

    def is_valid(self, now: datetime) -> bool:
        """Check if approval is still within its validity window."""
        return self.decision == ApprovalDecision.APPROVED and self.expires_at > now
