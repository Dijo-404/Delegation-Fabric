"""Execution Grant domain model."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from delegation_fabric_core.models.constraint import Constraint


class GrantStatus(str, Enum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    DENIED = "denied"


class ExecutionGrant(BaseModel):
    """Short-lived, single-use signed credential for one protected tool action.

    This model represents the CLAIMS within the JWS token.
    The signed compact JWS is stored separately as 'token'.
    """

    # JWS standard claims
    jti: str  # grant_id
    iss: str  # issuer: 'delegation-fabric-control-plane'
    aud: str  # audience: 'delegation-fabric-execution-gateway'

    # Delegation binding
    delegation_id: str
    task_id: str

    # Agent binding
    agent_id: str
    agent_version: str

    # Business context
    human_sponsor: str
    purpose: str

    # Tool authorization
    tool: str
    arg_constraints: list[Constraint] = Field(default_factory=list)
    allowed_response_fields: list[str] = Field(default_factory=list)
    max_records: int | None = None

    # Region and approvals
    region: str
    approval_ids: list[str] = Field(default_factory=list)

    # Time window (Unix timestamps for JWS compat)
    iat: int  # issued_at
    nbf: int  # not_before
    exp: int  # expires_at

    # Policy
    single_use: bool = True
    policy_version: str

    @property
    def grant_id(self) -> str:
        return self.jti

    def is_valid_at(self, now_ts: int) -> bool:
        """Check time validity (nbf <= now < exp)."""
        return self.nbf <= now_ts < self.exp


class GrantRecord(BaseModel):
    """Firestore document tracking grant lifecycle state."""

    grant_id: str
    delegation_id: str
    task_id: str
    agent_id: str
    agent_version: str
    tool: str
    status: GrantStatus = GrantStatus.ISSUED
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    policy_version: str
