"""Policy decision model and reason codes."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel


class ReasonCode(str, Enum):
    """Closed enum of authorization denial reason codes."""

    # Delegation
    DELEGATION_NOT_FOUND = "DELEGATION_NOT_FOUND"
    DELEGATION_REVOKED = "DELEGATION_REVOKED"
    DELEGATION_EXPIRED = "DELEGATION_EXPIRED"

    # Task binding
    TASK_NOT_BOUND_TO_DELEGATION = "TASK_NOT_BOUND_TO_DELEGATION"
    TASK_NOT_LIVE = "TASK_NOT_LIVE"

    # Agent
    AGENT_NOT_ALLOWED = "AGENT_NOT_ALLOWED"
    AGENT_VERSION_NOT_ALLOWED = "AGENT_VERSION_NOT_ALLOWED"
    CAPABILITY_NOT_DECLARED = "CAPABILITY_NOT_DECLARED"
    OUTSIDE_BUSINESS_PURPOSE = "OUTSIDE_BUSINESS_PURPOSE"

    # Arguments
    ARGUMENT_CONSTRAINT_FAILED = "ARGUMENT_CONSTRAINT_FAILED"
    ARGUMENT_TYPE_MISMATCH = "ARGUMENT_TYPE_MISMATCH"
    ARGUMENT_PATH_UNKNOWN = "ARGUMENT_PATH_UNKNOWN"

    # Response
    RESPONSE_FIELD_NOT_ALLOWED = "RESPONSE_FIELD_NOT_ALLOWED"

    # Approval
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_NOT_FOUND = "APPROVAL_NOT_FOUND"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_SUBJECT_MISMATCH = "APPROVAL_SUBJECT_MISMATCH"
    SEPARATION_OF_DUTIES_VIOLATION = "SEPARATION_OF_DUTIES_VIOLATION"

    # Region
    REGION_NOT_ALLOWED = "REGION_NOT_ALLOWED"

    # Semantic
    SEMANTIC_POLICY_DENIED = "SEMANTIC_POLICY_DENIED"

    # Grant verification
    GRANT_INVALID_SIGNATURE = "GRANT_INVALID_SIGNATURE"
    GRANT_INVALID_ISSUER = "GRANT_INVALID_ISSUER"
    GRANT_INVALID_AUDIENCE = "GRANT_INVALID_AUDIENCE"
    GRANT_NOT_YET_VALID = "GRANT_NOT_YET_VALID"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    GRANT_REPLAYED = "GRANT_REPLAYED"
    GRANT_TOOL_MISMATCH = "GRANT_TOOL_MISMATCH"
    GRANT_AGENT_MISMATCH = "GRANT_AGENT_MISMATCH"
    GRANT_TASK_MISMATCH = "GRANT_TASK_MISMATCH"
    GRANT_REGION_MISMATCH = "GRANT_REGION_MISMATCH"
    GRANT_UNKNOWN = "GRANT_UNKNOWN"


# Type alias for arbitrary JSON values
JsonValue = str | int | float | bool | list[Any] | dict[str, Any] | None
JsonObject = dict[str, Any]


class PolicyDecision(BaseModel):
    """Result of a deterministic policy evaluation."""

    allowed: bool
    reason_code: ReasonCode | None = None
    reason_detail: str | None = None
    # Path that failed (for constraint failures)
    failed_path: str | None = None

    @classmethod
    def allow(cls) -> PolicyDecision:
        return cls(allowed=True)

    @classmethod
    def deny(
        cls,
        reason_code: ReasonCode,
        detail: str = "",
        path: str | None = None,
    ) -> PolicyDecision:
        return cls(
            allowed=False,
            reason_code=reason_code,
            reason_detail=detail or None,
            failed_path=path,
        )


class ProjectionResult(BaseModel):
    """Result of field projection on a tool response."""

    projected: JsonValue
    dropped_count: int = 0
