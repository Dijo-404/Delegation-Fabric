"""Delegation Fabric domain exceptions."""

from __future__ import annotations


class DelegationFabricError(Exception):
    """Base exception for all Delegation Fabric errors."""


class PolicyDeniedError(DelegationFabricError):
    """Raised when authorization is denied by policy."""

    def __init__(self, reason_code: str, message: str = "") -> None:
        self.reason_code = reason_code
        super().__init__(message or reason_code)


class GrantError(DelegationFabricError):
    """Base class for grant-related errors."""


class GrantUnknownError(GrantError):
    """Grant document not found."""


class GrantReplayError(GrantError):
    """Attempt to use a consumed grant."""


class GrantExpiredError(GrantError):
    """Grant TTL exceeded."""


class GrantSignatureError(GrantError):
    """JWS signature verification failed."""


class InvalidTransitionError(DelegationFabricError):
    """Attempted state machine transition is not allowed."""

    def __init__(self, from_state: str, event: str) -> None:
        self.from_state = from_state
        self.event = event
        super().__init__(f"No transition from {from_state!r} on event {event!r}")


class EventDuplicateError(DelegationFabricError):
    """Event already processed (idempotency)."""


class AuditChainError(DelegationFabricError):
    """Audit chain verification failed."""

    def __init__(self, index: int, reason: str) -> None:
        self.index = index
        super().__init__(f"Chain broken at index {index}: {reason}")


class ConcurrentTaskUpdateError(DelegationFabricError):
    """Raised when a task was modified concurrently (optimistic CAS mismatch)."""


class TaskNotFoundError(DelegationFabricError):
    """Raised when the referenced task does not exist."""
