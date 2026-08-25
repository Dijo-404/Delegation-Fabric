"""Shared constants for adapter port implementations (PLAN.md section 6)."""

DEFAULT_FETCH_CAP = 200
"""Single server-side fetch cap for Firestore-backed listings.

Referenced by the registry list limit (``DEFAULT_LIST_LIMIT``) and the
memory search window (``MEMORY_FETCH_CAP``) so both ports stay in sync.
"""

__all__ = ["DEFAULT_FETCH_CAP"]
