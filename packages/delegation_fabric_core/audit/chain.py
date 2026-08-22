"""Tamper-evident audit chain implementation.

Canonical JSON:
- UTF-8
- Sorted keys
- Compact separators (no extra whitespace)
- ISO-8601 UTC timestamps

event_hash = SHA256(prev_hash || canonical_json(event_without_hash))
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from delegation_fabric_core.models.audit import AuditEvent

GENESIS_HASH = "genesis"


def _json_serial(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        # Ensure UTC and ISO-8601 formatting with Z
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=UTC)
        return obj.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if hasattr(obj, "value"):
        return obj.value
    raise TypeError(f"Type {type(obj)} not serializable")


def canonical_json(data: Any) -> str:
    """Produce canonical JSON representation: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        data,
        default=_json_serial,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_event_hash(prev_hash: str, event_data_without_hash: dict[str, Any]) -> str:
    """Compute SHA-256 hash for an audit event chained to prev_hash."""
    # Ensure event_hash is removed if present
    data = {k: v for k, v in event_data_without_hash.items() if k != "event_hash"}
    canonical_str = canonical_json(data)
    combined = f"{prev_hash}||{canonical_str}"
    digest = hashlib.sha256(combined.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def finalize_audit_event(event: AuditEvent, prev_hash: str) -> AuditEvent:
    """Compute and attach event_hash to an AuditEvent instance."""
    event.prev_hash = prev_hash
    event_dict = event.model_dump(mode="json")
    event.event_hash = compute_event_hash(prev_hash, event_dict)
    return event


class ChainVerificationResult(BaseModel):
    """Result of audit chain verification."""

    valid: bool
    event_count: int
    first_invalid_index: int | None = None
    reason: str | None = None
    head_hash: str | None = None


def verify_audit_chain(events: list[AuditEvent]) -> ChainVerificationResult:
    """Verify cryptographic integrity of an audit event chain."""
    if not events:
        return ChainVerificationResult(valid=True, event_count=0, head_hash=None)

    expected_prev = GENESIS_HASH

    for idx, evt in enumerate(events):
        if evt.prev_hash != expected_prev:
            return ChainVerificationResult(
                valid=False,
                event_count=len(events),
                first_invalid_index=idx,
                reason=f"Mismatched prev_hash: expected {expected_prev!r}, got {evt.prev_hash!r}",
            )

        evt_dict = evt.model_dump(mode="json")
        calculated_hash = compute_event_hash(evt.prev_hash, evt_dict)

        if evt.event_hash != calculated_hash:
            return ChainVerificationResult(
                valid=False,
                event_count=len(events),
                first_invalid_index=idx,
                reason=f"Corrupted event_hash: expected {calculated_hash!r}, got {evt.event_hash!r}",
            )

        expected_prev = evt.event_hash

    return ChainVerificationResult(
        valid=True,
        event_count=len(events),
        head_hash=events[-1].event_hash,
    )
