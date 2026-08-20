"""Unit tests for audit hash chain."""

from datetime import UTC, datetime

from delegation_fabric_core.audit.chain import (
    GENESIS_HASH,
    canonical_json,
    finalize_audit_event,
    verify_audit_chain,
)
from delegation_fabric_core.models.audit import AuditActor, AuditActorType, AuditEvent


def _make_event(event_id: str, prev_hash: str) -> AuditEvent:
    evt = AuditEvent(
        audit_event_id=event_id,
        task_id="task_1001",
        delegation_id="dlg_01",
        grant_id="grt_01",
        actor=AuditActor(type=AuditActorType.AGENT, id="treasury-approval", version="1.0.3"),
        event_type="tool.execution.completed",
        tool="payment.instruct",
        decision="allow",
        policy_version="finance-policy-2026-08-20.1",
        occurred_at=datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC),
        prev_hash=prev_hash,
    )
    return finalize_audit_event(evt, prev_hash)


def test_canonical_json_determinism():
    d1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    d2 = {"a": 1, "c": [3, 2, 1], "b": 2}
    assert canonical_json(d1) == canonical_json(d2)
    assert canonical_json(d1) == '{"a":1,"b":2,"c":[3,2,1]}'


def test_audit_chain_valid():
    evt1 = _make_event("aud_01", GENESIS_HASH)
    evt2 = _make_event("aud_02", evt1.event_hash)
    evt3 = _make_event("aud_03", evt2.event_hash)

    chain = [evt1, evt2, evt3]
    res = verify_audit_chain(chain)

    assert res.valid is True
    assert res.event_count == 3
    assert res.first_invalid_index is None
    assert res.head_hash == evt3.event_hash


def test_audit_chain_tampered_event():
    evt1 = _make_event("aud_01", GENESIS_HASH)
    evt2 = _make_event("aud_02", evt1.event_hash)
    evt3 = _make_event("aud_03", evt2.event_hash)

    # Tamper with decision in middle event without updating hash
    evt2.decision = "deny"

    chain = [evt1, evt2, evt3]
    res = verify_audit_chain(chain)

    assert res.valid is False
    assert res.first_invalid_index == 1
    assert "Corrupted event_hash" in (res.reason or "")


def test_audit_chain_broken_prev_hash():
    evt1 = _make_event("aud_01", GENESIS_HASH)
    evt2 = _make_event("aud_02", "sha256:wrong_prev_hash")

    chain = [evt1, evt2]
    res = verify_audit_chain(chain)

    assert res.valid is False
    assert res.first_invalid_index == 1
    assert "Mismatched prev_hash" in (res.reason or "")


def test_empty_chain_is_valid():
    res = verify_audit_chain([])
    assert res.valid is True
    assert res.event_count == 0
