"""Regression: audit-chain consumers must read the FULL chain, not the capped listing.

`get_audit_events` defaults to DEFAULT_LIST_LIMIT (200). Chain-append sites
(_append_audit in control-plane/execution-gateway/worker), /export and /verify
require the complete chain: a stale tail silently corrupts prev_hash links and
lets /verify bless a truncated prefix. These tests build a >200-event chain
and assert end-to-end integrity through the real endpoints.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from delegation_fabric_adapters.firestore.store import (
    DEFAULT_LIST_LIMIT,
    MemoryStore,
)
from delegation_fabric_adapters.kms.signer import LocalKMSSigner
from delegation_fabric_core.audit.chain import GENESIS_HASH, finalize_audit_event
from delegation_fabric_core.models.audit import AuditActor, AuditActorType, AuditEvent
from httpx import ASGITransport, AsyncClient

from apps.control_plane.main import create_app as create_control_plane

TASK_ID = "task_longchain"
EVENT_COUNT = DEFAULT_LIST_LIMIT + 50


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def kms() -> LocalKMSSigner:
    return LocalKMSSigner()


async def _setup(cp: AsyncClient) -> str:
    resp = await cp.post(
        "/v1/delegations",
        json={
            "purpose": "weekly_vendor_settlement",
            "task_id": TASK_ID,
            "allowed_agents": ["invoice-reconciliation"],
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert resp.status_code == 201
    return resp.json()["delegation_id"]


async def _seed(store: MemoryStore) -> list[AuditEvent]:
    """Append EVENT_COUNT properly chained audit events directly via the store."""
    seeded: list[AuditEvent] = []
    prev_hash = GENESIS_HASH
    for i in range(EVENT_COUNT):
        evt = finalize_audit_event(
            AuditEvent(
                audit_event_id=f"aud_{i:08d}",
                task_id=TASK_ID,
                delegation_id="del_seed",
                actor=AuditActor(type=AuditActorType.SYSTEM, id="seeder"),
                event_type="test.seeded",
                decision="allow",
                policy_version="p",
                occurred_at=datetime.now(UTC),
                prev_hash=prev_hash,
            ),
            prev_hash,
        )
        await store.append_audit_event(evt)
        seeded.append(evt)
        prev_hash = evt.event_hash
    return seeded


async def _append_like_service_layer(store: MemoryStore) -> AuditEvent:
    """Mirror _append_audit semantics: read FULL chain, link to its head."""
    chain = await store.get_audit_events(TASK_ID, limit=None)
    prev_hash = chain[-1].event_hash if chain else GENESIS_HASH
    evt = finalize_audit_event(
        AuditEvent(
            audit_event_id=f"aud_{EVENT_COUNT:08d}",
            task_id=TASK_ID,
            delegation_id="del_seed",
            actor=AuditActor(type=AuditActorType.SYSTEM, id="appender"),
            event_type="test.appended_after_cap",
            decision="allow",
            policy_version="p",
            occurred_at=datetime.now(UTC),
            prev_hash=prev_hash,
        ),
        prev_hash,
    )
    await store.append_audit_event(evt)
    return evt


@pytest.mark.asyncio
async def test_append_links_to_true_head_beyond_cap_and_verify_is_valid(
    store: MemoryStore, kms: LocalKMSSigner
) -> None:
    cp = create_control_plane(store=store, signer=kms)
    async with AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c:
        await _setup(c)

        seeded = await _seed(store)
        assert len(seeded) == EVENT_COUNT > DEFAULT_LIST_LIMIT

        # Sanity: the capped default listing truncates at DEFAULT_LIST_LIMIT...
        capped = await store.get_audit_events(TASK_ID)
        assert len(capped) == DEFAULT_LIST_LIMIT

        # ...but /verify must see the COMPLETE chain and validate all of it.
        verify_before = (await c.get(f"/v1/audit/tasks/{TASK_ID}/verify")).json()
        assert verify_before["valid"] is True
        assert verify_before["events"] == EVENT_COUNT
        assert verify_before["head_hash"] == seeded[-1].event_hash

        # A fresh append (service-layer semantics) must link to the TRUE head.
        appended = await _append_like_service_layer(store)
        full_chain = await store.get_audit_events(TASK_ID, limit=None)
        assert appended.prev_hash == full_chain[-2].event_hash
        assert appended.prev_hash != capped[-1].event_hash  # cap would have linked here

        # End-to-end: /verify validates the whole extended chain incl. new event.
        verify_after = (await c.get(f"/v1/audit/tasks/{TASK_ID}/verify")).json()
        assert verify_after["valid"] is True
        assert verify_after["events"] == EVENT_COUNT + 1
        assert verify_after["head_hash"] == appended.event_hash


@pytest.mark.asyncio
async def test_verify_and_export_use_full_chain_via_real_append_path(
    store: MemoryStore, kms: LocalKMSSigner
) -> None:
    """Drive >cap appends through the REAL control-plane _append_audit path
    by issuing grants, then assert verify/export report untruncated counts."""
    cp = create_control_plane(store=store, signer=kms)
    async with AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp") as c:
        did = await _setup(c)

        # First grant seeds the chain through _append_audit (grant.issued etc.).
        grant_resp = await c.post(
            "/v1/grants/evaluate",
            json={
                "task_id": TASK_ID,
                "delegation_id": did,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "invoice.read",
                "arguments": {"invoice_id": "INV-001"},
            },
        )
        assert grant_resp.status_code == 200
        base_count = len(await store.get_audit_events(TASK_ID, limit=None))
        assert base_count >= 1

        # Push the chain past the cap via direct store appends.
        prev_hash = (await store.get_audit_events(TASK_ID, limit=None))[-1].event_hash
        for i in range(EVENT_COUNT - base_count):
            evt = finalize_audit_event(
                AuditEvent(
                    audit_event_id=f"aud_fill_{i:06d}",
                    task_id=TASK_ID,
                    delegation_id=did,
                    actor=AuditActor(type=AuditActorType.SYSTEM, id="filler"),
                    event_type="test.filler",
                    decision="allow",
                    policy_version="p",
                    occurred_at=datetime.now(UTC),
                    prev_hash=prev_hash,
                ),
                prev_hash,
            )
            await store.append_audit_event(evt)
            prev_hash = evt.event_hash

        # Another REAL _append_audit call beyond the cap must not corrupt the chain.
        denied = await c.post(
            "/v1/grants/evaluate",
            json={
                "task_id": TASK_ID,
                "delegation_id": did,
                "agent": {"id": "unknown-agent", "version": "1.0.0"},
                "tool": "payment.instruct",
                "arguments": {"amount": 1},
            },
        )
        assert denied.status_code == 403  # policy.denied event appended

        verify = (await c.get(f"/v1/audit/tasks/{TASK_ID}/verify")).json()
        assert verify["valid"] is True
        assert verify["events"] == len(await store.get_audit_events(TASK_ID, limit=None))
        assert verify["events"] > DEFAULT_LIST_LIMIT

        export = await c.post(f"/v1/audit/tasks/{TASK_ID}/export")
        assert export.status_code == 200
        assert export.json()["event_count"] > DEFAULT_LIST_LIMIT
