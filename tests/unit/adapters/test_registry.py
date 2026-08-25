"""Unit tests for the registry fallback port (PLAN.md section 6).

FirestoreRegistry is exercised against a fake document client so no GCP
credentials or network access are required, mirroring test_pubsub_topics.py.
"""

from __future__ import annotations

from typing import Any

import pytest
from delegation_fabric_adapters.registry import (
    FirestoreRegistry,
    RegistryPort,
    StaticRegistry,
    create_registry_from_env,
)
from delegation_fabric_core.models.manifest import AgentManifest, RiskClass


def _manifest(agent_id: str = "agent_finance_ops", version: str = "1.0.0") -> AgentManifest:
    return AgentManifest(
        agent_id=agent_id,
        version=version,
        display_name="Finance Ops",
        owner="team-finance",
        risk_class=RiskClass.HIGH,
        capabilities=["payments.transfer", "ledger.read"],
    )


class _Snapshot:
    """Minimal stand-in for a Firestore document snapshot."""

    def __init__(self, doc_id: str, data: dict[str, Any] | None) -> None:
        self.id = doc_id
        self._data = data

    @property
    def exists(self) -> bool:
        return self._data is not None

    def to_dict(self) -> dict[str, Any]:
        assert self._data is not None
        return self._data


class _CollectionRef:
    def __init__(self, db: _FakeDb) -> None:
        self._db = db

    def document(self, doc_id: str) -> Any:
        outer = self._db

        class _DocRef:
            def get(self) -> _Snapshot:
                return _Snapshot(doc_id, outer.docs.get(doc_id))

        return _DocRef()

    def where(self, **_kwargs: Any) -> Any:
        return self

    def order_by(self, *_args: Any, **_kwargs: Any) -> Any:
        return self

    def limit(self, count: int) -> Any:
        self._db.applied_limit = count
        return self

    def stream(self) -> list[_Snapshot]:
        ids = sorted(self._db.docs)
        if self._db.applied_limit is not None:
            ids = ids[: self._db.applied_limit]
        return [_Snapshot(doc_id, self._db.docs[doc_id]) for doc_id in ids]


class _FakeDb:
    """Minimal stand-in for google.cloud.firestore.Client."""

    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}
        self.applied_limit: int | None = None

    def collection(self, name: str) -> Any:
        assert name == "agent_registry"
        return _CollectionRef(self)

    def document(self, doc_id: str) -> Any:
        return _CollectionRef(self).document(doc_id)


# ─── StaticRegistry ──────────────────────────────────────────────────────────


async def test_static_registry_returns_seeded_manifest() -> None:
    manifest = _manifest()
    registry = StaticRegistry({"agent_finance_ops": manifest})
    assert await registry.get("agent_finance_ops") == manifest


async def test_static_registry_get_unknown_agent_raises() -> None:
    registry = StaticRegistry({})
    with pytest.raises(KeyError):
        await registry.get("ghost")


async def test_static_registry_lists_all_sorted_by_agent_id() -> None:
    registry = StaticRegistry(
        {
            "b_agent": _manifest("b_agent"),
            "a_agent": _manifest("a_agent"),
            "c_agent": _manifest("c_agent"),
        }
    )
    listed = await registry.list()
    assert [m.agent_id for m in listed] == ["a_agent", "b_agent", "c_agent"]


async def test_static_registry_list_respects_limit() -> None:
    manifests = {f"agent_{i}": _manifest(f"agent_{i}") for i in range(5)}
    registry = StaticRegistry(manifests)
    listed = await registry.list(limit=2)
    assert [m.agent_id for m in listed] == ["agent_0", "agent_1"]


async def test_static_registry_list_empty_is_empty_list() -> None:
    assert await StaticRegistry({}).list() == []


# ─── FirestoreRegistry ───────────────────────────────────────────────────────


def _firestore_registry(
    docs: dict[str, dict[str, Any]] | None = None,
) -> tuple[FirestoreRegistry, _FakeDb]:
    registry = FirestoreRegistry(project_id="proj-test")
    db = _FakeDb()
    db.docs.update(docs or {})
    registry._db = db
    return registry, db


async def test_firestore_registry_get_roundtrips_serialized_manifest() -> None:
    manifest = _manifest()
    payload = manifest.model_dump(mode="json")
    registry, _db = _firestore_registry({manifest.agent_id: payload})
    loaded = await registry.get(manifest.agent_id)
    assert loaded == manifest
    assert isinstance(loaded.risk_class, RiskClass)


async def test_firestore_registry_get_unknown_agent_raises_key_error() -> None:
    registry, _db = _firestore_registry()
    with pytest.raises(KeyError):
        await registry.get("missing")


async def test_firestore_registry_list_maps_documents_and_applies_limit() -> None:
    docs = {
        "a_agent": _manifest("a_agent").model_dump(mode="json"),
        "b_agent": _manifest("b_agent").model_dump(mode="json"),
        "c_agent": _manifest("c_agent").model_dump(mode="json"),
    }
    registry, db = _firestore_registry(docs)
    listed = await registry.list(limit=2)
    assert [m.agent_id for m in listed] == ["a_agent", "b_agent"]
    assert db.applied_limit == 2


async def test_firestore_registry_lazy_client_defers_google_import() -> None:
    registry = FirestoreRegistry(project_id="proj-test")
    assert registry._db is None


# ─── Factory ────────────────────────────────────────────────────────────────


def test_factory_defaults_to_static(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DF_REGISTRY", raising=False)
    assert isinstance(create_registry_from_env(), StaticRegistry)


def test_factory_selects_firestore(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DF_REGISTRY", "firestore")
    assert isinstance(create_registry_from_env(), FirestoreRegistry)


def test_factory_rejects_unknown_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DF_REGISTRY", "spanner")
    with pytest.raises(ValueError):
        create_registry_from_env()


def test_implementations_satisfy_the_port_protocol() -> None:
    static: RegistryPort = StaticRegistry({})
    firestore: RegistryPort = FirestoreRegistry(project_id="p")
    assert static is not None
    assert firestore is not None
