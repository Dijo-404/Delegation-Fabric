"""Unit tests for the memory fallback port (PLAN.md section 6).

FirestoreMemoryStore runs against a fake document client so no GCP
credentials are needed; scoring is deterministic keyword overlap.
"""

from __future__ import annotations

from typing import Any

import pytest
from delegation_fabric_adapters.memory import (
    FirestoreMemoryStore,
    InMemoryMemoryStore,
    MemoryPort,
    create_memory_from_env,
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


class _FakeDb:
    """Minimal stand-in for google.cloud.firestore.Client."""

    def __init__(self, collection_name: str = "memory_entries") -> None:
        self.docs: dict[str, dict[str, Any]] = {}
        self.next_id = 0
        self.filters: list[tuple[str, str]] = []
        self.applied_limit: int | None = None
        self.collection_name = collection_name

    def collection(self, name: str) -> Any:
        assert name == self.collection_name
        return _CollectionRef(self)

    def add_doc(self, data: dict[str, Any]) -> str:
        self.next_id += 1
        doc_id = f"doc_{self.next_id:04d}"
        self.docs[doc_id] = data
        return doc_id


class _CollectionRef:
    def __init__(self, db: _FakeDb) -> None:
        self._db = db

    def document(self, doc_id: str) -> Any:
        outer = self._db

        class _DocRef:
            def set(self, payload: dict[str, Any]) -> None:
                outer.docs[doc_id] = payload

            def get(self) -> _Snapshot:
                return _Snapshot(doc_id, outer.docs.get(doc_id))

        return _DocRef()

    def where(self, *, filter: Any) -> Any:
        self._db.filters.append((filter.field_path, filter.op_string))
        matching = {
            doc_id: data
            for doc_id, data in self._db.docs.items()
            if data.get(filter.field_path) == filter.value
        }
        return _FilteredQuery(self._db, matching)

    def stream(self) -> list[_Snapshot]:
        return [_Snapshot(doc_id, data) for doc_id, data in sorted(self._db.docs.items())]


class _FilteredQuery(_CollectionRef):
    def __init__(self, db: _FakeDb, docs: dict[str, dict[str, Any]]) -> None:
        super().__init__(db)
        self._docs = docs

    def limit(self, count: int) -> Any:
        self._db.applied_limit = count
        return self

    def stream(self) -> list[_Snapshot]:
        ids = sorted(self._docs)
        if self._db.applied_limit is not None:
            ids = ids[: self._db.applied_limit]
        return [_Snapshot(doc_id, self._docs[doc_id]) for doc_id in ids]


# ─── InMemoryMemoryStore ─────────────────────────────────────────────────────


async def test_inmemory_write_returns_entry_id() -> None:
    store = InMemoryMemoryStore()
    entry_id = await store.write("sess_1", "approved the vendor payout")
    assert entry_id
    second = await store.write("sess_1", "payout settled")
    assert second != entry_id


async def test_inmemory_search_ranks_by_keyword_overlap() -> None:
    store = InMemoryMemoryStore()
    await store.write("s", "vendor payout scheduled for monday")
    await store.write("s", "kyc review completed for vendor")
    await store.write("s", "unrelated note about weather")
    hits = await store.search("s", "vendor payout")
    assert [h.content for h in hits][:1] == ["vendor payout scheduled for monday"]
    scores = [h.score for h in hits]
    assert scores == sorted(scores, reverse=True)
    assert all(h.ref for h in hits)


async def test_inmemory_search_respects_limit_top_k() -> None:
    store = InMemoryMemoryStore()
    await store.write("s", "alpha report")
    await store.write("s", "beta report")
    await store.write("s", "gamma report")
    hits = await store.search("s", "report", limit=2)
    assert len(hits) == 2
    assert all(h.score > 0.0 for h in hits)


async def test_inmemory_search_no_match_returns_empty() -> None:
    store = InMemoryMemoryStore()
    await store.write("s", "vendor payout")
    assert await store.search("s", "quantum entanglement") == []


async def test_inmemory_sessions_are_isolated() -> None:
    store = InMemoryMemoryStore()
    await store.write("s1", "secret ledger note")
    assert await store.search("s2", "ledger") == []


async def test_inmemory_empty_session_returns_empty() -> None:
    assert await InMemoryMemoryStore().search("nothing_here", "anything") == []


# ─── FirestoreMemoryStore ────────────────────────────────────────────────────


def _firestore_store(
    entries: list[tuple[str, str]] | None = None,
) -> tuple[FirestoreMemoryStore, _FakeDb]:
    store = FirestoreMemoryStore(project_id="proj-test")
    db = _FakeDb()
    for session_id, content in entries or []:
        db.add_doc({"session_id": session_id, "content": content})
    store._db = db
    return store, db


async def test_firestore_write_stores_document_and_returns_id() -> None:
    store, db = _firestore_store()
    entry_id = await store.write("sess_9", "approved the wire transfer")
    stored = db.docs[entry_id]
    assert stored["session_id"] == "sess_9"
    assert stored["content"] == "approved the wire transfer"
    assert stored["created_at"]


async def test_firestore_write_ids_are_unique() -> None:
    store, _db = _firestore_store()
    first = await store.write("s", "one")
    second = await store.write("s", "two")
    assert first != second


async def test_firestore_search_filters_by_session_and_scores_client_side() -> None:
    entries = [
        ("s1", "vendor payout approved"),
        ("s1", "weather report"),
        ("s2", "payout rejected"),
    ]
    store, db = _firestore_store(entries)
    hits = await store.search("s1", "vendor payout")
    assert [h.content for h in hits][0] == "vendor payout approved"
    assert db.filters == [("session_id", "==")]
    assert all(h.ref for h in hits)


async def test_firestore_search_applies_limit_after_ranking() -> None:
    entries = [(f"s{i}", f"report {i} details") for i in range(4)]
    store, db = _firestore_store(entries)
    hits = await store.search("s0", "report", limit=1)
    assert len(hits) == 1
    # The limit truncates the client-side ranked list, not the server query.
    assert db.applied_limit is None


async def test_firestore_search_unknown_session_is_empty() -> None:
    store, _db = _firestore_store([("s1", "note")])
    assert await store.search("ghost", "note") == []


async def test_firestore_lazy_client_defers_google_import() -> None:
    store = FirestoreMemoryStore(project_id="proj-test")
    assert store._db is None


# ─── Factory & protocol ──────────────────────────────────────────────────────


def test_factory_defaults_to_inmemory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DF_MEMORY", raising=False)
    assert isinstance(create_memory_from_env(), InMemoryMemoryStore)


def test_factory_selects_firestore(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DF_MEMORY", "firestore")
    assert isinstance(create_memory_from_env(), FirestoreMemoryStore)


def test_factory_rejects_unknown_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DF_MEMORY", "pgvector")
    with pytest.raises(ValueError):
        create_memory_from_env()


def test_implementations_satisfy_the_port_protocol() -> None:
    inmem: MemoryPort = InMemoryMemoryStore()
    firestore: MemoryPort = FirestoreMemoryStore(project_id="p")
    assert inmem is not None
    assert firestore is not None
