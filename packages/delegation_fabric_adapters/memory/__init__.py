"""Memory bank port and implementations (PLAN.md section 6 — Fallback).

MemoryPort persists session-scoped notes and answers keyword queries.
FirestoreMemoryStore is the managed backend (collection ``memory_entries``);
InMemoryMemoryStore is the portable fallback used for tests and local runs.

Selection is driven by DF_MEMORY=inmemory|firestore via
``create_memory_from_env``. Scoring is deterministic keyword overlap so
results are reproducible across backends.
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel
from ulid import ULID

from delegation_fabric_adapters.constants import DEFAULT_FETCH_CAP

MEMORY_COLLECTION = "memory_entries"
DEFAULT_SEARCH_LIMIT = 5
MEMORY_FETCH_CAP = DEFAULT_FETCH_CAP
"""Server-side fetch window: newest-first entries capped before scoring."""
MAX_MEMORY_CONTENT_CHARS = 10_000
"""Hard bound on persisted memory entry content (characters)."""

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def _validate_content(content: str) -> None:
    if len(content) > MAX_MEMORY_CONTENT_CHARS:
        msg = f"memory content is {len(content)} chars; max allowed is {MAX_MEMORY_CONTENT_CHARS}"
        raise ValueError(msg)


class MemoryHit(BaseModel):
    content: str
    score: float = 0.0
    ref: str = ""


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def score_content(query: str, content: str) -> float:
    """Deterministic keyword-overlap score in [0, 1].

    Full query substring match earns a bonus; otherwise the score is the
    fraction of unique query tokens present in the entry content.
    """
    query_tokens = set(_tokens(query))
    if not query_tokens:
        return 0.0
    content_lower = content.lower()
    matched = sum(1 for t in query_tokens if t in content_lower)
    base = matched / len(query_tokens)
    if query.strip().lower() and query.strip().lower() in content_lower:
        return min(1.0, base + 0.25)
    return base


class MemoryPort(Protocol):
    async def write(self, session_id: str, content: str) -> str:
        """Persist an entry for the session and return its reference id.

        Implementations must reject content longer than
        ``MAX_MEMORY_CONTENT_CHARS`` with ``ValueError``. Content is stored
        verbatim: Model Armor / Sensitive Data Protection screening is the
        managed-path counterpart and is NOT applied here (PLAN.md section 6).
        """
        ...

    async def search(
        self, session_id: str, query: str, limit: int = DEFAULT_SEARCH_LIMIT
    ) -> list[MemoryHit]:
        """Return up to ``limit`` ranked hits for the session."""
        ...


class InMemoryMemoryStore:
    """Dict-of-sessions store with naive keyword scoring — the portable fallback."""

    def __init__(self) -> None:
        self._entries: dict[str, dict[str, str]] = {}

    async def write(self, session_id: str, content: str) -> str:
        _validate_content(content)
        ref = f"mem_{ULID()}"
        self._entries.setdefault(session_id, {})[ref] = content
        return ref

    async def search(
        self, session_id: str, query: str, limit: int = DEFAULT_SEARCH_LIMIT
    ) -> list[MemoryHit]:
        entries = self._entries.get(session_id, {})
        hits = [
            MemoryHit(ref=ref, content=content, score=score_content(query, content))
            for ref, content in entries.items()
        ]
        ranked = [h for h in sorted(hits, key=lambda h: (-h.score, h.ref)) if h.score > 0.0]
        return ranked[:limit]


class FirestoreMemoryStore:
    """Firestore-backed memory (collection memory_entries).

    Documents carry session_id/content/created_at; search filters by
    session_id server-side, orders newest-first and caps the fetch window at
    ``MEMORY_FETCH_CAP`` documents before scoring contents client-side, so
    ranking is identical to the in-memory fallback without a full collection
    scan (older entries beyond the cap are not scored). The
    google-cloud-firestore client is imported lazily; blocking SDK calls run
    via asyncio.to_thread. Content is stored verbatim: Armor/SDP screening is
    the managed-path counterpart, NOT applied here.
    """

    def __init__(self, project_id: str | None = None) -> None:
        self._project_id = project_id
        self._db: Any | None = None

    def _ensure_db(self) -> Any:
        if self._db is None:
            from google.cloud import firestore

            self._db = firestore.Client(project=self._project_id)
        return self._db

    async def write(self, session_id: str, content: str) -> str:
        _validate_content(content)

        def _write() -> str:
            db = self._ensure_db()
            ref = f"mem_{ULID()}"
            payload = {
                "session_id": session_id,
                "content": content,
                "created_at": datetime.now(UTC).isoformat(),
            }
            db.collection(MEMORY_COLLECTION).document(ref).set(payload)
            return ref

        return await asyncio.to_thread(_write)

    async def search(
        self, session_id: str, query: str, limit: int = DEFAULT_SEARCH_LIMIT
    ) -> list[MemoryHit]:
        def _search() -> list[MemoryHit]:
            db = self._ensure_db()
            from google.cloud.firestore import FieldFilter, Query

            docs_query = (
                db.collection(MEMORY_COLLECTION)
                .where(filter=FieldFilter("session_id", "==", session_id))
                .order_by("created_at", direction=Query.DESCENDING)
                .limit(MEMORY_FETCH_CAP)
            )
            hits: list[MemoryHit] = []
            for doc in docs_query.stream():
                data = doc.to_dict() or {}
                content = str(data.get("content", ""))
                hits.append(
                    MemoryHit(ref=doc.id, content=content, score=score_content(query, content))
                )
            ranked = [h for h in sorted(hits, key=lambda h: (-h.score, h.ref)) if h.score > 0.0]
            return ranked[:limit]

        return await asyncio.to_thread(_search)


def create_memory_from_env() -> MemoryPort:
    """Build a MemoryPort from DF_MEMORY (inmemory|firestore). Default: inmemory."""
    backend = os.environ.get("DF_MEMORY", "inmemory").strip().lower()
    if backend == "inmemory":
        return InMemoryMemoryStore()
    if backend == "firestore":
        return FirestoreMemoryStore(project_id=os.environ.get("GOOGLE_CLOUD_PROJECT"))
    msg = f"Unknown DF_MEMORY backend {backend!r} (expected 'inmemory' or 'firestore')"
    raise ValueError(msg)


__all__ = [
    "DEFAULT_SEARCH_LIMIT",
    "FirestoreMemoryStore",
    "InMemoryMemoryStore",
    "MAX_MEMORY_CONTENT_CHARS",
    "MEMORY_COLLECTION",
    "MEMORY_FETCH_CAP",
    "MemoryHit",
    "MemoryPort",
    "create_memory_from_env",
]
