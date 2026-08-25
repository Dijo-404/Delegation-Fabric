"""Agent registry port and implementations (PLAN.md section 6 — Fallback).

The registry answers "what may this agent request?" from versioned
AgentManifest declarations. FirestoreRegistry is the managed backend
(collection ``agent_registry``, documents keyed by agent_id); StaticRegistry
is the portable in-memory fallback used for tests and local runs.

Selection is driven by DF_REGISTRY=firestore|static via
``create_registry_from_env``.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Protocol

from delegation_fabric_core.models.manifest import AgentManifest

from delegation_fabric_adapters.constants import DEFAULT_FETCH_CAP

REGISTRY_COLLECTION = "agent_registry"

# Single shared fetch cap (see adapters.constants); aliased here so the
# Protocol default and both implementations reference one module-level const.
DEFAULT_LIST_LIMIT = DEFAULT_FETCH_CAP


class RegistryPort(Protocol):
    async def get(self, agent_id: str) -> AgentManifest:
        """Return the current manifest for an agent."""
        ...

    async def list(self, limit: int | None = DEFAULT_LIST_LIMIT) -> list[AgentManifest]:
        """List manifests ordered by agent_id."""
        ...


class StaticRegistry:
    """In-memory dict-backed registry seeded from a manifest mapping."""

    def __init__(self, manifests: dict[str, AgentManifest]) -> None:
        self._manifests = dict(manifests)

    async def get(self, agent_id: str) -> AgentManifest:
        try:
            return self._manifests[agent_id]
        except KeyError:
            raise KeyError(f"Agent {agent_id!r} not found in registry") from None

    async def list(self, limit: int | None = DEFAULT_LIST_LIMIT) -> list[AgentManifest]:
        manifests = [self._manifests[k] for k in sorted(self._manifests)]
        if limit is not None:
            manifests = manifests[:limit]
        return manifests


class FirestoreRegistry:
    """Firestore-backed registry (collection agent_registry, keyed by agent_id).

    The google-cloud-firestore client is imported lazily so this module can be
    imported without credentials installed; blocking SDK calls run off the
    event loop via asyncio.to_thread. Documents that deserialize to an empty
    mapping raise ValueError instead of a bare pydantic ValidationError.
    """

    def __init__(self, project_id: str | None = None) -> None:
        self._project_id = project_id
        self._db: Any | None = None

    def _ensure_db(self) -> Any:
        """Typed as Any: the SDK stubs union sync/async returns."""
        if self._db is None:
            from google.cloud import firestore

            self._db = firestore.Client(project=self._project_id)
        return self._db

    async def get(self, agent_id: str) -> AgentManifest:
        def _get() -> AgentManifest:
            db = self._ensure_db()
            snap = db.collection(REGISTRY_COLLECTION).document(agent_id).get()
            if not snap.exists:
                raise KeyError(f"Agent {agent_id!r} not found in registry")
            data = snap.to_dict()
            if not data:
                raise ValueError(f"registry doc for {agent_id!r} is empty")
            return AgentManifest.model_validate(data)

        return await asyncio.to_thread(_get)

    async def list(self, limit: int | None = DEFAULT_LIST_LIMIT) -> list[AgentManifest]:
        def _list() -> list[AgentManifest]:
            db = self._ensure_db()
            query = db.collection(REGISTRY_COLLECTION).order_by("agent_id")
            if limit is not None:
                query = query.limit(limit)
            manifests: list[AgentManifest] = []
            for doc in query.stream():
                data = doc.to_dict()
                if not data:
                    raise ValueError(f"registry doc {doc.id!r} is empty")
                manifests.append(AgentManifest.model_validate(data))
            return manifests

        return await asyncio.to_thread(_list)


def create_registry_from_env() -> RegistryPort:
    """Build a RegistryPort from DF_REGISTRY (static|firestore). Default: static."""
    backend = os.environ.get("DF_REGISTRY", "static").strip().lower()
    if backend == "static":
        return StaticRegistry({})
    if backend == "firestore":
        return FirestoreRegistry(project_id=os.environ.get("GOOGLE_CLOUD_PROJECT"))
    msg = f"Unknown DF_REGISTRY backend {backend!r} (expected 'static' or 'firestore')"
    raise ValueError(msg)


__all__ = [
    "DEFAULT_LIST_LIMIT",
    "FirestoreRegistry",
    "REGISTRY_COLLECTION",
    "RegistryPort",
    "StaticRegistry",
    "create_registry_from_env",
]
