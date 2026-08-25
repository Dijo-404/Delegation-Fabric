"""Agent runtime port and implementations (PLAN.md section 6 — Fallback).

RuntimePort starts and resumes agent workflow sessions. LocalRunnerRuntime is
the portable fallback standing in for "ADK runner on Cloud Run/Jobs": it
delegates to an injected async workflow callable and keeps per-session state
in memory so resume continues from stored state plus a provided checkpoint.

No google-adk dependency is required at runtime.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from typing import Protocol

from delegation_fabric_core.models.policy import JsonObject, JsonValue
from pydantic import BaseModel


class SessionRef(BaseModel):
    """Reference to a started runtime session."""

    session_id: str
    agent_id: str


class RunResult(BaseModel):
    """Outcome of a (re)started agent run."""

    session_id: str
    status: str  # "completed" | "failed"
    output: JsonValue = None
    error: str = ""


WorkflowFn = Callable[[JsonObject], Awaitable[JsonValue]]


class RuntimePort(Protocol):
    async def start(self, agent_id: str, input_data: JsonObject) -> SessionRef:
        """Start a session for the agent and return its reference."""
        ...

    async def resume(self, session_id: str, checkpoint: JsonObject | None = None) -> RunResult:
        """Continue the session from stored state plus the provided checkpoint."""
        ...


class _SessionState:
    __slots__ = ("agent_id", "input_data", "output")

    def __init__(self, agent_id: str, input_data: JsonObject) -> None:
        self.agent_id = agent_id
        self.input_data = input_data
        self.output: JsonValue = None


class LocalRunnerRuntime:
    """In-process runner that invokes an injected async workflow callable.

    ``start`` allocates session state from the caller's input; ``resume``
    executes (or re-executes) the workflow with the original input merged
    under any checkpoint keys the caller supplies, returning a RunResult.
    Failures are captured as ``RunResult(status="failed")`` so orchestrators
    can branch on results without exception plumbing.
    """

    def __init__(self, workflow: WorkflowFn) -> None:
        self._workflow = workflow
        self._sessions: dict[str, _SessionState] = {}
        self._counter = 0

    def _new_session_id(self) -> str:
        from ulid import ULID

        self._counter += 1
        return f"sess_{ULID()}_{self._counter:06d}"

    @staticmethod
    def _merge(base: JsonObject, override: JsonObject | None) -> JsonObject:
        if not override:
            return dict(base)
        return {**base, **override}

    async def start(self, agent_id: str, input_data: JsonObject) -> SessionRef:
        session_id = self._new_session_id()
        self._sessions[session_id] = _SessionState(agent_id, dict(input_data))
        return SessionRef(session_id=session_id, agent_id=agent_id)

    async def resume(self, session_id: str, checkpoint: JsonObject | None = None) -> RunResult:
        try:
            state = self._sessions[session_id]
        except KeyError:
            raise KeyError(f"Unknown runtime session {session_id!r}") from None
        payload = self._merge(state.input_data, checkpoint)
        try:
            state.output = await self._workflow(payload)
            return RunResult(
                session_id=session_id,
                status="completed",
                output=state.output,
            )
        except Exception as exc:
            return RunResult(session_id=session_id, status="failed", error=str(exc))


def create_runtime_from_env(workflow: WorkflowFn) -> RuntimePort:
    """Build a RuntimePort from DF_RUNTIME ('local' only today)."""
    backend = os.environ.get("DF_RUNTIME", "local").strip().lower()
    if backend == "local":
        return LocalRunnerRuntime(workflow)
    msg = f"Unknown DF_RUNTIME backend {backend!r} (expected 'local')"
    raise ValueError(msg)


__all__ = [
    "LocalRunnerRuntime",
    "RunResult",
    "RuntimePort",
    "SessionRef",
    "WorkflowFn",
    "create_runtime_from_env",
]
