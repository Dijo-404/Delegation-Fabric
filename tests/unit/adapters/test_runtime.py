"""Unit tests for the runtime fallback port (PLAN.md section 6).

LocalRunnerRuntime simulates an agent run by delegating to an injected
async workflow callable; no google-adk dependency is required.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from delegation_fabric_adapters.runtime import (
    LocalRunnerRuntime,
    RunResult,
    RuntimePort,
    SessionRef,
    create_runtime_from_env,
)


async def _echo_workflow(payload: dict[str, Any]) -> dict[str, Any]:
    return {"echo": payload, "done": True}


async def test_start_registers_session_without_invoking_the_workflow() -> None:
    calls: list[dict[str, Any]] = []

    async def workflow(payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(payload)
        return {"ok": True}

    runtime = LocalRunnerRuntime(workflow)
    ref = await runtime.start("agent_finance_ops", {"amount": 100})
    assert isinstance(ref, SessionRef)
    assert ref.agent_id == "agent_finance_ops"
    assert ref.session_id.startswith("sess_")
    # Execution is deferred to resume; start only allocates session state.
    assert calls == []


async def test_resume_executes_the_workflow_with_stored_input() -> None:
    seen: list[dict[str, Any]] = []

    async def workflow(payload: dict[str, Any]) -> dict[str, Any]:
        seen.append(payload)
        return {"echo": payload}

    runtime = LocalRunnerRuntime(workflow)
    ref = await runtime.start("agent_x", {"amount": 100})
    result = await runtime.resume(ref.session_id)
    assert seen == [{"amount": 100}]
    assert isinstance(result, RunResult)
    assert result.status == "completed"
    assert result.output == {"echo": {"amount": 100}}


async def test_start_generates_unique_session_ids() -> None:
    runtime = LocalRunnerRuntime(_echo_workflow)
    ref_a = await runtime.start("agent_a", {})
    ref_b = await runtime.start("agent_a", {})
    assert ref_a.session_id != ref_b.session_id


async def test_resume_reruns_workflow_with_merged_checkpoint() -> None:
    seen: list[dict[str, Any]] = []

    async def workflow(payload: dict[str, Any]) -> dict[str, Any]:
        seen.append(payload)
        return {"seen_keys": sorted(payload)}

    runtime = LocalRunnerRuntime(workflow)
    ref = await runtime.start("agent_x", {"step": 1})
    result = await runtime.resume(ref.session_id, {"step": 2, "extra": "ctx"})
    assert isinstance(result, RunResult)
    assert result.status == "completed"
    assert result.session_id == ref.session_id
    # Resume receives the original input merged with the provided checkpoint.
    assert seen[-1] == {"step": 2, "extra": "ctx"}


async def test_resume_without_checkpoint_reuses_stored_state() -> None:
    runtime = LocalRunnerRuntime(_echo_workflow)
    ref = await runtime.start("agent_x", {"n": 7})
    result = await runtime.resume(ref.session_id)
    assert result.status == "completed"
    output: dict[str, Any] = result.output  # type: ignore[assignment]
    assert output["echo"] == {"n": 7}


async def test_resume_unknown_session_raises_key_error() -> None:
    runtime = LocalRunnerRuntime(_echo_workflow)
    with pytest.raises(KeyError):
        await runtime.resume("sess_does_not_exist")


async def test_concurrent_resume_on_the_same_session_is_rejected() -> None:
    started = asyncio.Event()

    async def slow_workflow(_payload: dict[str, Any]) -> dict[str, Any]:
        started.set()
        await asyncio.sleep(0.05)
        return {"done": True}

    runtime = LocalRunnerRuntime(slow_workflow)
    ref = await runtime.start("agent_x", {"k": "v"})
    first = asyncio.create_task(runtime.resume(ref.session_id))
    await started.wait()
    second = asyncio.create_task(runtime.resume(ref.session_id))
    outcomes = await asyncio.gather(first, second, return_exceptions=True)
    results = [o for o in outcomes if isinstance(o, RunResult)]
    errors = [o for o in outcomes if isinstance(o, BaseException)]
    assert len(results) == 1
    assert results[0].status == "completed"
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)
    assert "single-caller" in str(errors[0])


async def test_sequential_resumes_still_work_and_rerun_the_workflow() -> None:
    calls: list[int] = []

    async def counting_workflow(_payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(len(calls) + 1)
        return {"run": len(calls)}

    runtime = LocalRunnerRuntime(counting_workflow)
    ref = await runtime.start("agent_x", {})
    first = await runtime.resume(ref.session_id)
    second = await runtime.resume(ref.session_id)
    assert calls == [1, 2]
    assert first.status == "completed"
    assert second.status == "completed"
    first_output: dict[str, Any] = first.output  # type: ignore[assignment]
    second_output: dict[str, Any] = second.output  # type: ignore[assignment]
    assert (first_output["run"], second_output["run"]) == (1, 2)


async def test_resume_guard_is_released_after_failure() -> None:
    attempts: list[int] = []

    async def flaky(_payload: dict[str, Any]) -> dict[str, Any]:
        attempts.append(1)
        msg = "boom"
        raise RuntimeError(msg)

    runtime = LocalRunnerRuntime(flaky)
    ref = await runtime.start("agent_x", {})
    failed = await runtime.resume(ref.session_id)
    assert failed.status == "failed"
    retried = await runtime.resume(ref.session_id)
    assert retried.status == "failed"
    assert len(attempts) == 2


async def test_failing_workflow_yields_failed_run_result() -> None:
    async def boom(_payload: dict[str, Any]) -> dict[str, Any]:
        msg = "workflow exploded"
        raise RuntimeError(msg)

    runtime = LocalRunnerRuntime(boom)
    ref = await runtime.start("agent_x", {"k": "v"})
    result = await runtime.resume(ref.session_id)
    assert result.status == "failed"
    assert "workflow exploded" in result.error
    assert result.output is None


async def test_run_result_output_is_json_serializable() -> None:
    runtime = LocalRunnerRuntime(_echo_workflow)
    ref = await runtime.start("agent_x", {"nested": {"a": [1, 2]}})
    result = await runtime.resume(ref.session_id)
    assert json.loads(json.dumps(result.model_dump(mode="json")))["status"] == "completed"


def test_implementations_satisfy_the_port_protocol() -> None:
    port: RuntimePort = LocalRunnerRuntime(_echo_workflow)
    assert port is not None


# ─── Factory ────────────────────────────────────────────────────────────────


def test_factory_defaults_to_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DF_RUNTIME", raising=False)
    port = create_runtime_from_env(_echo_workflow)
    assert isinstance(port, LocalRunnerRuntime)


def test_factory_selects_local_explicitly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DF_RUNTIME", "local")
    port = create_runtime_from_env(_echo_workflow)
    assert isinstance(port, LocalRunnerRuntime)


def test_factory_rejects_unknown_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DF_RUNTIME", "adk-cloud-run")
    with pytest.raises(ValueError):
        create_runtime_from_env(_echo_workflow)
