"""Env wiring for grant issuer/audience and deployment region resolution."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from delegation_fabric_adapters.config import (
    DEFAULT_DEPLOYMENT_REGION,
    DEFAULT_GRANT_AUDIENCE,
    DEFAULT_GRANT_ISSUER,
    deployment_region,
    grant_audience,
    grant_issuer,
)
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import JWSGrantVerifier, LocalKMSSigner
from httpx import ASGITransport, AsyncClient

from apps.control_plane.main import create_app as create_control_plane
from apps.execution_gateway.main import (
    create_app as create_execution_gateway,
)
from apps.execution_gateway.main import (
    create_app_from_env as create_gateway_from_env,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "DF_GRANT_ISSUER",
        "DF_GRANT_AUDIENCE",
        "GOOGLE_CLOUD_LOCATION",
        "GOOGLE_CLOUD_REGION",
    ):
        monkeypatch.delenv(var, raising=False)


def test_default_issuer_and_audience_are_current_literals() -> None:
    assert grant_issuer() == "delegation-fabric-control-plane" == DEFAULT_GRANT_ISSUER
    assert grant_audience() == "delegation-fabric-execution-gateway" == DEFAULT_GRANT_AUDIENCE


def test_env_overrides_change_issuer_and_audience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DF_GRANT_ISSUER", "cp-other")
    monkeypatch.setenv("DF_GRANT_AUDIENCE", "gw-other")
    assert grant_issuer() == "cp-other"
    assert grant_audience() == "gw-other"


def test_region_prefers_location_then_falls_back_then_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "europe-west1")
    monkeypatch.setenv("GOOGLE_CLOUD_REGION", "us-central1")
    assert deployment_region() == "europe-west1"

    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION")
    assert deployment_region() == "us-central1"

    monkeypatch.delenv("GOOGLE_CLOUD_REGION")
    assert deployment_region() == DEFAULT_DEPLOYMENT_REGION == "asia-south1"


def test_gateway_env_factory_wires_tracing_without_otel_stack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """create_app_from_env must configure tracing gracefully with no OTel/GCP env."""
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    app = create_gateway_from_env()
    assert app.title == "Delegation Fabric Execution Gateway"


def _grant_claims(token: str) -> dict[str, Any]:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _delegation_body(task_id: str, regions: list[str]) -> dict[str, Any]:
    expires = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "purpose": "invoice_reconciliation",
        "task_id": task_id,
        "allowed_agents": ["invoice-reconciliation"],
        "allowed_regions": regions,
        "expires_at": expires,
    }


def _gw_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Agent-Id": "invoice-reconciliation",
        "X-Agent-Version": "1.0.0",
    }


@pytest.mark.asyncio
async def test_mint_verify_round_trip_honors_env_override() -> None:
    store = MemoryStore()
    signer = LocalKMSSigner()
    verifier = JWSGrantVerifier()
    verifier.register_public_key(signer.key_version, signer.get_public_key_pem())

    cp_app = create_control_plane(store=store, signer=signer)
    gw_app = create_execution_gateway(store=store, verifier=verifier)

    async with (
        AsyncClient(transport=ASGITransport(app=cp_app), base_url="http://cp.test") as cp,
        AsyncClient(transport=ASGITransport(app=gw_app), base_url="http://gw.test") as gw,
    ):
        del_resp = await cp.post(
            "/v1/delegations",
            json=_delegation_body("task_envwiring", ["asia-south1"]),
            headers={"x-authenticated-user": "user:priya@example.com"},
        )
        assert del_resp.status_code == 201
        delegation_id = del_resp.json()["delegation_id"]

        eval_resp = await cp.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_envwiring",
                "delegation_id": delegation_id,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "invoice.read",
                "arguments": {"invoice_id": "INV-042"},
            },
        )
        assert eval_resp.status_code == 200
        token = eval_resp.json()["token"]

        claims = _grant_claims(token)
        assert claims["iss"] == "delegation-fabric-control-plane"
        assert claims["aud"] == "delegation-fabric-execution-gateway"

        exec_resp = await gw.post(
            "/v1/execute",
            json={"tool": "invoice.read", "arguments": {"invoice_id": "INV-042"}},
            headers=_gw_headers(token),
        )
        assert exec_resp.status_code == 200


@pytest.mark.asyncio
async def test_env_override_flows_through_mint_and_verify_round_trip(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("DF_GRANT_ISSUER", "df-cp-staging")
    monkeypatch.setenv("DF_GRANT_AUDIENCE", "df-gw-staging")

    store = MemoryStore()
    signer = LocalKMSSigner()
    verifier = JWSGrantVerifier()
    verifier.register_public_key(signer.key_version, signer.get_public_key_pem())

    cp_app = create_control_plane(store=store, signer=signer)
    gw_app = create_execution_gateway(store=store, verifier=verifier)

    async with (
        AsyncClient(transport=ASGITransport(app=cp_app), base_url="http://cp.test") as cp,
        AsyncClient(transport=ASGITransport(app=gw_app), base_url="http://gw.test") as gw,
    ):
        del_resp = await cp.post(
            "/v1/delegations",
            json=_delegation_body("task_envoverride", ["asia-south1"]),
            headers={"x-authenticated-user": "user:priya@example.com"},
        )
        assert del_resp.status_code == 201
        delegation_id = del_resp.json()["delegation_id"]

        eval_resp = await cp.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_envoverride",
                "delegation_id": delegation_id,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "invoice.read",
                "arguments": {"invoice_id": "INV-042"},
            },
        )
        assert eval_resp.status_code == 200
        token = eval_resp.json()["token"]

    claims = _grant_claims(token)
    assert claims["iss"] == "df-cp-staging"
    assert claims["aud"] == "df-gw-staging"

    body = {"tool": "invoice.read", "arguments": {"invoice_id": "INV-042"}}
    headers = _gw_headers(token)

    async with AsyncClient(transport=ASGITransport(app=gw_app), base_url="http://gw.test") as gw:
        ok_resp = await gw.post("/v1/execute", json=body, headers=headers)
        assert ok_resp.status_code == 200
        assert '"latency_ms"' in capsys.readouterr().out  # GW executed log record

        monkeypatch.setenv("DF_GRANT_ISSUER", "df-cp-somewhere-else")
        stale_resp = await gw.post("/v1/execute", json=body, headers=headers)
        assert stale_resp.status_code == 403
        assert stale_resp.json()["detail"]["code"] == "GRANT_INVALID_ISSUER"


@pytest.mark.asyncio
async def test_gateway_region_check_follows_location_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "europe-west1")
    store = MemoryStore()
    signer = LocalKMSSigner()
    verifier = JWSGrantVerifier()
    verifier.register_public_key(signer.key_version, signer.get_public_key_pem())

    cp_app = create_control_plane(store=store, signer=signer)
    gw_app = create_execution_gateway(store=store, verifier=verifier, region=deployment_region())

    async with (
        AsyncClient(transport=ASGITransport(app=cp_app), base_url="http://cp.test") as cp,
        AsyncClient(transport=ASGITransport(app=gw_app), base_url="http://gw.test") as gw,
    ):
        del_resp = await cp.post(
            "/v1/delegations",
            json=_delegation_body("task_regionloc", ["europe-west1"]),
            headers={"x-authenticated-user": "user:priya@example.com"},
        )
        assert del_resp.status_code == 201
        delegation_id = del_resp.json()["delegation_id"]

        eval_resp = await cp.post(
            "/v1/grants/evaluate",
            json={
                "task_id": "task_regionloc",
                "delegation_id": delegation_id,
                "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                "tool": "invoice.read",
                "arguments": {"invoice_id": "INV-042"},
                "region": "europe-west1",
            },
        )
        assert eval_resp.status_code == 200
        token = eval_resp.json()["token"]

        exec_resp = await gw.post(
            "/v1/execute",
            json={"tool": "invoice.read", "arguments": {"invoice_id": "INV-042"}},
            headers=_gw_headers(token),
        )
        assert exec_resp.status_code == 200
