"""Pre-demo preflight checks.

Validates the local environment before running the demo:
1. Python + dependency imports resolve.
2. Core domain invariants (constraint engine, projection, audit chain).
3. In-process service wiring (Control Plane -> Execution Gateway -> Worker).
4. Required configuration surface (env vars) is documented/present for
   cloud deployments when DF_ENV != local.

Exit code 0 = all gates pass. Any failure exits non-zero with a reason.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for p in (str(_ROOT), str(_ROOT / "packages")):
    if p not in sys.path:
        sys.path.insert(0, p)

from datetime import UTC, datetime, timedelta  # noqa: E402

from delegation_fabric_adapters.firestore.store import MemoryStore  # noqa: E402
from delegation_fabric_adapters.kms.signer import JWSGrantVerifier, LocalKMSSigner  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from apps.control_plane.main import create_app as create_control_plane  # noqa: E402
from apps.execution_gateway.main import create_app as create_execution_gateway  # noqa: E402
from apps.worker.main import create_app as create_worker  # noqa: E402

CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, ok, detail))
    marker = "PASS" if ok else "FAIL"
    suffix = f" — {detail}" if detail else ""
    print(f"  [{marker}] {name}{suffix}")


async def check_services() -> None:
    print("\n[3] Service wiring (in-process)")
    store = MemoryStore()
    signer = LocalKMSSigner()
    verifier = JWSGrantVerifier()
    verifier.register_public_key(signer.key_version, signer.get_public_key_pem())

    cp = create_control_plane(store=store, signer=signer)
    gw = create_execution_gateway(store=store, verifier=verifier)
    worker = create_worker(store=store)

    async with (
        AsyncClient(transport=ASGITransport(app=cp), base_url="http://cp.test") as cp_c,
        AsyncClient(transport=ASGITransport(app=gw), base_url="http://gw.test") as gw_c,
        AsyncClient(transport=ASGITransport(app=worker), base_url="http://w.test") as w_c,
    ):
        resp = await cp_c.post(
            "/v1/delegations",
            json={
                "purpose": "invoice_reconciliation",
                "task_id": "task_preflight",
                "allowed_agents": ["invoice-reconciliation"],
                "allowed_regions": ["asia-south1"],
                "expires_at": (datetime.now(UTC) + timedelta(hours=24)).isoformat(),
            },
        )
        check("POST /v1/delegations", resp.status_code == 201, f"HTTP {resp.status_code}")
        delegation_id = resp.json().get("delegation_id", "")

        agents_resp = await cp_c.get("/v1/agents")
        check(
            "Registry facade /v1/agents",
            agents_resp.status_code == 200 and len(agents_resp.json()) == 3,
            f"{len(agents_resp.json())} agents",
        )

        grant_resp = (
            await cp_c.post(
                "/v1/grants/evaluate",
                json={
                    "task_id": "task_preflight",
                    "delegation_id": delegation_id,
                    "agent": {"id": "invoice-reconciliation", "version": "1.0.0"},
                    "tool": "invoice.read",
                    "arguments": {"invoice_id": "INV-042"},
                },
            )
        ).json()
        check(
            "Grant issued (KMS-signed ES256)",
            grant_resp.get("decision") == "allow" and grant_resp.get("token"),
            f"decision={grant_resp.get('decision')}",
        )

        exec_headers = {
            "Authorization": f"Bearer {grant_resp.get('token', '')}",
            "X-Agent-Id": "invoice-reconciliation",
            "X-Agent-Version": "1.0.0",
        }
        exec_resp = await gw_c.post(
            "/v1/execute",
            json={"tool": "invoice.read", "arguments": {"invoice_id": "INV-042"}},
            headers=exec_headers,
        )
        check(
            "Execution Gateway executes invoice.read",
            exec_resp.status_code == 200,
            f"HTTP {exec_resp.status_code}",
        )

        replay = await gw_c.post(
            "/v1/execute",
            json={"tool": "invoice.read", "arguments": {"invoice_id": "INV-042"}},
            headers=exec_headers,
        )
        check("Replay rejected (single-use)", replay.status_code == 403)

        # Worker event round-trip: task.start advances CREATED -> RUNNING
        import base64 as b64
        import json as jsonlib

        envelope = {
            "event_id": "evt_preflight_start",
            "event_type": "task.start",
            "task_id": "task_preflight",
            "occurred_at": datetime.now(UTC).isoformat(),
            "source": "control-plane",
            "schema_version": "1",
            "data": {},
        }
        worker_resp = await w_c.post(
            "/internal/events/pubsub",
            json={"message": {"data": b64.b64encode(jsonlib.dumps(envelope).encode()).decode()}},
        )
        check(
            "Worker event round-trip",
            worker_resp.status_code == 200 and worker_resp.json().get("new_state") == "running",
            f"{worker_resp.json().get('status')}",
        )

        verify = (await cp_c.get("/v1/audit/tasks/task_preflight/verify")).json()
        check(
            "Audit chain verifies",
            verify.get("valid") is True and verify.get("events", 0) >= 2,
            f"{verify.get('events')} events",
        )

        export = await cp_c.post("/v1/audit/tasks/task_preflight/export")
        check("Audit export available", export.status_code == 200)

        console_resp = await cp_c.get("/console")
        check("Console served at /console", console_resp.status_code == 200)

        metrics_resp = await cp_c.get("/metrics")
        check("Metrics endpoint live", metrics_resp.status_code == 200)


async def main() -> int:
    print("=" * 60)
    print("   DELEGATION FABRIC — DEMO PREFLIGHT")
    print("=" * 60)

    print("\n[1] Runtime")
    check(f"Python {'.'.join(map(str, sys.version_info[:3]))}", sys.version_info >= (3, 12))

    print("\n[2] Configuration")
    df_env = os.environ.get("DF_ENV", "local")
    print(f"  DF_ENV={df_env}")
    if df_env == "local":
        print("  [SKIP] Cloud config checks skipped for local run.")
    else:
        required = [
            "GOOGLE_CLOUD_PROJECT",
            "DF_KMS_KEY_VERSION",
            "DF_CONTROL_PLANE_URL",
            "DF_EXECUTION_GATEWAY_URL",
        ]
        missing = [k for k in required if not os.environ.get(k)]
        check("Cloud env vars present", not missing, f"missing={missing or 'none'}")

    await check_services()

    failed = [c for c in CHECKS if not c[1]]
    print("\n" + "=" * 60)
    if failed:
        print(f"   PREFLIGHT FAILED ({len(failed)} gate(s) down)")
        print("=" * 60)
        return 1
    print("   PREFLIGHT PASSED — demo environment ready")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
