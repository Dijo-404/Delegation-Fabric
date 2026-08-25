"""Execution Gateway application.

Enforces the strict 14-step verification sequence from docs/ARCHITECTURE.md § 6:
1.  Caller authentication
2.  Token syntax / header
3.  Key ID allowed
4.  Signature valid
5.  Issuer / Audience valid
6.  nbf / iat / exp time bounds
7.  Deployment region matches
8.  Delegation & task active status check (live datastore read)
9.  Agent ID & version binding
10. Exact tool binding
11. Atomic single-use grant consumption (Firestore transaction)
12. Actual argument constraints re-evaluation
13. Protected adapter execution
14. Response field projection & audit appending
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import ulid
from delegation_fabric_adapters.config import (
    DEFAULT_DEPLOYMENT_REGION,
    deployment_region,
    grant_audience,
    grant_issuer,
)
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import JWSGrantVerifier
from delegation_fabric_core.audit.chain import GENESIS_HASH, finalize_audit_event
from delegation_fabric_core.constraints.engine import evaluate_constraints
from delegation_fabric_core.errors.exceptions import (
    GrantExpiredError,
    GrantReplayError,
    GrantSignatureError,
    GrantUnknownError,
)
from delegation_fabric_core.models.audit import AuditActor, AuditActorType, AuditEvent
from delegation_fabric_core.models.delegation import DelegationStatus
from delegation_fabric_core.models.policy import ReasonCode
from delegation_fabric_core.models.task import TaskState
from delegation_fabric_core.policy.projection import project_fields
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

if TYPE_CHECKING:
    from delegation_fabric_adapters.firestore.firestore_store import FirestoreStore
from pydantic import BaseModel, Field


class ExecuteRequest(BaseModel):
    model_config = {"extra": "forbid"}

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


_REQUIRED_ARGS: dict[str, tuple[str, ...]] = {
    "invoice.read": ("invoice_id",),
    "purchase_order.read": ("po_id",),
    "vendor.read": ("vendor_id",),
    "reconciliation.write": ("invoice_id",),
    "payment.instruct": ("batch_id", "amount_minor", "currency"),
}


class _BuiltinDemoERP:
    """In-memory demo dataset used when no ERP backend is configured."""

    def __init__(self) -> None:
        self.invoices = {
            "INV-042": {
                "invoice_id": "INV-042",
                "vendor_id": "V-1001",
                "po_id": "PO-882",
                "total_minor": 74200000,
                "currency": "INR",
                "status": "pending",
                "bank_account_internal": "SECRET_ACC_987654",
            }
        }
        self.purchase_orders = {
            "PO-882": {
                "po_id": "PO-882",
                "vendor_id": "V-1001",
                "total_minor": 74200000,
                "currency": "INR",
                "status": "open",
            }
        }
        self.vendors = {
            "V-1001": {
                "vendor_id": "V-1001",
                "legal_name": "Acme Supplies Private Ltd",
                "status": "active",
                "country_code": "IN",
                "bank_account": "SECRET_ACC_987654",
            }
        }

    async def read_invoice(self, invoice_id: str) -> dict[str, Any] | None:
        return self.invoices.get(invoice_id)

    async def read_purchase_order(self, po_id: str) -> dict[str, Any] | None:
        return self.purchase_orders.get(po_id)

    async def read_vendor(self, vendor_id: str) -> dict[str, Any] | None:
        return self.vendors.get(vendor_id)

    async def write_reconciliation(self, args: dict[str, Any]) -> dict[str, Any]:
        return {
            "reconciliation_id": f"rec_{ulid.ULID()}",
            "invoice_id": args.get("invoice_id"),
            "result": args.get("result", "matched"),
            "variance_minor": args.get("variance_minor", 0),
        }

    async def instruct_payment(self, args: dict[str, Any], grant_id: str) -> dict[str, Any]:
        del grant_id
        return {
            "payment_id": f"pay_{ulid.ULID()}",
            "batch_id": args.get("batch_id"),
            "status": "accepted",
            "processed_at": datetime.now(UTC).isoformat(),
        }


def create_app(
    store: MemoryStore | FirestoreStore | None = None,
    verifier: JWSGrantVerifier | None = None,
    region: str = DEFAULT_DEPLOYMENT_REGION,
    erp: Any = None,
) -> FastAPI:
    app = FastAPI(title="Delegation Fabric Execution Gateway", version="0.2.0")

    from delegation_fabric_adapters.observability import METRICS, configure_logging, log_event

    configure_logging()

    db = store or MemoryStore()
    jws_verifier = verifier or JWSGrantVerifier()
    erp_backend: Any = erp or _BuiltinDemoERP()

    @app.post("/v1/execute")
    async def execute(
        req: ExecuteRequest,
        request: Request,
        authorization: str = Header(..., description="Bearer <ExecutionGrant>"),
    ) -> dict[str, Any]:
        _t0 = time.perf_counter()
        now = datetime.now(UTC)
        now_ts = int(now.timestamp())

        # Step 1 & 2 & 3 & 4: Extract Bearer and parse/verify JWS
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "UNAUTHORIZED", "message": "Missing Bearer token"},
            )

        token = authorization[7:].strip()

        # Fail-closed caller identity declaration (PLAN.md Day 2, step 9):
        # the presenting agent MUST declare its id and version on every
        # execution request so both can be bound against the signed grant
        # claims. Checked before grant verification so a malformed request is
        # rejected structurally and never consumes the single-use credential.
        caller_agent = request.headers.get("x-agent-id")
        if not caller_agent:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "MISSING_AGENT_ID",
                    "message": "X-Agent-Id header is required for execution",
                },
            )
        caller_version = request.headers.get("x-agent-version")
        if not caller_version:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "MISSING_AGENT_VERSION",
                    "message": "X-Agent-Version header is required for execution",
                },
            )

        try:
            header, grant = jws_verifier.parse_and_verify(token)
        except GrantSignatureError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": ReasonCode.GRANT_INVALID_SIGNATURE.value, "message": str(e)},
            ) from e

        # Step 5: Issuer and Audience verification
        if grant.iss != grant_issuer():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.GRANT_INVALID_ISSUER.value,
                    "message": f"Unexpected issuer: {grant.iss}",
                },
            )
        if grant.aud != grant_audience():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.GRANT_INVALID_AUDIENCE.value,
                    "message": f"Unexpected audience: {grant.aud}",
                },
            )

        # Step 6: Time bounds (iat sanity / nbf / exp) with clock-skew tolerance
        skew = int(os.environ.get("DF_CLOCK_SKEW_SECONDS", "30"))
        if now_ts + skew < grant.iat:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.GRANT_NOT_YET_VALID.value,
                    "message": "Grant issued in the future (clock skew exceeded)",
                },
            )
        if now_ts < grant.nbf - skew:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.GRANT_NOT_YET_VALID.value,
                    "message": "Grant is not yet valid",
                },
            )
        if now_ts >= grant.exp:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": ReasonCode.GRANT_EXPIRED.value, "message": "Grant has expired"},
            )

        # Step 7: Deployment Region
        if grant.region != region:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.GRANT_REGION_MISMATCH.value,
                    "message": f"Region mismatch: grant for {grant.region}, gateway in {region}",
                },
            )

        # Step 8a: Live Delegation status with distinct reason codes
        delegation = await db.get_delegation(grant.delegation_id)
        if delegation is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.DELEGATION_NOT_FOUND.value,
                    "message": "Delegation not found",
                },
            )
        if delegation.status == DelegationStatus.REVOKED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.DELEGATION_REVOKED.value,
                    "message": "Delegation has been revoked",
                },
            )
        if delegation.status != DelegationStatus.ACTIVE or delegation.expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.DELEGATION_EXPIRED.value,
                    "message": "Delegation is expired or inactive",
                },
            )

        # Step 8b: Task liveness — terminal or quarantined tasks cannot execute
        task = await db.get_task(grant.task_id)
        if task is None or task.state.is_terminal() or task.state == TaskState.QUARANTINED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.TASK_NOT_BOUND_TO_DELEGATION.value
                    if task is None
                    else "TASK_NOT_LIVE",
                    "message": f"Task {grant.task_id!r} is not in a live state"
                    + (f" (state={task.state.value})" if task else ""),
                },
            )

        # Step 9a: Agent ID binding — declared identity must match the grant subject.
        # (X-Agent-Id is derived from authenticated service context on Cloud Run.)
        if caller_agent != grant.agent_id:
            METRICS.inc("grant_denied_total", reason=ReasonCode.GRANT_AGENT_MISMATCH.value)
            log_event(
                "grant denied",
                reason=ReasonCode.GRANT_AGENT_MISMATCH.value,
                field="agent_id",
                expected=grant.agent_id,
                received=caller_agent,
                task_id=grant.task_id,
                delegation_id=grant.delegation_id,
                grant_id=grant.grant_id,
                decision="deny",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.GRANT_AGENT_MISMATCH.value,
                    "message": f"Caller {caller_agent!r} does not match grant agent {grant.agent_id!r}",
                },
            )

        # Step 9b: Agent version binding — re-verified at execution time against
        # the version pinned into the grant at issuance (stale-build defense).
        if caller_version != grant.agent_version:
            METRICS.inc("grant_denied_total", reason=ReasonCode.GRANT_AGENT_MISMATCH.value)
            log_event(
                "grant denied",
                reason=ReasonCode.GRANT_AGENT_MISMATCH.value,
                field="agent_version",
                expected=grant.agent_version,
                received=caller_version,
                task_id=grant.task_id,
                delegation_id=grant.delegation_id,
                grant_id=grant.grant_id,
                decision="deny",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.GRANT_AGENT_MISMATCH.value,
                    "message": f"Caller agent version {caller_version!r} does not match "
                    f"grant-pinned version {grant.agent_version!r}",
                },
            )

        # Step 9c: Tool binding + adapter whitelist & required-argument validation
        # BEFORE consumption, so malformed requests never burn a single-use grant.
        if grant.tool != req.tool:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.GRANT_TOOL_MISMATCH.value,
                    "message": f"Grant authorizes tool {grant.tool!r}, attempted {req.tool!r}",
                },
            )
        required_args = _REQUIRED_ARGS.get(req.tool)
        if required_args is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "UNKNOWN_TOOL", "message": f"Unknown tool {req.tool!r}"},
            )
        missing = [k for k in required_args if k not in req.arguments]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": ReasonCode.ARGUMENT_PATH_UNKNOWN.value,
                    "message": f"Missing required arguments: {', '.join(missing)}",
                },
            )

        # Step 12 (pre-consume): Re-evaluate actual request arguments so that a
        # constraint violation never consumes the credential.
        if grant.arg_constraints:
            pol_dec = evaluate_constraints(grant.arg_constraints, req.arguments)
            if not pol_dec.allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": pol_dec.reason_code.value
                        if pol_dec.reason_code
                        else ReasonCode.ARGUMENT_CONSTRAINT_FAILED.value,
                        "message": pol_dec.reason_detail
                        or "Actual arguments violate grant constraints",
                    },
                )

        # Step 10 & 11: Transactional single-use Grant Consumption.
        # At-most-once authorization use; downstream idempotency by grant_id
        # resolves timeouts after a possible commit (docs/AUTHORIZATION.md § 10).
        if grant.single_use:
            try:
                await db.consume_grant_atomic(grant.grant_id, now)
            except GrantReplayError as e:
                METRICS.inc("grant_replay_total")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": ReasonCode.GRANT_REPLAYED.value,
                        "message": "Grant has already been consumed",
                    },
                ) from e
            except (GrantExpiredError, GrantUnknownError) as e:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": ReasonCode.GRANT_EXPIRED.value
                        if isinstance(e, GrantExpiredError)
                        else ReasonCode.GRANT_UNKNOWN.value,
                        "message": str(e),
                    },
                ) from e

        # Step 13: Adapter Execution
        raw_result: Any = None
        resource_refs: list[str] = []

        if req.tool == "invoice.read":
            inv = await erp_backend.read_invoice(req.arguments.get("invoice_id", ""))
            if inv is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found"
                )
            raw_result = inv
            resource_refs.append(f"invoice:{inv.get('invoice_id')}")

        elif req.tool == "purchase_order.read":
            po = await erp_backend.read_purchase_order(req.arguments.get("po_id", ""))
            if po is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PO not found")
            raw_result = po
            resource_refs.append(f"purchase_order:{po.get('po_id')}")

        elif req.tool == "vendor.read":
            vendor = await erp_backend.read_vendor(req.arguments.get("vendor_id", ""))
            if vendor is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found"
                )
            raw_result = vendor
            resource_refs.append(f"vendor:{vendor.get('vendor_id')}")

        elif req.tool == "reconciliation.write":
            raw_result = await erp_backend.write_reconciliation(req.arguments)
            resource_refs.append(f"reconciliation:{raw_result['reconciliation_id']}")

        elif req.tool == "payment.instruct":
            # Downstream idempotency keyed by grant_id (payments.grant_id UNIQUE).
            raw_result = await erp_backend.instruct_payment(req.arguments, grant.grant_id)
            resource_refs.append(f"payment:{raw_result['payment_id']}")

        # Step 14: Response Field Projection
        projection = project_fields(raw_result, grant.allowed_response_fields)

        # Append Audit Event
        existing_chain = await db.get_audit_events(grant.task_id, limit=None)
        prev_hash = existing_chain[-1].event_hash if existing_chain else GENESIS_HASH

        audit_evt = AuditEvent(
            audit_event_id=f"aud_{ulid.ULID()}",
            task_id=grant.task_id,
            delegation_id=grant.delegation_id,
            grant_id=grant.grant_id,
            actor=AuditActor(
                type=AuditActorType.AGENT,
                id=grant.agent_id,
                version=grant.agent_version,
            ),
            event_type="tool.execution.completed",
            tool=grant.tool,
            decision="allow",
            policy_version=grant.policy_version,
            approval_ids=grant.approval_ids,
            resource_refs=resource_refs,
            occurred_at=now,
            prev_hash=prev_hash,
        )
        finalized_evt = finalize_audit_event(audit_evt, prev_hash)
        await db.append_audit_event(finalized_evt)

        METRICS.inc("tool_execution_total", tool=grant.tool, status="success")
        execution_latency_ms = (time.perf_counter() - _t0) * 1000.0
        METRICS.observe("gateway_execution_latency_ms", execution_latency_ms)
        log_event(
            "tool executed",
            task_id=grant.task_id,
            delegation_id=grant.delegation_id,
            grant_id=grant.grant_id,
            agent_id=grant.agent_id,
            agent_version=grant.agent_version,
            tool=grant.tool,
            decision="allow",
            latency_ms=round(execution_latency_ms, 2),
        )

        return {
            "grant_id": grant.grant_id,
            "tool": grant.tool,
            "result": projection.projected,
        }

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        return PlainTextResponse(
            METRICS.prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return app


def create_app_from_env() -> FastAPI:
    from delegation_fabric_adapters.config import (
        build_erp_backend,
        build_signer,
        build_store,
        build_verifier,
    )
    from delegation_fabric_adapters.tracing import configure_tracing, instrument_fastapi_app

    configure_tracing("execution-gateway")
    signer = build_signer()
    application = create_app(
        store=build_store(),
        verifier=build_verifier(signer),
        region=deployment_region(),
        erp=build_erp_backend(),
    )
    instrument_fastapi_app(application)
    return application


app = create_app_from_env()
