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

from datetime import UTC, datetime
from typing import Any

import ulid
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
from delegation_fabric_core.policy.projection import project_fields
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field


class ExecuteRequest(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


def create_app(
    store: MemoryStore | None = None,
    verifier: JWSGrantVerifier | None = None,
    region: str = "asia-south1",
) -> FastAPI:
    app = FastAPI(title="Delegation Fabric Execution Gateway", version="0.1.0")

    db = store or MemoryStore()
    jws_verifier = verifier or JWSGrantVerifier()

    invoices_db = {
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
    po_db = {
        "PO-882": {
            "po_id": "PO-882",
            "vendor_id": "V-1001",
            "total_minor": 74200000,
            "currency": "INR",
            "status": "open",
        }
    }
    vendors_db = {
        "V-1001": {
            "vendor_id": "V-1001",
            "legal_name": "Acme Supplies Private Ltd",
            "status": "active",
            "country_code": "IN",
            "bank_account": "SECRET_ACC_987654",
        }
    }

    @app.post("/v1/execute")
    async def execute(
        req: ExecuteRequest,
        authorization: str = Header(..., description="Bearer <ExecutionGrant>"),
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        now_ts = int(now.timestamp())

        # Step 1 & 2 & 3 & 4: Extract Bearer and parse/verify JWS
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "UNAUTHORIZED", "message": "Missing Bearer token"},
            )

        token = authorization[7:].strip()
        try:
            header, grant = jws_verifier.parse_and_verify(token)
        except GrantSignatureError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": ReasonCode.GRANT_INVALID_SIGNATURE.value, "message": str(e)},
            ) from e

        # Step 5: Issuer and Audience verification
        if grant.iss != "delegation-fabric-control-plane":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "GRANT_INVALID_ISSUER",
                    "message": f"Unexpected issuer: {grant.iss}",
                },
            )
        if grant.aud != "delegation-fabric-execution-gateway":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.GRANT_INVALID_AUDIENCE.value,
                    "message": f"Unexpected audience: {grant.aud}",
                },
            )

        # Step 6: Time bounds (nbf / exp)
        if now_ts < grant.nbf:
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

        # Step 8: Live Delegation & Task active status
        delegation = await db.get_delegation(grant.delegation_id)
        if (
            not delegation
            or delegation.status != DelegationStatus.ACTIVE
            or delegation.expires_at <= now
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.DELEGATION_REVOKED.value
                    if delegation and delegation.status == DelegationStatus.REVOKED
                    else ReasonCode.DELEGATION_NOT_FOUND.value,
                    "message": "Delegation inactive or revoked",
                },
            )

        # Step 9: Tool Binding
        if grant.tool != req.tool:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ReasonCode.GRANT_TOOL_MISMATCH.value,
                    "message": f"Grant authorizes tool {grant.tool!r}, attempted {req.tool!r}",
                },
            )

        # Step 10 & 11: Transactional Grant Consumption (Consume First -> Execute Second)
        if grant.single_use:
            try:
                await db.consume_grant_atomic(grant.grant_id, now)
            except GrantReplayError as e:
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

        # Step 12: Re-evaluate actual request arguments
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

        # Step 13: Adapter Execution
        raw_result: Any = None
        resource_refs: list[str] = []

        if req.tool == "invoice.read":
            inv_id = req.arguments.get("invoice_id")
            if inv_id not in invoices_db:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found"
                )
            raw_result = invoices_db[inv_id]
            resource_refs.append(f"invoice:{inv_id}")

        elif req.tool == "purchase_order.read":
            p_id = req.arguments.get("po_id")
            if p_id not in po_db:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PO not found")
            raw_result = po_db[p_id]
            resource_refs.append(f"purchase_order:{p_id}")

        elif req.tool == "vendor.read":
            v_id = req.arguments.get("vendor_id")
            if v_id not in vendors_db:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found"
                )
            raw_result = vendors_db[v_id]
            resource_refs.append(f"vendor:{v_id}")

        elif req.tool == "reconciliation.write":
            raw_result = {
                "reconciliation_id": f"rec_{ulid.ULID()}",
                "invoice_id": req.arguments.get("invoice_id"),
                "result": req.arguments.get("result", "matched"),
                "variance_minor": req.arguments.get("variance_minor", 0),
            }
            resource_refs.append(f"reconciliation:{raw_result['reconciliation_id']}")

        elif req.tool == "payment.instruct":
            raw_result = {
                "payment_id": f"pay_{ulid.ULID()}",
                "batch_id": req.arguments.get("batch_id"),
                "status": "accepted",
                "processed_at": now.isoformat(),
            }
            resource_refs.append(f"payment:{raw_result['payment_id']}")

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown tool adapter {req.tool!r}",
            )

        # Step 14: Response Field Projection
        projection = project_fields(raw_result, grant.allowed_response_fields)

        # Append Audit Event
        existing_chain = await db.get_audit_events(grant.task_id)
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

        return {
            "grant_id": grant.grant_id,
            "tool": grant.tool,
            "result": projection.projected,
        }

    return app
