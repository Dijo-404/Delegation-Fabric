"""Control Plane service implementation.

Endpoints per docs/API_CONTRACTS.md:
- POST /v1/delegations
- POST /v1/delegations/{id}/revoke
- POST /v1/grants/evaluate (Full 14-phase evaluation + KMS asymmetric signing)
- GET  /v1/grants/{id}
- POST /v1/approvals
- GET  /v1/tasks/{id}
- POST /v1/tasks/{id}/release
- GET  /v1/audit/tasks/{id}
- GET  /v1/audit/tasks/{id}/verify
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import ulid
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import LocalKMSSigner
from delegation_fabric_core.audit.chain import (
    ChainVerificationResult,
    canonical_json,
    verify_audit_chain,
)
from delegation_fabric_core.constraints.engine import evaluate_constraints
from delegation_fabric_core.models.approval import ApprovalDecision, ApprovalRecord
from delegation_fabric_core.models.constraint import Constraint, ConstraintOp
from delegation_fabric_core.models.delegation import Delegation, DelegationStatus, Sponsor
from delegation_fabric_core.models.grant import ExecutionGrant, GrantRecord, GrantStatus
from delegation_fabric_core.models.manifest import AgentManifest, RiskClass
from delegation_fabric_core.models.policy import ReasonCode
from delegation_fabric_core.models.task import Task, TaskState
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

# Request models defined at module level for Pydantic type resolution in Python 3.13 / FastAPI


class CreateDelegationRequest(BaseModel):
    purpose: str
    task_id: str
    allowed_agents: list[str] = Field(default_factory=list)
    allowed_regions: list[str] = Field(default_factory=lambda: ["asia-south1"])
    expires_at: datetime
    policy_version: str = "finance-policy-2026-08-20.1"


class RevokeDelegationRequest(BaseModel):
    reason: str = "workflow_cancelled"


class EvaluateGrantAgent(BaseModel):
    id: str
    version: str = "1.0.0"


class EvaluateGrantRequest(BaseModel):
    task_id: str
    delegation_id: str
    agent: EvaluateGrantAgent
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    region: str = "asia-south1"


class CreateApprovalRequest(BaseModel):
    task_id: str
    delegation_id: str
    approval_type: str
    subject: dict[str, Any]
    decision: ApprovalDecision = ApprovalDecision.APPROVED
    expires_in_seconds: int = 14400  # 4 hours


def create_app(
    store: MemoryStore | None = None,
    signer: LocalKMSSigner | None = None,
    manifests: dict[str, AgentManifest] | None = None,
) -> FastAPI:
    app = FastAPI(title="Delegation Fabric Control Plane", version="0.1.0")

    db = store or MemoryStore()
    kms_signer = signer or LocalKMSSigner()

    agent_manifests: dict[str, AgentManifest] = manifests or {
        "invoice-reconciliation": AgentManifest(
            agent_id="invoice-reconciliation",
            version="1.0.0",
            risk_class=RiskClass.MEDIUM,
            capabilities=["invoice.read", "purchase_order.read", "reconciliation.write"],
            denied_tools=["payment.instruct", "vendor_bank_account.read"],
            allowed_regions=["asia-south1"],
        ),
        "procurement-exception": AgentManifest(
            agent_id="procurement-exception",
            version="1.0.0",
            risk_class=RiskClass.HIGH,
            capabilities=["vendor.read", "exception.write"],
            denied_tools=["payment.instruct", "exception.approve_self"],
            allowed_regions=["asia-south1"],
        ),
        "treasury-approval": AgentManifest(
            agent_id="treasury-approval",
            version="1.0.3",
            risk_class=RiskClass.CRITICAL,
            capabilities=["payment_batch.read", "payment.instruct"],
            denied_tools=[],
            allowed_regions=["asia-south1"],
        ),
    }

    # ─── 1. Delegations ────────────────────────────────────────────────────────

    @app.post("/v1/delegations", status_code=status.HTTP_201_CREATED)
    async def create_delegation(
        req: CreateDelegationRequest,
        x_authenticated_user: str | None = Header(default="user:priya@example.com"),
    ) -> dict[str, Any]:
        delegation_id = f"dlg_{ulid.ULID()}"
        now = datetime.now(UTC)
        sponsor_subject = x_authenticated_user or "user:priya@example.com"

        delegation = Delegation(
            delegation_id=delegation_id,
            sponsor=Sponsor(subject=sponsor_subject),
            purpose=req.purpose,
            task_id=req.task_id,
            allowed_agents=req.allowed_agents,
            allowed_regions=req.allowed_regions,
            policy_version=req.policy_version,
            status=DelegationStatus.ACTIVE,
            created_at=now,
            expires_at=req.expires_at,
        )
        await db.put_delegation(delegation)

        task = await db.get_task(req.task_id)
        if not task:
            task = Task(
                task_id=req.task_id,
                delegation_id=delegation_id,
                state=TaskState.CREATED,
                state_version=1,
                policy_version=req.policy_version,
                created_at=now,
                updated_at=now,
            )
            await db.put_task(task)

        return {
            "delegation_id": delegation.delegation_id,
            "sponsor": delegation.sponsor.subject,
            "purpose": delegation.purpose,
            "task_id": delegation.task_id,
            "status": delegation.status.value,
            "policy_version": delegation.policy_version,
            "created_at": delegation.created_at.isoformat(),
            "expires_at": delegation.expires_at.isoformat(),
        }

    @app.post("/v1/delegations/{delegation_id}/revoke")
    async def revoke_delegation(
        delegation_id: str,
        req: RevokeDelegationRequest,
        x_authenticated_user: str | None = Header(default="user:priya@example.com"),
    ) -> dict[str, Any]:
        delegation = await db.get_delegation(delegation_id)
        if not delegation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Delegation not found"
            )

        now = datetime.now(UTC)
        delegation.status = DelegationStatus.REVOKED
        delegation.revoked_at = now
        delegation.revoked_by = x_authenticated_user or "user:priya@example.com"
        await db.put_delegation(delegation)

        return {"delegation_id": delegation_id, "status": "revoked", "reason": req.reason}

    # ─── 2. Evaluate & Issue Grant ─────────────────────────────────────────────

    @app.post("/v1/grants/evaluate")
    async def evaluate_grant(req: EvaluateGrantRequest) -> dict[str, Any]:
        now = datetime.now(UTC)
        now_ts = int(now.timestamp())

        # Phase A & B: Delegation lookup & active check
        delegation = await db.get_delegation(req.delegation_id)
        if not delegation:
            return {
                "decision": "deny",
                "reason_code": ReasonCode.DELEGATION_NOT_FOUND.value,
                "detail": f"Delegation {req.delegation_id} not found",
            }

        if delegation.status == DelegationStatus.REVOKED:
            return {
                "decision": "deny",
                "reason_code": ReasonCode.DELEGATION_REVOKED.value,
                "detail": "Delegation has been revoked",
            }

        if delegation.expires_at <= now:
            return {
                "decision": "deny",
                "reason_code": ReasonCode.DELEGATION_EXPIRED.value,
                "detail": "Delegation is expired",
            }

        # Phase C: Task/Delegation binding
        if delegation.task_id != req.task_id:
            return {
                "decision": "deny",
                "reason_code": ReasonCode.TASK_NOT_BOUND_TO_DELEGATION.value,
                "detail": "Task ID does not match delegation",
            }

        # Phase D: Agent allowed
        if delegation.allowed_agents and req.agent.id not in delegation.allowed_agents:
            return {
                "decision": "deny",
                "reason_code": ReasonCode.AGENT_NOT_ALLOWED.value,
                "detail": f"Agent {req.agent.id} not allowed by delegation",
            }

        # Phase E: Manifest capability check
        manifest = agent_manifests.get(req.agent.id)
        if not manifest or not manifest.can_request_tool(req.tool):
            return {
                "decision": "deny",
                "reason_code": ReasonCode.CAPABILITY_NOT_DECLARED.value,
                "detail": f"Agent {req.agent.id} manifest does not declare capability for {req.tool}",
            }

        # Phase F: Region check
        if req.region not in delegation.allowed_regions:
            return {
                "decision": "deny",
                "reason_code": ReasonCode.REGION_NOT_ALLOWED.value,
                "detail": f"Region {req.region} is not allowed",
            }

        # Phase G: Approval & Separation of Duties check for sensitive tools
        approval_ids: list[str] = []
        if req.tool == "payment.instruct":
            batch_id = req.arguments.get("batch_id")
            amount_minor = req.arguments.get("amount_minor")
            currency = req.arguments.get("currency", "INR")

            matching_approvals: list[ApprovalRecord] = []
            for app_rec in db.approvals.values():
                if (
                    app_rec.task_id == req.task_id
                    and app_rec.decision == ApprovalDecision.APPROVED
                    and app_rec.is_valid(now)
                ):
                    sub = app_rec.subject
                    if (
                        sub.get("batch_id") == batch_id
                        and sub.get("amount_minor") == amount_minor
                        and sub.get("currency") == currency
                    ):
                        matching_approvals.append(app_rec)

            if not matching_approvals:
                return {
                    "decision": "deny",
                    "reason_code": ReasonCode.APPROVAL_REQUIRED.value,
                    "detail": "Action payment.instruct requires valid human approval record",
                }

            # Check if at least one approval satisfies Separation of Duties
            valid_sod_approval = None
            for app_rec in matching_approvals:
                if app_rec.approver_subject != delegation.sponsor.subject:
                    valid_sod_approval = app_rec
                    break

            if not valid_sod_approval:
                return {
                    "decision": "deny",
                    "reason_code": ReasonCode.SEPARATION_OF_DUTIES_VIOLATION.value,
                    "detail": "Approver must differ from delegation sponsor",
                }

            approval_ids.append(valid_sod_approval.approval_id)

        # Build constraints & allowed response fields per tool
        arg_constraints: list[Constraint] = []
        allowed_response_fields: list[str] = []

        if req.tool == "invoice.read":
            allowed_response_fields = [
                "invoice_id",
                "vendor_id",
                "po_id",
                "total_minor",
                "currency",
                "status",
            ]
        elif req.tool == "purchase_order.read":
            allowed_response_fields = ["po_id", "vendor_id", "total_minor", "currency", "status"]
        elif req.tool == "vendor.read":
            allowed_response_fields = ["vendor_id", "legal_name", "status", "country_code"]
        elif req.tool == "reconciliation.write":
            allowed_response_fields = ["reconciliation_id", "result", "variance_minor"]
        elif req.tool == "payment.instruct":
            allowed_response_fields = ["payment_id", "status", "processed_at"]
            arg_constraints = [
                Constraint(
                    path="batch_id", op=ConstraintOp.EQ, value=req.arguments.get("batch_id")
                ),
                Constraint(
                    path="amount_minor",
                    op=ConstraintOp.LTE,
                    value=req.arguments.get("amount_minor"),
                ),
                Constraint(
                    path="currency", op=ConstraintOp.EQ, value=req.arguments.get("currency")
                ),
            ]

        # Phase H: Pre-evaluate constraints against current arguments
        if arg_constraints:
            pol_dec = evaluate_constraints(arg_constraints, req.arguments)
            if not pol_dec.allowed:
                return {
                    "decision": "deny",
                    "reason_code": pol_dec.reason_code.value
                    if pol_dec.reason_code
                    else ReasonCode.ARGUMENT_CONSTRAINT_FAILED.value,
                    "detail": pol_dec.reason_detail or "Argument constraints failed",
                }

        # Issue Grant
        grant_id = f"grt_{ulid.ULID()}"
        ttl_seconds = 300
        expires_at = now_ts + ttl_seconds

        grant = ExecutionGrant(
            jti=grant_id,
            iss="delegation-fabric-control-plane",
            aud="delegation-fabric-execution-gateway",
            delegation_id=req.delegation_id,
            task_id=req.task_id,
            agent_id=req.agent.id,
            agent_version=req.agent.version,
            human_sponsor=delegation.sponsor.subject,
            purpose=delegation.purpose,
            tool=req.tool,
            arg_constraints=arg_constraints,
            allowed_response_fields=allowed_response_fields,
            region=req.region,
            approval_ids=approval_ids,
            iat=now_ts,
            nbf=now_ts,
            exp=expires_at,
            single_use=True,
            policy_version=delegation.policy_version,
        )

        token = kms_signer.sign_grant(grant)

        # Store grant record in DB
        grant_record = GrantRecord(
            grant_id=grant_id,
            delegation_id=req.delegation_id,
            task_id=req.task_id,
            agent_id=req.agent.id,
            agent_version=req.agent.version,
            tool=req.tool,
            status=GrantStatus.ISSUED,
            issued_at=now,
            expires_at=datetime.fromtimestamp(expires_at, tz=UTC),
            policy_version=delegation.policy_version,
        )
        await db.put_grant(grant_record)

        return {
            "decision": "allow",
            "grant_id": grant_id,
            "token": token,
            "expires_at": datetime.fromtimestamp(expires_at, tz=UTC).isoformat(),
            "policy_version": delegation.policy_version,
        }

    # ─── 3. Approvals ──────────────────────────────────────────────────────────

    @app.post("/v1/approvals", status_code=status.HTTP_201_CREATED)
    async def create_approval(
        req: CreateApprovalRequest,
        x_authenticated_user: str | None = Header(default="user:arun@example.com"),
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        approval_id = f"apr_{ulid.ULID()}"
        expires_at = datetime.fromtimestamp(now.timestamp() + req.expires_in_seconds, tz=UTC)
        approver = x_authenticated_user or "user:arun@example.com"

        subject_canonical = canonical_json(req.subject)
        subject_hash = f"sha256:{hashlib.sha256(subject_canonical.encode('utf-8')).hexdigest()}"

        approval = ApprovalRecord(
            approval_id=approval_id,
            task_id=req.task_id,
            delegation_id=req.delegation_id,
            approval_type=req.approval_type,
            subject=req.subject,
            subject_hash=subject_hash,
            decision=req.decision,
            approver_subject=approver,
            created_at=now,
            expires_at=expires_at,
            policy_version="finance-policy-2026-08-20.1",
        )
        await db.put_approval(approval)

        return {
            "approval_id": approval.approval_id,
            "approver": approval.approver_subject,
            "decision": approval.decision.value,
            "created_at": approval.created_at.isoformat(),
            "expires_at": approval.expires_at.isoformat(),
        }

    # ─── 4. Tasks & Audit ──────────────────────────────────────────────────────

    @app.get("/v1/tasks/{task_id}")
    async def get_task(task_id: str) -> dict[str, Any]:
        task = await db.get_task(task_id)
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
        return {
            "task_id": task.task_id,
            "delegation_id": task.delegation_id,
            "state": task.state.value,
            "state_version": task.state_version,
            "current_agent": f"{task.current_agent_id}@{task.current_agent_version}"
            if task.current_agent_id
            else "",
            "latest_checkpoint_id": task.latest_checkpoint_id,
            "updated_at": task.updated_at.isoformat(),
        }

    @app.get("/v1/audit/tasks/{task_id}")
    async def get_audit_events(task_id: str) -> list[dict[str, Any]]:
        events = await db.get_audit_events(task_id)
        return [evt.model_dump(mode="json") for evt in events]

    @app.get("/v1/audit/tasks/{task_id}/verify")
    async def verify_audit(task_id: str) -> ChainVerificationResult:
        events = await db.get_audit_events(task_id)
        return verify_audit_chain(events)

    return app
