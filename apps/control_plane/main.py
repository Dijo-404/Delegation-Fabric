"""Control Plane service implementation.

Endpoints per docs/API_CONTRACTS.md:
- POST /v1/delegations
- POST /v1/delegations/{id}/revoke            (appends audit event)
- POST /v1/grants/evaluate                    (policy-driven, denies -> 403 + request_id)
- GET  /v1/grants/{id}
- POST /v1/approvals                          (publishes approval.created)
- GET  /v1/tasks/{id}
- POST /v1/tasks/{id}/release                 (quarantine release, optimistic version)
- GET  /v1/agents                             (registry read facade)
- GET  /v1/audit/tasks/{id}
- GET  /v1/audit/tasks/{id}/verify

Authorization is driven by the deterministic purpose-policy document
(docs/AUTHORIZATION.md § 5) plus agent manifests. Denials are audited;
capability/purpose violations quarantine a RUNNING task.
"""

from __future__ import annotations

import hashlib
import os
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import ulid as ulid_mod
from delegation_fabric_adapters.config import grant_audience, grant_issuer
from delegation_fabric_adapters.firestore.store import MemoryStore
from delegation_fabric_adapters.kms.signer import LocalKMSSigner
from delegation_fabric_core.audit.chain import (
    GENESIS_HASH,
    ChainVerificationResult,
    canonical_json,
    finalize_audit_event,
    verify_audit_chain,
)
from delegation_fabric_core.constraints.engine import evaluate_constraints
from delegation_fabric_core.errors.exceptions import ConcurrentTaskUpdateError
from delegation_fabric_core.models.approval import ApprovalDecision, ApprovalRecord
from delegation_fabric_core.models.audit import AuditActor, AuditActorType, AuditEvent
from delegation_fabric_core.models.checkpoint import TaskCheckpoint
from delegation_fabric_core.models.constraint import Constraint, ConstraintOp
from delegation_fabric_core.models.delegation import Delegation, DelegationStatus, Sponsor
from delegation_fabric_core.models.event import EventEnvelope, EventType
from delegation_fabric_core.models.grant import ExecutionGrant, GrantRecord, GrantStatus
from delegation_fabric_core.models.manifest import AgentManifest, RiskClass
from delegation_fabric_core.models.policy import ReasonCode
from delegation_fabric_core.models.task import Task, TaskEvent, TaskState
from delegation_fabric_core.policy.purpose import PolicyDocument, default_policy_document
from delegation_fabric_core.policy.semantic import evaluate_semantic_intent, should_deny
from delegation_fabric_core.policy.state_machine import transition
from fastapi import FastAPI, Header, HTTPException, Request, status

if TYPE_CHECKING:
    from delegation_fabric_adapters.firestore.firestore_store import FirestoreStore
    from delegation_fabric_adapters.kms.cloud_signer import CloudKMSSigner
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator

QUARANTINE_TRIGGERS = {
    ReasonCode.CAPABILITY_NOT_DECLARED,
    ReasonCode.OUTSIDE_BUSINESS_PURPOSE,
}


def _subject_digest(subject: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON encoding, matching ApprovalRecord.subject_hash."""
    return f"sha256:{hashlib.sha256(canonical_json(subject).encode('utf-8')).hexdigest()}"


def _sponsor_view(sponsor: Sponsor) -> dict[str, str]:
    """Non-identifying sponsor projection for unauthenticated read facades."""
    digest = hashlib.sha256(sponsor.subject.encode("utf-8")).hexdigest()
    return {"subject_hash": f"sha256:{digest}"}


def _approval_view(approval: ApprovalRecord) -> dict[str, Any]:
    """Approval projection with the raw subject payload redacted to its hash."""
    return {
        "approval_id": approval.approval_id,
        "task_id": approval.task_id,
        "delegation_id": approval.delegation_id,
        "approval_type": approval.approval_type,
        "subject_hash": approval.subject_hash,
        "decision": approval.decision.value,
        "approver_subject": approval.approver_subject,
        "created_at": approval.created_at.isoformat(),
        "expires_at": approval.expires_at.isoformat(),
        "used_by_grant_id": approval.used_by_grant_id,
        "policy_version": approval.policy_version,
    }


def _checkpoint_view(checkpoint: TaskCheckpoint) -> dict[str, Any]:
    """Checkpoint projection with the raw pending subject redacted to its hash."""
    view = checkpoint.model_dump(mode="json", exclude={"pending_subject"})
    if checkpoint.pending_subject:
        view["pending_subject_hash"] = _subject_digest(checkpoint.pending_subject)
    return view


class CreateDelegationRequest(BaseModel):
    model_config = {"extra": "forbid"}

    purpose: str
    task_id: str
    allowed_agents: list[str] = Field(default_factory=list)
    allowed_regions: list[str] = Field(default_factory=lambda: ["asia-south1"])
    expires_at: datetime
    policy_version: str = "finance-policy-2026-08-20.1"

    @field_validator("expires_at")
    @classmethod
    def _validate_expiry(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware (UTC)")
        now = datetime.now(UTC)
        if v <= now:
            raise ValueError("expires_at must be in the future")
        if (v - now).total_seconds() > 90 * 24 * 3600:
            raise ValueError("delegation lifetime exceeds policy maximum (90 days)")
        return v


class RevokeDelegationRequest(BaseModel):
    model_config = {"extra": "forbid"}

    reason: str = "workflow_cancelled"


class EvaluateGrantAgent(BaseModel):
    id: str
    version: str = "1.0.0"


class EvaluateGrantRequest(BaseModel):
    model_config = {"extra": "forbid"}

    task_id: str
    delegation_id: str
    agent: EvaluateGrantAgent
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    region: str = "asia-south1"


class CreateApprovalRequest(BaseModel):
    model_config = {"extra": "forbid"}

    task_id: str
    delegation_id: str
    approval_type: str
    subject: dict[str, Any]
    decision: ApprovalDecision = ApprovalDecision.APPROVED
    expires_in_seconds: int = 14400


class ReleaseTaskRequest(BaseModel):
    model_config = {"extra": "forbid"}

    expected_state: str = "quarantined"
    expected_state_version: int | None = None  # preferred optimistic precondition
    reason: str = "document manually reviewed"


def _default_manifests() -> dict[str, AgentManifest]:
    return {
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


def create_app(
    store: MemoryStore | FirestoreStore | None = None,
    signer: LocalKMSSigner | CloudKMSSigner | None = None,
    manifests: dict[str, AgentManifest] | None = None,
    policy_doc: PolicyDocument | None = None,
    publisher: Any = None,
    armor: Any = None,
    audit_exporter: Any = None,
) -> FastAPI:
    from delegation_fabric_adapters.observability import METRICS, configure_logging, log_event
    from delegation_fabric_adapters.pubsub import LoggingEventPublisher

    configure_logging()

    app = FastAPI(title="Delegation Fabric Control Plane", version="0.2.0")

    @app.middleware("http")
    async def request_id_header(request: Request, call_next: Any) -> Any:
        request.state.request_id = f"req_{ulid_mod.ULID()}"
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    from delegation_fabric_adapters.armor import create_armor_from_env
    from delegation_fabric_adapters.gcs_exporter import create_audit_exporter_from_env

    db = store or MemoryStore()
    kms_signer = signer or LocalKMSSigner()
    armor_port: Any = armor or create_armor_from_env()
    exporter: Any = audit_exporter or create_audit_exporter_from_env()
    agent_manifests: dict[str, AgentManifest] = manifests or _default_manifests()
    policy: PolicyDocument = policy_doc or default_policy_document()
    events = publisher or LoggingEventPublisher()

    # ─── Internal helpers ──────────────────────────────────────────────────────

    async def _append_audit(evt: AuditEvent) -> AuditEvent:
        chain = await db.get_audit_events(evt.task_id, limit=None)
        prev_hash = chain[-1].event_hash if chain else GENESIS_HASH
        finalized = finalize_audit_event(evt, prev_hash)
        await db.append_audit_event(finalized)
        return finalized

    async def _deny(
        req: EvaluateGrantRequest,
        reason_code: ReasonCode,
        detail: str,
        request_id: str,
        quarantine_task: bool = False,
        latency_ms: float | None = None,
    ) -> JSONResponse:
        now = datetime.now(UTC)
        await _append_audit(
            AuditEvent(
                audit_event_id=f"aud_{ulid_mod.ULID()}",
                task_id=req.task_id,
                delegation_id=req.delegation_id,
                actor=AuditActor(
                    type=AuditActorType.AGENT, id=req.agent.id, version=req.agent.version
                ),
                event_type="policy.denied",
                tool=req.tool,
                decision="deny",
                reason_code=reason_code.value,
                policy_version=policy.version,
                occurred_at=now,
                prev_hash=GENESIS_HASH,  # replaced by _append_audit
            )
        )

        if quarantine_task:
            try:
                current = await db.get_task(req.task_id)
            except Exception:
                current = None
            if current and current.state == TaskState.RUNNING:
                expected_version = current.state_version

                def _quarantine(t: Task) -> None:
                    t.state = transition(t.state, TaskEvent.SECURITY_EVENT)
                    t.state_version += 1
                    t.updated_at = now

                try:
                    quarantined = await db.mutate_task_atomic(
                        req.task_id, _quarantine, expected_version=expected_version
                    )
                except ConcurrentTaskUpdateError:
                    quarantined = None  # racing writer won; skip duplicate quarantine
                if quarantined is not None:
                    METRICS.inc(
                        "task_state_transition_total",
                        **{"from": current.state.value, "to": quarantined.state.value},
                    )
                    METRICS.inc("quarantine_total", reason=reason_code.value)
                    await _append_audit(
                        AuditEvent(
                            audit_event_id=f"aud_{ulid_mod.ULID()}",
                            task_id=quarantined.task_id,
                            delegation_id=req.delegation_id,
                            actor=AuditActor(type=AuditActorType.SYSTEM, id="control-plane"),
                            event_type="task.quarantined",
                            decision="quarantine",
                            reason_code=reason_code.value,
                            policy_version=policy.version,
                            resource_refs=[f"tool:{req.tool}"],
                            occurred_at=now,
                            prev_hash=GENESIS_HASH,
                        )
                    )

        METRICS.inc("grant_denied_total", reason=reason_code.value)
        deny_fields: dict[str, Any] = {
            "task_id": req.task_id,
            "delegation_id": req.delegation_id,
            "agent_id": req.agent.id,
            "agent_version": req.agent.version,
            "tool": req.tool,
            "decision": "deny",
            "reason_code": reason_code.value,
        }
        if latency_ms is not None:
            deny_fields["latency_ms"] = round(latency_ms, 2)
        log_event("grant denied", **deny_fields)

        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "decision": "deny",
                "reason_code": reason_code.value,
                "detail": detail,
                "request_id": request_id,
            },
        )

    # Bound once so evaluate handlers can time the decision path only:
    # elapsed_ms is sampled before _deny_base runs, so the reported latency
    # excludes the denial audit append and quarantine writes.
    _deny_base = _deny

    # ─── 1. Delegations ────────────────────────────────────────────────────────

    @app.post("/v1/delegations", status_code=status.HTTP_201_CREATED)
    async def create_delegation(
        req: CreateDelegationRequest,
        x_authenticated_user: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if policy.purpose(req.purpose) is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "code": ReasonCode.OUTSIDE_BUSINESS_PURPOSE.value,
                    "message": f"Purpose {req.purpose!r} is not recognized by the active policy",
                },
            )

        delegation_id = f"dlg_{ulid_mod.ULID()}"
        now = datetime.now(UTC)
        sponsor_subject = x_authenticated_user or "user:priya@example.com"

        delegation = Delegation(
            delegation_id=delegation_id,
            sponsor=Sponsor(subject=sponsor_subject),
            purpose=req.purpose,
            task_id=req.task_id,
            allowed_agents=req.allowed_agents,
            allowed_regions=req.allowed_regions,
            policy_version=policy.version,
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
                policy_version=policy.version,
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
        x_authenticated_user: str | None = Header(default=None),
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

        await _append_audit(
            AuditEvent(
                audit_event_id=f"aud_{ulid_mod.ULID()}",
                task_id=delegation.task_id,
                delegation_id=delegation_id,
                actor=AuditActor(type=AuditActorType.HUMAN, id=delegation.revoked_by or "unknown"),
                event_type="delegation.revoked",
                decision="deny",
                reason_code=ReasonCode.DELEGATION_REVOKED.value,
                policy_version=delegation.policy_version,
                metadata={"revoke_reason": req.reason},
                occurred_at=now,
                prev_hash=GENESIS_HASH,
            )
        )

        return {"delegation_id": delegation_id, "status": "revoked", "reason": req.reason}

    # ─── 2. Evaluate & Issue Grant ─────────────────────────────────────────────

    @app.post("/v1/grants/evaluate", response_model=None)
    async def evaluate_grant(req: EvaluateGrantRequest) -> JSONResponse | dict[str, Any]:
        _t0 = time.perf_counter()
        request_id = f"req_{ulid_mod.ULID()}"
        now = datetime.now(UTC)
        now_ts = int(now.timestamp())

        async def _deny(
            req: EvaluateGrantRequest,
            reason_code: ReasonCode,
            detail: str,
            request_id: str,
            quarantine_task: bool = False,
        ) -> JSONResponse:
            elapsed_ms = (time.perf_counter() - _t0) * 1000.0
            return await _deny_base(
                req, reason_code, detail, request_id, quarantine_task, elapsed_ms
            )

        # Phase A-C: Delegation lookup, status, expiry, task binding
        delegation = await db.get_delegation(req.delegation_id)
        if not delegation:
            return await _deny(
                req,
                ReasonCode.DELEGATION_NOT_FOUND,
                f"Delegation {req.delegation_id} not found",
                request_id,
            )
        if delegation.status == DelegationStatus.REVOKED:
            return await _deny(
                req, ReasonCode.DELEGATION_REVOKED, "Delegation has been revoked", request_id
            )
        if delegation.expires_at <= now:
            return await _deny(
                req, ReasonCode.DELEGATION_EXPIRED, "Delegation is expired", request_id
            )
        if delegation.task_id != req.task_id:
            return await _deny(
                req,
                ReasonCode.TASK_NOT_BOUND_TO_DELEGATION,
                "Task ID does not match delegation",
                request_id,
            )

        # Phase A3: Task liveness at issuance — fail closed at the source.
        # Mirrors the gateway's Step 8b so a quarantined or terminal task can
        # neither execute nor mint fresh credentials (defense-in-depth).
        task = await db.get_task(req.task_id)
        if task is None or task.state.is_terminal() or task.state == TaskState.QUARANTINED:
            return await _deny(
                req,
                ReasonCode.TASK_NOT_BOUND_TO_DELEGATION
                if task is None
                else ReasonCode.TASK_NOT_LIVE,
                f"Task {req.task_id} is not in a live state"
                + (f" (state={task.state.value})" if task else ""),
                request_id,
            )

        # Phase D: Agent allowed by delegation scope
        if delegation.allowed_agents and req.agent.id not in delegation.allowed_agents:
            return await _deny(
                req,
                ReasonCode.AGENT_NOT_ALLOWED,
                f"Agent {req.agent.id} not allowed by delegation",
                request_id,
            )

        # Phase E: Manifest capability check (hard capability boundary)
        manifest = agent_manifests.get(req.agent.id)
        if not manifest or not manifest.can_request_tool(req.tool):
            return await _deny(
                req,
                ReasonCode.CAPABILITY_NOT_DECLARED,
                f"Agent {req.agent.id} manifest does not declare capability for {req.tool}",
                request_id,
                quarantine_task=True,
            )

        # Phase E2: Manifest-pinned agent version
        if req.agent.version != manifest.version:
            return await _deny(
                req,
                ReasonCode.AGENT_VERSION_NOT_ALLOWED,
                f"Agent version {req.agent.version} not approved; manifest pins {manifest.version}",
                request_id,
            )

        # Phase F: Region check
        if req.region not in delegation.allowed_regions:
            return await _deny(
                req,
                ReasonCode.REGION_NOT_ALLOWED,
                f"Region {req.region} is not allowed",
                request_id,
            )

        # Phase F2: Purpose policy — deterministic business-purpose scoping
        purpose_policy = policy.purpose(delegation.purpose)
        if purpose_policy is None:
            return await _deny(
                req,
                ReasonCode.OUTSIDE_BUSINESS_PURPOSE,
                f"Purpose {delegation.purpose!r} not recognized by policy {policy.version}",
                request_id,
                quarantine_task=True,
            )
        agent_purpose = purpose_policy.agents.get(req.agent.id)
        if agent_purpose is None:
            return await _deny(
                req,
                ReasonCode.OUTSIDE_BUSINESS_PURPOSE,
                f"Agent {req.agent.id} is outside business purpose {delegation.purpose!r}",
                request_id,
                quarantine_task=True,
            )
        tool_policy = agent_purpose.tools.get(req.tool)
        if tool_policy is None:
            return await _deny(
                req,
                ReasonCode.OUTSIDE_BUSINESS_PURPOSE,
                f"Tool {req.tool!r} is not authorized under purpose {delegation.purpose!r}",
                request_id,
                quarantine_task=True,
            )

        # Phase G: Approval & Separation of Duties (policy-driven)
        approval_ids: list[str] = []
        if tool_policy.requires_approval:
            task_approvals = await db.list_approvals(req.task_id)
            candidates = []
            for apr in task_approvals:
                if (
                    apr.delegation_id != req.delegation_id
                    or apr.approval_type != "payment_batch"
                    or apr.decision != ApprovalDecision.APPROVED
                    or not apr.is_valid(now)
                ):
                    continue
                if apr.used_by_grant_id is not None:
                    continue  # single-use: already bound to an issued grant
                # Fail-closed binding: EVERY approval subject key must be present
                # in the request arguments and match exactly. An empty overlap
                # never authorizes.
                if not all(
                    k in req.arguments and req.arguments[k] == v for k, v in apr.subject.items()
                ):
                    continue
                candidates.append(apr)
            if not candidates:
                return await _deny(
                    req,
                    ReasonCode.APPROVAL_REQUIRED,
                    "A valid human approval record is required for this action",
                    request_id,
                )

            valid_sod = None
            for apr in candidates:
                sod_ok = True
                for rule in tool_policy.sod_approver_must_differ_from:
                    if rule == "delegation_sponsor":
                        if apr.approver_subject == delegation.sponsor.subject:
                            sod_ok = False
                    elif rule == "originating_exception_actor":
                        # Not tracked in this build; treated as satisfied only when
                        # no such actor context exists on the delegation.
                        pass
                    else:
                        sod_ok = False  # unknown rule: fail closed
                        break
                if sod_ok:
                    valid_sod = apr
                    break
            if not valid_sod:
                return await _deny(
                    req,
                    ReasonCode.SEPARATION_OF_DUTIES_VIOLATION,
                    "Approver must differ from the parties bound by separation-of-duties rules",
                    request_id,
                )
            approval_ids.append(valid_sod.approval_id)

        # Build constraints: argument pinning + real policy caps.
        arg_constraints: list[Constraint] = [
            Constraint(path=k, op=ConstraintOp.EQ, value=v)
            for k, v in sorted(req.arguments.items())
            if isinstance(v, str | int | float | bool)
        ]
        if tool_policy.max_amount_minor is not None:
            arg_constraints.extend(
                [
                    Constraint(
                        path="amount_minor", op=ConstraintOp.LTE, value=tool_policy.max_amount_minor
                    ),
                    # Deterministic positivity — do not rely on advisory semantic checks.
                    Constraint(path="amount_minor", op=ConstraintOp.GT, value=0),
                ]
            )
        if tool_policy.allowed_currencies:
            arg_constraints.append(
                Constraint(
                    path="currency", op=ConstraintOp.IN, value=tool_policy.allowed_currencies
                )
            )

        # Phase H: Pre-evaluate constraints against actual arguments
        pol_dec = evaluate_constraints(arg_constraints, req.arguments)
        if not pol_dec.allowed:
            return await _deny(
                req,
                pol_dec.reason_code or ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                pol_dec.reason_detail or "Argument constraints failed",
                request_id,
            )

        # Phase I: Content screening + Semantic Governance (evidence, not sole decision)
        def _collect_strings(node: Any) -> list[str]:
            if isinstance(node, str):
                return [node]
            if isinstance(node, dict):
                return [s2 for v in node.values() for s2 in _collect_strings(v)]
            if isinstance(node, list):
                return [s2 for v in node for s2 in _collect_strings(v)]
            return []

        arg_text = " ".join(_collect_strings(req.arguments))
        screen_result = await armor_port.screen(arg_text) if arg_text else None
        semantic_verdict = evaluate_semantic_intent(delegation.purpose, req.tool, req.arguments)

        if should_deny(semantic_verdict):
            return await _deny(
                req,
                ReasonCode.SEMANTIC_POLICY_DENIED,
                f"Semantic governance enforcement: {semantic_verdict.rationale}",
                request_id,
                quarantine_task=True,
            )

        # Issue Grant
        grant_id = f"grt_{ulid_mod.ULID()}"
        ttl_seconds = int(os.environ.get("DF_GRANT_TTL_SECONDS", "300"))
        expires_at = now_ts + ttl_seconds

        grant = ExecutionGrant(
            jti=grant_id,
            iss=grant_issuer(),
            aud=grant_audience(),
            delegation_id=req.delegation_id,
            task_id=req.task_id,
            agent_id=req.agent.id,
            agent_version=req.agent.version,
            human_sponsor=delegation.sponsor.subject,
            purpose=delegation.purpose,
            tool=req.tool,
            arg_constraints=arg_constraints,
            allowed_response_fields=tool_policy.allowed_fields,
            region=req.region,
            approval_ids=approval_ids,
            iat=now_ts,
            nbf=now_ts,
            exp=expires_at,
            single_use=True,
            policy_version=policy.version,
        )
        token = kms_signer.sign_grant(grant)
        issue_latency_ms = (time.perf_counter() - _t0) * 1000.0

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
            policy_version=policy.version,
        )
        await db.put_grant(grant_record)

        # Bind the consumed approval to this grant (single-use approvals).
        if approval_ids and valid_sod is not None:
            valid_sod.used_by_grant_id = grant_id
            await db.put_approval(valid_sod)

        # Post-durable emission: both metrics fire only after the grant and
        # approval binding are persisted, so histogram count stays consistent
        # with grant_issued_total.
        METRICS.inc("grant_issued_total")
        METRICS.observe("grant_issue_latency_ms", issue_latency_ms)
        log_event(
            "grant issued",
            task_id=req.task_id,
            delegation_id=req.delegation_id,
            grant_id=grant_id,
            agent_id=req.agent.id,
            agent_version=req.agent.version,
            tool=req.tool,
            decision="allow",
            latency_ms=round(issue_latency_ms, 2),
        )

        # Audit the issuance itself with screening/semantic evidence attached
        evidence_meta: dict[str, Any] = {
            "semantic_mode": semantic_verdict.mode.value,
            "semantic_rationale": semantic_verdict.rationale,
        }
        if screen_result is not None:
            evidence_meta["content_screening"] = {
                "verdict": screen_result.verdict,
                "screener": screen_result.screener,
                "findings": [f.model_dump() for f in screen_result.findings],
            }
        try:
            await _append_audit(
                AuditEvent(
                    audit_event_id=f"aud_{ulid_mod.ULID()}",
                    task_id=req.task_id,
                    delegation_id=req.delegation_id,
                    grant_id=grant_id,
                    actor=AuditActor(
                        type=AuditActorType.AGENT, id=req.agent.id, version=req.agent.version
                    ),
                    event_type="grant.issued",
                    tool=req.tool,
                    decision="allow",
                    policy_version=policy.version,
                    approval_ids=approval_ids,
                    metadata=evidence_meta,
                    occurred_at=now,
                    prev_hash=GENESIS_HASH,
                )
            )
        except Exception:
            # Never hand out a live credential that has no audit chain entry.
            grant_record.status = GrantStatus.EXPIRED
            await db.put_grant(grant_record)
            METRICS.inc("grant_denied_total", reason="AUDIT_APPEND_FAILED")
            raise

        return {
            "decision": "allow",
            "grant_id": grant_id,
            "token": token,
            "expires_at": datetime.fromtimestamp(expires_at, tz=UTC).isoformat(),
            "policy_version": policy.version,
            "request_id": request_id,
        }

    @app.get("/v1/grants/{grant_id}")
    async def get_grant(grant_id: str) -> dict[str, Any]:
        grant = await db.get_grant(grant_id)
        if not grant:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grant not found")
        return {
            "grant_id": grant.grant_id,
            "delegation_id": grant.delegation_id,
            "task_id": grant.task_id,
            "agent": f"{grant.agent_id}@{grant.agent_version}",
            "tool": grant.tool,
            "status": grant.status.value,
            "issued_at": grant.issued_at.isoformat(),
            "consumed_at": grant.consumed_at.isoformat() if grant.consumed_at else None,
            "expires_at": grant.expires_at.isoformat(),
            "policy_version": grant.policy_version,
        }

    # ─── 3. Approvals ──────────────────────────────────────────────────────────

    @app.post("/v1/approvals", status_code=status.HTTP_201_CREATED)
    async def create_approval(
        req: CreateApprovalRequest,
        x_authenticated_user: str | None = Header(default=None),
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        approval_id = f"apr_{ulid_mod.ULID()}"
        expires_at = datetime.fromtimestamp(now.timestamp() + req.expires_in_seconds, tz=UTC)
        approver = x_authenticated_user or "user:arun@example.com"

        subject_hash = _subject_digest(req.subject)

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
            policy_version=policy.version,
        )
        await db.put_approval(approval)

        await events.publish(
            EventEnvelope(
                event_id=f"evt_{ulid_mod.ULID()}",
                event_type=EventType.APPROVAL_CREATED,
                task_id=req.task_id,
                source="control-plane",
                occurred_at=now,
                data={"approval_id": approval_id, "approver": approver},
            )
        )

        return {
            "approval_id": approval.approval_id,
            "approver": approval.approver_subject,
            "decision": approval.decision.value,
            "created_at": approval.created_at.isoformat(),
            "expires_at": approval.expires_at.isoformat(),
        }

    # ─── 4. Tasks ──────────────────────────────────────────────────────────────

    @app.get("/v1/tasks/{task_id}")
    async def get_task(task_id: str) -> dict[str, Any]:
        task = await db.get_task(task_id)
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
        return {
            "task_id": task.task_id,
            "delegation_id": task.delegation_id,
            "state": task.state.value,
            "session_id": task.session_id or None,
            "agent": f"{task.current_agent_id}@{task.current_agent_version}"
            if task.current_agent_id
            else None,
            "version": task.state_version,
            "policy_version": task.policy_version or None,
            "latest_checkpoint_id": task.latest_checkpoint_id or None,
            "created_at": task.created_at.isoformat(),
            "updated_at": task.updated_at.isoformat(),
        }

    @app.post("/v1/tasks/{task_id}/release")
    async def release_task(
        task_id: str,
        req: ReleaseTaskRequest,
        x_authenticated_user: str | None = Header(default=None),
    ) -> dict[str, Any]:
        task = await db.get_task(task_id)
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
        # Optimistic concurrency: server-owned state_version is the CAS condition.
        if (
            req.expected_state_version is not None
            and task.state_version != req.expected_state_version
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "STATE_VERSION_CONFLICT",
                    "message": f"Expected version {req.expected_state_version}, actual {task.state_version}",
                },
            )
        if task.state.value != req.expected_state:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "STATE_VERSION_CONFLICT",
                    "message": f"Expected state {req.expected_state!r}, actual {task.state.value!r}",
                },
            )
        try:
            next_state = transition(task.state, TaskEvent.HUMAN_RELEASED)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "INVALID_TRANSITION", "message": str(e)},
            ) from e

        now = datetime.now(UTC)
        expected_version = task.state_version
        previous_state = task.state
        session_ref = [task.session_id]

        def _release(t: Task) -> None:
            t.state = next_state
            t.state_version += 1
            t.session_id = t.session_id or f"session_{ulid_mod.ULID()}"
            t.updated_at = now
            session_ref[0] = t.session_id

        try:
            task = await db.mutate_task_atomic(task_id, _release, expected_version=expected_version)
        except ConcurrentTaskUpdateError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "STATE_VERSION_CONFLICT", "message": str(e)},
            ) from e

        METRICS.inc(
            "task_state_transition_total",
            **{"from": previous_state.value, "to": task.state.value},
        )

        await _append_audit(
            AuditEvent(
                audit_event_id=f"aud_{ulid_mod.ULID()}",
                task_id=task_id,
                delegation_id=task.delegation_id,
                actor=AuditActor(type=AuditActorType.HUMAN, id=x_authenticated_user or "unknown"),
                event_type="task.released",
                decision="allow",
                reason_code=None,
                policy_version=policy.version,
                metadata={"reason": req.reason},
                occurred_at=now,
                prev_hash=GENESIS_HASH,
            )
        )

        return {
            "task_id": task_id,
            "state": task.state.value,
            "version": task.state_version,
            "released_by": x_authenticated_user,
        }

    # ─── 5. Registry read facade ───────────────────────────────────────────────

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        return PlainTextResponse(
            METRICS.prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    from apps.control_plane.console import register_console

    register_console(app)

    def _manifest_view(m: AgentManifest) -> dict[str, Any]:
        return {
            "agent_id": m.agent_id,
            "version": m.version,
            "owner": m.owner or None,
            "risk_class": m.risk_class.value,
            "capabilities": m.capabilities,
            "denied_tools": m.denied_tools,
            "allowed_regions": m.allowed_regions,
            "deployment_revision": m.deployment_revision or None,
        }

    @app.get("/v1/agents")
    async def list_agents() -> list[dict[str, Any]]:
        return [_manifest_view(m) for m in agent_manifests.values()]

    @app.get("/v1/agents/{agent_id}/versions/{version}")
    async def get_agent(agent_id: str, version: str) -> dict[str, Any]:
        m = agent_manifests.get(agent_id)
        if not m or m.version != version:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return _manifest_view(m)

    # ─── 6. Delegation & approval read facades (console) ──────────────────────

    @app.get("/v1/delegations")
    async def list_delegations() -> list[dict[str, Any]]:
        delegations = await db.list_delegations()
        delegations.sort(key=lambda d: d.created_at, reverse=True)
        return [
            {
                "delegation_id": d.delegation_id,
                "sponsor": _sponsor_view(d.sponsor),
                "purpose": d.purpose,
                "task_id": d.task_id,
                "status": d.status.value,
                "policy_version": d.policy_version,
                "created_at": d.created_at.isoformat(),
                "expires_at": d.expires_at.isoformat(),
            }
            for d in delegations
        ]

    @app.get("/v1/delegations/{delegation_id}")
    async def get_delegation_detail(delegation_id: str) -> dict[str, Any]:
        d = await db.get_delegation(delegation_id)
        if not d:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Delegation not found"
            )
        return {
            "delegation_id": d.delegation_id,
            "sponsor": _sponsor_view(d.sponsor),
            "purpose": d.purpose,
            "task_id": d.task_id,
            "allowed_agents": d.allowed_agents,
            "allowed_regions": d.allowed_regions,
            "status": d.status.value,
            "policy_version": d.policy_version,
            "created_at": d.created_at.isoformat(),
            "expires_at": d.expires_at.isoformat(),
            "revoked_at": d.revoked_at.isoformat() if d.revoked_at else None,
            "revoked_by": d.revoked_by,
        }

    @app.get("/v1/approvals")
    async def list_all_approvals() -> list[dict[str, Any]]:
        approvals = await db.list_all_approvals()
        approvals.sort(key=lambda a: a.created_at, reverse=True)
        return [_approval_view(a) for a in approvals]

    # ─── 7. Task depth (console Task Inspector) ───────────────────────────────

    @app.get("/v1/tasks/{task_id}/depth")
    async def get_task_depth(task_id: str) -> dict[str, Any]:
        task = await db.get_task(task_id)
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
        checkpoints = await db.list_checkpoints(task_id)
        grants = await db.list_grants(task_id)
        approvals = await db.list_approvals(task_id)
        receipts = await db.list_event_receipts(task_id)
        return {
            "checkpoints": [_checkpoint_view(c) for c in checkpoints],
            "grants": [g.model_dump(mode="json") for g in grants],
            "approvals": [_approval_view(a) for a in approvals],
            "event_receipts": receipts,
        }

    # ─── 8. Audit ──────────────────────────────────────────────────────────────

    @app.get("/v1/audit/tasks/{task_id}")
    async def get_audit_events(task_id: str) -> list[dict[str, Any]]:
        events_list = await db.get_audit_events(task_id)
        return [evt.model_dump(mode="json") for evt in events_list]

    @app.post("/v1/audit/tasks/{task_id}/export")
    async def export_audit(task_id: str) -> dict[str, Any]:
        events_list = await db.get_audit_events(task_id, limit=None)
        if not events_list:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No audit events")
        uri = await exporter.export_chain(task_id, events_list)
        return {"task_id": task_id, "uri": uri, "event_count": len(events_list)}

    @app.get("/v1/audit/tasks/{task_id}/verify")
    async def verify_audit(task_id: str) -> dict[str, Any]:
        events_list = await db.get_audit_events(task_id, limit=None)
        result: ChainVerificationResult = verify_audit_chain(events_list)
        payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
        payload["events"] = payload.pop("event_count", None)
        payload["task_id"] = task_id
        return payload

    return app


def create_app_from_env() -> FastAPI:
    from delegation_fabric_adapters.armor import create_armor_from_env
    from delegation_fabric_adapters.config import build_publisher, build_signer, build_store
    from delegation_fabric_adapters.gcs_exporter import create_audit_exporter_from_env
    from delegation_fabric_adapters.observability import configure_logging
    from delegation_fabric_adapters.tracing import configure_tracing, instrument_fastapi_app

    configure_logging()
    configure_tracing("control-plane")

    application = create_app(
        store=build_store(),
        signer=build_signer(),
        publisher=build_publisher(),
        armor=create_armor_from_env(),
        audit_exporter=create_audit_exporter_from_env(),
    )
    instrument_fastapi_app(application)
    return application


app = create_app_from_env()
