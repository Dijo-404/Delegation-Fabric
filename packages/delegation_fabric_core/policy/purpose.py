"""Purpose-based authorization policy document (AUTHORIZATION.md § 5).

Deterministic, versioned configuration that decides whether a grant may be
minted: which agents may invoke which tools under which business purpose,
with what response-field projection, approval requirements, separation-of-
duties rules and argument limits.

Immutable after publication; selected by ``delegation.purpose``.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

SPONSOR = "delegation_sponsor"
ORIGINATING_EXCEPTION_ACTOR = "originating_exception_actor"


class ToolPolicy(BaseModel):
    """Authorization rules for one tool under one agent/purpose pair."""

    allowed_fields: list[str] = Field(default_factory=list)
    requires_approval: bool = False
    sod_approver_must_differ_from: list[str] = Field(default_factory=list)
    # Deterministic argument limits evaluated against actual request arguments.
    max_amount_minor: int | None = None
    allowed_currencies: list[str] = Field(default_factory=list)


class PurposeAgentPolicy(BaseModel):
    tools: dict[str, ToolPolicy]


class PurposePolicy(BaseModel):
    agents: dict[str, PurposeAgentPolicy]


class PolicyDocument(BaseModel):
    version: str
    purposes: dict[str, PurposePolicy]

    def purpose(self, name: str) -> PurposePolicy | None:
        return self.purposes.get(name)

    def tool_policy(self, purpose_name: str, agent_id: str, tool: str) -> ToolPolicy | None:
        pp = self.purposes.get(purpose_name)
        if pp is None:
            return None
        agent_policy = pp.agents.get(agent_id)
        if agent_policy is None:
            return None
        return agent_policy.tools.get(tool)


def default_policy_document() -> PolicyDocument:
    """The finance-policy-2026-08-20.1 baseline referenced across the docs."""

    read_invoice_fields = [
        "invoice_id",
        "vendor_id",
        "po_id",
        "total_minor",
        "currency",
        "status",
    ]
    read_po_fields = ["po_id", "vendor_id", "total_minor", "currency", "status"]

    return PolicyDocument(
        version="finance-policy-2026-08-20.1",
        purposes={
            "weekly_vendor_settlement": PurposePolicy(
                agents={
                    "invoice-reconciliation": PurposeAgentPolicy(
                        tools={
                            "invoice.read": ToolPolicy(allowed_fields=read_invoice_fields),
                            "purchase_order.read": ToolPolicy(allowed_fields=read_po_fields),
                        }
                    ),
                    "procurement-exception": PurposeAgentPolicy(
                        tools={
                            "vendor.read": ToolPolicy(
                                allowed_fields=["vendor_id", "legal_name", "status", "country_code"]
                            ),
                        }
                    ),
                    "treasury-approval": PurposeAgentPolicy(
                        tools={
                            "payment.instruct": ToolPolicy(
                                allowed_fields=["payment_id", "status", "processed_at"],
                                requires_approval=True,
                                sod_approver_must_differ_from=[SPONSOR],
                                max_amount_minor=100_000_000,
                                allowed_currencies=["INR"],
                            ),
                            "payment_batch.read": ToolPolicy(
                                allowed_fields=["batch_id", "total_minor", "currency", "status"],
                            ),
                        }
                    ),
                }
            ),
            "invoice_reconciliation": PurposePolicy(
                agents={
                    "invoice-reconciliation": PurposeAgentPolicy(
                        tools={
                            "invoice.read": ToolPolicy(allowed_fields=read_invoice_fields),
                            "purchase_order.read": ToolPolicy(allowed_fields=read_po_fields),
                            "reconciliation.write": ToolPolicy(
                                allowed_fields=["reconciliation_id", "result", "variance_minor"],
                            ),
                        }
                    )
                }
            ),
            "procurement_exception": PurposePolicy(
                agents={
                    "procurement-exception": PurposeAgentPolicy(
                        tools={
                            "vendor.read": ToolPolicy(
                                allowed_fields=["vendor_id", "legal_name", "status", "country_code"]
                            ),
                            "exception.write": ToolPolicy(
                                allowed_fields=["exception_id", "status"],
                            ),
                        }
                    )
                }
            ),
        },
    )
