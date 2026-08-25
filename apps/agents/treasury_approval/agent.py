"""Treasury Approval workflow orchestrator (approval-gated)."""

from __future__ import annotations

from typing import Any

from apps.agents.treasury_approval.tools import TreasuryApprovalTools


async def run_payment_approval_workflow(
    tools: TreasuryApprovalTools,
    batch_id: str,
    amount_minor: int,
    currency: str = "INR",
) -> dict[str, Any]:
    """Execute payment instruction only for batches already marked approved."""
    # 1. Read Payment Batch
    batch_data = await tools.read_payment_batch(batch_id)
    if "error" in batch_data:
        return {"status": "failed", "error": batch_data}

    # 2. Approval gate: never instruct against an unapproved batch
    approval_status = batch_data.get("approval_status")
    if approval_status != "approved":
        return {
            "status": "blocked",
            "reason": "batch_not_approved",
            "batch_id": batch_id,
            "approval_status": approval_status,
        }

    # 3. Amount/currency gate: bind the instructed payment to the approved
    # batch record instead of trusting caller-supplied figures. Defense in
    # depth: the Control Plane re-evaluates constraints server-side at
    # /v1/execute, but the agent must never submit amounts that disagree with
    # the approved batch data returned by payment_batch.read.
    batch_amount = batch_data.get("amount_minor")
    batch_currency = batch_data.get("currency")
    amount_ok = isinstance(batch_amount, int) and not isinstance(batch_amount, bool)
    currency_ok = isinstance(batch_currency, str)
    if not amount_ok or not currency_ok:
        return {
            "status": "blocked",
            "reason": "batch_missing_approved_terms",
            "batch_id": batch_id,
            "approval_status": approval_status,
        }
    if batch_amount != amount_minor or batch_currency != currency:
        return {
            "status": "blocked",
            "reason": "payment_terms_mismatch",
            "batch_id": batch_id,
            "approval_status": approval_status,
            "approved_amount_minor": batch_amount,
            "requested_amount_minor": amount_minor,
            "approved_currency": batch_currency,
            "requested_currency": currency,
        }

    # 4. Instruct payment
    instruct_result = await tools.instruct_payment(batch_id, amount_minor, currency)
    if "error" in instruct_result:
        return {"status": "failed", "error": instruct_result}

    return {
        "status": "completed",
        "batch_id": batch_id,
        "amount_minor": amount_minor,
        "currency": currency,
        "payment_instructed": instruct_result,
    }
