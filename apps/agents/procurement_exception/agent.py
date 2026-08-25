"""Procurement Exception workflow orchestrator."""

from __future__ import annotations

from typing import Any

from apps.agents.procurement_exception.tools import ProcurementExceptionTools

HIGH_SEVERITY_RISK_SCORE = 80
MEDIUM_SEVERITY_RISK_SCORE = 50


async def run_exception_workflow(
    tools: ProcurementExceptionTools,
    invoice_id: str,
    vendor_id: str,
    reason: str = "price_variance",
) -> dict[str, Any]:
    """Evaluate vendor data and flag procurement exceptions under Delegation Fabric authorization."""
    # 1. Read Vendor
    vendor_data = await tools.read_vendor(vendor_id)
    if "error" in vendor_data:
        return {"status": "failed", "error": vendor_data}

    # 2. Derive severity from vendor risk signal
    risk_score = vendor_data.get("risk_score", 0)
    if risk_score >= HIGH_SEVERITY_RISK_SCORE:
        severity = "high"
    elif risk_score >= MEDIUM_SEVERITY_RISK_SCORE:
        severity = "medium"
    else:
        severity = "low"

    # 3. Write exception
    exception_data = await tools.write_exception(invoice_id, severity, reason)
    if "error" in exception_data:
        return {"status": "failed", "error": exception_data}

    return {
        "status": "completed",
        "invoice_id": invoice_id,
        "vendor_id": vendor_id,
        "severity": severity,
        "exception": exception_data,
    }
