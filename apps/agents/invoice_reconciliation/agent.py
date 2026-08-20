"""Invoice Reconciliation workflow orchestrator."""

from __future__ import annotations

from typing import Any

from apps.agents.invoice_reconciliation.tools import InvoiceReconciliationTools


async def run_reconciliation_workflow(
    tools: InvoiceReconciliationTools,
    invoice_id: str,
) -> dict[str, Any]:
    """Execute invoice reconciliation business logic under Delegation Fabric authorization."""
    # 1. Read Invoice
    inv_data = await tools.read_invoice(invoice_id)
    if "error" in inv_data:
        return {"status": "failed", "error": inv_data}

    # 2. Read PO
    po_id = inv_data.get("po_id")
    if not po_id:
        return {"status": "mismatch", "reason": "missing_po"}

    po_data = await tools.read_purchase_order(po_id)
    if "error" in po_data:
        return {"status": "failed", "error": po_data}

    # 3. Compare totals
    inv_total = inv_data.get("total_minor", 0)
    po_total = po_data.get("total_minor", 0)
    variance = inv_total - po_total

    result_type = "matched" if variance == 0 else "mismatch"

    # 4. Write reconciliation
    rec_data = await tools.write_reconciliation(invoice_id, result_type, variance)
    return {
        "status": "completed",
        "invoice_id": invoice_id,
        "result": result_type,
        "variance_minor": variance,
        "reconciliation": rec_data,
    }
