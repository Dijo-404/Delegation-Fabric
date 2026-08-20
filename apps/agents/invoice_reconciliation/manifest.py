"""Agent manifest for invoice-reconciliation agent."""

manifest = {
    "agent_id": "invoice-reconciliation",
    "version": "1.0.0",
    "display_name": "Invoice Reconciliation Agent",
    "owner": "finance-ops@example.com",
    "risk_class": "medium",
    "capabilities": [
        "invoice.read",
        "purchase_order.read",
        "reconciliation.write",
    ],
    "denied_tools": [
        "payment.instruct",
        "vendor_bank_account.read",
    ],
    "allowed_regions": ["asia-south1"],
    "memory": {
        "classes": ["working_state", "episodic"],
        "ttl_days": 30,
        "prohibited_content": ["bank_account", "secret", "execution_grant"],
    },
}
