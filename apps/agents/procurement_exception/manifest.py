"""Agent manifest for procurement-exception agent."""

manifest = {
    "agent_id": "procurement-exception",
    "version": "1.0.0",
    "display_name": "Procurement Exception Agent",
    "owner": "procurement-ops@example.com",
    "risk_class": "high",
    "capabilities": [
        "vendor.read",
        "exception.write",
    ],
    "denied_tools": [
        "payment.instruct",
        "exception.approve_self",
        "vendor_bank_account.read",
    ],
    "allowed_regions": ["asia-south1"],
    "memory": {
        "classes": ["working_state", "episodic"],
        "ttl_days": 30,
        "prohibited_content": ["bank_account", "secret", "execution_grant"],
    },
}
