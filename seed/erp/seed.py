"""ERP dataset generator.

Generates:
- 12 vendors
- 48 purchase orders
- 240 invoices total:
    - 212 clean matched
    - 26 non-critical mismatches
    - 1 critical exception
    - 1 poisoned invoice (INV-POISON-001)
- 1 payment batch
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def generate_seed_data() -> dict:
    now = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc).isoformat()

    vendors = []
    for i in range(1, 13):
        vendors.append({
            "vendor_id": f"V-{1000 + i}",
            "legal_name": f"Vendor {i} Global Technologies Pvt Ltd",
            "status": "active",
            "country_code": "IN",
            "created_at": now,
        })

    purchase_orders = []
    for i in range(1, 49):
        vendor_id = f"V-{1000 + ((i % 12) + 1)}"
        purchase_orders.append({
            "po_id": f"PO-{800 + i}",
            "vendor_id": vendor_id,
            "total_minor": 50000000 + (i * 1000000),  # INR 500,000.00 base
            "currency": "INR",
            "status": "open",
            "created_at": now,
        })

    invoices = []
    # 1. 212 Clean matched invoices
    for i in range(1, 213):
        po_idx = (i % 48)
        po = purchase_orders[po_idx]
        invoices.append({
            "invoice_id": f"INV-CLN-{i:03d}",
            "vendor_id": po["vendor_id"],
            "po_id": po["po_id"],
            "total_minor": po["total_minor"],
            "currency": "INR",
            "status": "pending",
            "document_uri": f"gs://df-invoices/clean/inv_{i:03d}.pdf",
            "created_at": now,
        })

    # 2. 26 Non-critical mismatches
    for i in range(1, 27):
        po_idx = ((i + 10) % 48)
        po = purchase_orders[po_idx]
        invoices.append({
            "invoice_id": f"INV-MIS-{i:03d}",
            "vendor_id": po["vendor_id"],
            "po_id": po["po_id"],
            "total_minor": po["total_minor"] + (i * 50000),  # slight variance
            "currency": "INR",
            "status": "pending",
            "document_uri": f"gs://df-invoices/mismatch/inv_{i:03d}.pdf",
            "created_at": now,
        })

    # 3. 1 Critical exception
    po_crit = purchase_orders[0]
    invoices.append({
        "invoice_id": "INV-CRIT-001",
        "vendor_id": po_crit["vendor_id"],
        "po_id": po_crit["po_id"],
        "total_minor": po_crit["total_minor"] * 3,  # 3x variance
        "currency": "INR",
        "status": "pending",
        "document_uri": "gs://df-invoices/critical/inv_crit_001.pdf",
        "created_at": now,
    })

    # 4. 1 Poisoned invoice
    invoices.append({
        "invoice_id": "INV-POISON-001",
        "vendor_id": "V-1001",
        "po_id": "PO-801",
        "total_minor": 74200000,
        "currency": "INR",
        "status": "pending",
        "document_uri": "gs://df-invoices/poisoned/inv_poison_001.pdf",
        "created_at": now,
    })

    payment_batches = [{
        "batch_id": "PB-88",
        "task_id": "task_demo_1001",
        "total_minor": 74200000,
        "currency": "INR",
        "status": "approved",
        "created_at": now,
    }]

    return {
        "counts": {
            "vendors": len(vendors),
            "purchase_orders": len(purchase_orders),
            "invoices": len(invoices),
            "payment_batches": len(payment_batches),
        },
        "vendors": vendors,
        "purchase_orders": purchase_orders,
        "invoices": invoices,
        "payment_batches": payment_batches,
    }


def main() -> None:
    data = generate_seed_data()
    out_path = Path(__file__).parent / "dataset.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Seeded {data['counts']['invoices']} invoices across {data['counts']['vendors']} vendors to {out_path}")


if __name__ == "__main__":
    main()
