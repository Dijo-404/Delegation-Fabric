# ERP Seed Data

## Dataset counts

| Category | Count |
|---|---|
| Vendors | 12 |
| Purchase Orders | 48 |
| Total invoices | 240 |
| Clean / matched | 212 |
| Non-critical mismatches | 26 |
| Critical exception | 1 |
| Poisoned invoice | 1 |
| Payment batches | 1 |

All counts must match: seed script output, console counters, test fixtures, and demo screenshots.

## Seed commands

```bash
make seed
```

## Poisoned invoice

Invoice `INV-POISON-001` contains prompt-injection text in its `document_uri`-referenced content.
It is seeded separately by `seed/poisoned_invoice/seed.py` and always has `status = 'quarantined'`
after the attack demo runs.
