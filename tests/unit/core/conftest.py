"""Pytest fixtures for core tests."""

import pytest


@pytest.fixture
def sample_arguments() -> dict:
    return {
        "invoice_id": "INV-042",
        "vendor": {
            "id": "V-1001",
            "country": "IN",
        },
        "amount_minor": 74200000,
        "currency": "INR",
        "recipients": [
            {"domain": "example.com", "name": "Accounts"},
            {"domain": "vendor.com", "name": "Billing"},
        ],
        "tags": ["urgent", "q3_settlement"],
        "is_active": True,
    }
