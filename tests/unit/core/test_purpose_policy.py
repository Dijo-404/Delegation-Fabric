"""Unit tests for the purpose-policy document (AUTHORIZATION § 5)."""

import pytest
from delegation_fabric_core.policy.purpose import default_policy_document


@pytest.fixture
def policy() -> object:
    return default_policy_document()


def test_version_is_pinned(policy) -> None:
    assert policy.version == "finance-policy-2026-08-20.1"


def test_payment_requires_approval_and_sod(policy) -> None:
    tp = policy.tool_policy("weekly_vendor_settlement", "treasury-approval", "payment.instruct")
    assert tp is not None
    assert tp.requires_approval is True
    assert "delegation_sponsor" in tp.sod_approver_must_differ_from
    assert tp.max_amount_minor is not None and tp.max_amount_minor > 0
    assert tp.allowed_currencies == ["INR"]


def test_invoice_read_projects_fields(policy) -> None:
    tp = policy.tool_policy("invoice_reconciliation", "invoice-reconciliation", "invoice.read")
    assert tp is not None
    assert "bank_account_internal" not in tp.allowed_fields
    assert "total_minor" in tp.allowed_fields


def test_unknown_purpose_returns_none(policy) -> None:
    assert policy.purpose("nonexistent") is None
    assert policy.tool_policy("nonexistent", "any-agent", "any.tool") is None


def test_agent_outside_purpose_returns_none(policy) -> None:
    # treasury-approval has no role under procurement_exception purpose
    assert (
        policy.tool_policy("procurement_exception", "treasury-approval", "payment.instruct") is None
    )


def test_tool_outside_agent_scope_returns_none(policy) -> None:
    # invoice-reconciliation cannot payment.instruct even under settlement purpose
    assert (
        policy.tool_policy("weekly_vendor_settlement", "invoice-reconciliation", "payment.instruct")
        is None
    )
