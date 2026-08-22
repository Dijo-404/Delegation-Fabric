"""Comprehensive unit tests for the deterministic constraint engine."""

import pytest
from delegation_fabric_core.constraints.engine import evaluate_constraints, get_nested_value
from delegation_fabric_core.models.constraint import Constraint, ConstraintOp
from delegation_fabric_core.models.policy import ReasonCode


def test_get_nested_value_basic(sample_arguments):
    found, val = get_nested_value(sample_arguments, "invoice_id")
    assert found is True
    assert val == "INV-042"

    found, val = get_nested_value(sample_arguments, "vendor.id")
    assert found is True
    assert val == "V-1001"

    found, val = get_nested_value(sample_arguments, "recipients.1.domain")
    assert found is True
    assert val == "vendor.com"

    found, val = get_nested_value(sample_arguments, "vendor.non_existent")
    assert found is False
    assert val is None

    found, val = get_nested_value(sample_arguments, "recipients.99.domain")
    assert found is False
    assert val is None

    # Exceed max nesting depth (max 5)
    deep_path = "a.b.c.d.e.f"
    found, _ = get_nested_value({}, deep_path)
    assert found is False


# ─── Operator Tests ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "op,path,value,expected_allowed,expected_reason",
    [
        # EQ
        (ConstraintOp.EQ, "currency", "INR", True, None),
        (ConstraintOp.EQ, "currency", "USD", False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.EQ, "amount_minor", 74200000, True, None),
        (ConstraintOp.EQ, "amount_minor", "74200000", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        (ConstraintOp.EQ, "is_active", True, True, None),
        (ConstraintOp.EQ, "is_active", 1, False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # NEQ
        (ConstraintOp.NEQ, "currency", "USD", True, None),
        (ConstraintOp.NEQ, "currency", "INR", False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.NEQ, "amount_minor", "74200000", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # IN
        (ConstraintOp.IN, "currency", ["INR", "USD", "EUR"], True, None),
        (ConstraintOp.IN, "currency", ["USD", "EUR"], False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.IN, "currency", "INR", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        (ConstraintOp.IN, "vendor", ["V-1001"], False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # NOT_IN
        (ConstraintOp.NOT_IN, "currency", ["USD", "EUR"], True, None),
        (
            ConstraintOp.NOT_IN,
            "currency",
            ["INR", "USD"],
            False,
            ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
        ),
        (ConstraintOp.NOT_IN, "currency", "USD", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        (ConstraintOp.NOT_IN, "vendor", ["V-1001"], False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # LT
        (ConstraintOp.LT, "amount_minor", 100000000, True, None),
        (ConstraintOp.LT, "amount_minor", 74200000, False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.LT, "amount_minor", "100000000", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        (ConstraintOp.LT, "is_active", 2, False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # LTE
        (ConstraintOp.LTE, "amount_minor", 74200000, True, None),
        (ConstraintOp.LTE, "amount_minor", 74199999, False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.LTE, "amount_minor", "74200000", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # GT
        (ConstraintOp.GT, "amount_minor", 50000000, True, None),
        (ConstraintOp.GT, "amount_minor", 74200000, False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.GT, "amount_minor", "50000000", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # GTE
        (ConstraintOp.GTE, "amount_minor", 74200000, True, None),
        (ConstraintOp.GTE, "amount_minor", 74200001, False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.GTE, "amount_minor", "74200000", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # PREFIX
        (ConstraintOp.PREFIX, "invoice_id", "INV-", True, None),
        (ConstraintOp.PREFIX, "invoice_id", "PO-", False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.PREFIX, "amount_minor", "74", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        (ConstraintOp.PREFIX, "invoice_id", 123, False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # SUBSET_OF
        (ConstraintOp.SUBSET_OF, "tags", ["urgent", "q3_settlement", "finance"], True, None),
        (ConstraintOp.SUBSET_OF, "tags", ["urgent"], False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.SUBSET_OF, "currency", ["INR"], False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # MATCHES
        (ConstraintOp.MATCHES, "invoice_id", r"^INV-\d{3}$", True, None),
        (
            ConstraintOp.MATCHES,
            "invoice_id",
            r"^PO-\d{3}$",
            False,
            ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
        ),
        (
            ConstraintOp.MATCHES,
            "invoice_id",
            "[invalid_regex",
            False,
            ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
        ),
        (ConstraintOp.MATCHES, "amount_minor", r"^\d+$", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        # EXISTS
        (ConstraintOp.EXISTS, "vendor.id", None, True, None),
        (
            ConstraintOp.EXISTS,
            "vendor.missing_field",
            None,
            False,
            ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
        ),
        # ─── Extended matrix (PLAN Day 1 gate: 60+ table-driven rows) ──────────
        # EQ extended
        (ConstraintOp.EQ, "vendor.country", "IN", True, None),
        (ConstraintOp.EQ, "vendor.country", "US", False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.EQ, "missing.path", "x", False, ReasonCode.ARGUMENT_PATH_UNKNOWN),
        (ConstraintOp.EQ, "tags", ["urgent"], False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.EQ, "tags", ["urgent", "q3_settlement"], True, None),
        (ConstraintOp.EQ, "recipients.0.name", "Accounts", True, None),
        (
            ConstraintOp.EQ,
            "recipients.0.name",
            "Billing",
            False,
            ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
        ),
        (ConstraintOp.EQ, "amount_minor", 74_200_000.0, True, None),
        (ConstraintOp.EQ, "is_active", False, False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        # NEQ extended
        (ConstraintOp.NEQ, "vendor.country", "US", True, None),
        (ConstraintOp.NEQ, "invoice_id", "INV-042", False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.NEQ, "missing.path", "x", False, ReasonCode.ARGUMENT_PATH_UNKNOWN),
        # IN / NOT_IN extended
        (ConstraintOp.IN, "vendor.country", ["IN", "SG"], True, None),
        (ConstraintOp.IN, "vendor.id", ["V-1001", "V-1002"], True, None),
        (ConstraintOp.IN, "vendor.id", ["V-9999"], False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.NOT_IN, "vendor.country", ["PK", "CN"], True, None),
        (ConstraintOp.IN, "missing.path", ["x"], False, ReasonCode.ARGUMENT_PATH_UNKNOWN),
        # LT/LTE/GT/GTE boundary semantics
        (ConstraintOp.LT, "amount_minor", 74200001, True, None),
        (ConstraintOp.LTE, "amount_minor", 74200001, True, None),
        (ConstraintOp.GT, "amount_minor", 74199999, True, None),
        (ConstraintOp.GTE, "amount_minor", 74199999, True, None),
        (ConstraintOp.LT, "currency", 5, False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        (ConstraintOp.GTE, "vendor.id", 5, False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        (ConstraintOp.GT, "missing.path", 1, False, ReasonCode.ARGUMENT_PATH_UNKNOWN),
        # PREFIX extended
        (ConstraintOp.PREFIX, "invoice_id", "INV-0", True, None),
        (ConstraintOp.PREFIX, "invoice_id", "", True, None),
        (ConstraintOp.PREFIX, "vendor.id", "V-", True, None),
        (ConstraintOp.PREFIX, "vendor.id", "X-", False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.PREFIX, "missing.path", "x", False, ReasonCode.ARGUMENT_PATH_UNKNOWN),
        # SUBSET_OF extended
        (ConstraintOp.SUBSET_OF, "tags", ["urgent", "q3_settlement", "finance", "x"], True, None),
        (ConstraintOp.SUBSET_OF, "tags", [], False, ReasonCode.ARGUMENT_CONSTRAINT_FAILED),
        (ConstraintOp.SUBSET_OF, "tags", "urgent", False, ReasonCode.ARGUMENT_TYPE_MISMATCH),
        (ConstraintOp.SUBSET_OF, "missing.path", ["a"], False, ReasonCode.ARGUMENT_PATH_UNKNOWN),
        # MATCHES extended
        (ConstraintOp.MATCHES, "vendor.id", r"^V-\d{4}$", True, None),
        (
            ConstraintOp.MATCHES,
            "invoice_id",
            r"^inv-\d+$",
            False,
            ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
        ),
        (ConstraintOp.MATCHES, "currency", r"^IN", True, None),
        (ConstraintOp.MATCHES, "missing.path", r"^x$", False, ReasonCode.ARGUMENT_PATH_UNKNOWN),
        # EXISTS extended
        (ConstraintOp.EXISTS, "amount_minor", None, True, None),
        (ConstraintOp.EXISTS, "recipients.0.domain", None, True, None),
        (
            ConstraintOp.EXISTS,
            "recipients.9.domain",
            None,
            False,
            ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
        ),
        (
            ConstraintOp.EXISTS,
            "totally.missing.deep.path",
            None,
            False,
            ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
        ),
    ],
)
def test_individual_operators(sample_arguments, op, path, value, expected_allowed, expected_reason):
    c = Constraint(path=path, op=op, value=value)
    decision = evaluate_constraints([c], sample_arguments)
    assert decision.allowed is expected_allowed
    if not expected_allowed:
        assert decision.reason_code == expected_reason


def test_unknown_path_fails_closed(sample_arguments):
    c = Constraint(path="vendor.bank_account", op=ConstraintOp.EQ, value="12345")
    decision = evaluate_constraints([c], sample_arguments)
    assert decision.allowed is False
    assert decision.reason_code == ReasonCode.ARGUMENT_PATH_UNKNOWN


def test_multiple_constraints_and_logic(sample_arguments):
    # All pass
    constraints = [
        Constraint(path="invoice_id", op=ConstraintOp.PREFIX, value="INV-"),
        Constraint(path="amount_minor", op=ConstraintOp.LTE, value=100000000),
        Constraint(path="currency", op=ConstraintOp.EQ, value="INR"),
    ]
    decision = evaluate_constraints(constraints, sample_arguments)
    assert decision.allowed is True

    # One fails
    constraints.append(Constraint(path="amount_minor", op=ConstraintOp.LT, value=50000000))
    decision = evaluate_constraints(constraints, sample_arguments)
    assert decision.allowed is False
    assert decision.reason_code == ReasonCode.ARGUMENT_CONSTRAINT_FAILED


def test_invalid_arguments_root():
    c = Constraint(path="foo", op=ConstraintOp.EQ, value="bar")
    decision = evaluate_constraints([c], "not-a-dict")  # type: ignore
    assert decision.allowed is False
    assert decision.reason_code == ReasonCode.ARGUMENT_TYPE_MISMATCH
