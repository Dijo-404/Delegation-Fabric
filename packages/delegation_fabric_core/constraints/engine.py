"""Deterministic constraint evaluation engine.

Rules:
- No Python eval
- Strict type checks; fails closed on type mismatch
- Bounded nesting depth (max 5)
- Precompiled regex with length limits
- Unknown paths deny for authorization predicates
- Malformed predicates deny closed
- Deterministic reason code returned for every failure
"""

from __future__ import annotations

import re
from typing import Any

from delegation_fabric_core.models.constraint import Constraint, ConstraintOp
from delegation_fabric_core.models.policy import JsonObject, PolicyDecision, ReasonCode

MAX_NESTING_DEPTH = 5
MAX_REGEX_LENGTH = 200


def get_nested_value(data: Any, path: str) -> tuple[bool, Any]:
    """Retrieve value at dotted path with bounded depth.

    Supports:
    - Dict key lookup: 'vendor.id'
    - List index lookup: 'recipients.0.domain'

    Returns:
    - (found: bool, value: Any)
    """
    if not path:
        return False, None

    parts = path.split(".")
    if len(parts) > MAX_NESTING_DEPTH:
        return False, None

    current = data
    for part in parts:
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            else:
                return False, None
        elif isinstance(current, list):
            try:
                idx = int(part)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return False, None
            except ValueError:
                return False, None
        else:
            return False, None

    return True, current


def evaluate_constraints(
    constraints: list[Constraint],
    arguments: JsonObject,
) -> PolicyDecision:
    """Evaluate a list of deterministic constraints against arguments.

    All constraints must pass (AND logic).
    Fails closed on first violation.
    """
    if not isinstance(arguments, dict):
        return PolicyDecision.deny(
            ReasonCode.ARGUMENT_TYPE_MISMATCH,
            "Arguments root must be a JSON object",
        )

    for c in constraints:
        # Check path existence
        found, actual = get_nested_value(arguments, c.path)

        if c.op == ConstraintOp.EXISTS:
            if not found or actual is None:
                return PolicyDecision.deny(
                    ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                    f"Required field {c.path!r} does not exist",
                    path=c.path,
                )
            continue

        if not found:
            return PolicyDecision.deny(
                ReasonCode.ARGUMENT_PATH_UNKNOWN,
                f"Path {c.path!r} not found in arguments",
                path=c.path,
            )

        # Evaluate specific operators with strict type checking
        match c.op:
            case ConstraintOp.EQ:
                # Disallow implicit bool/int or float/str coercion
                if type(actual) is not type(c.value) and not (
                    isinstance(actual, (int, float))
                    and isinstance(c.value, (int, float))
                    and not isinstance(actual, bool)
                    and not isinstance(c.value, bool)
                ):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"Type mismatch at {c.path!r}: expected {type(c.value).__name__}, got {type(actual).__name__}",
                        path=c.path,
                    )
                if actual != c.value:
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Value at {c.path!r} ({actual!r}) does not equal {c.value!r}",
                        path=c.path,
                    )

            case ConstraintOp.NEQ:
                if type(actual) is not type(c.value) and not (
                    isinstance(actual, (int, float))
                    and isinstance(c.value, (int, float))
                    and not isinstance(actual, bool)
                    and not isinstance(c.value, bool)
                ):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"Type mismatch at {c.path!r}: expected {type(c.value).__name__}, got {type(actual).__name__}",
                        path=c.path,
                    )
                if actual == c.value:
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Value at {c.path!r} ({actual!r}) must not equal {c.value!r}",
                        path=c.path,
                    )

            case ConstraintOp.IN:
                if not isinstance(c.value, list):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"Constraint 'in' value must be a list for path {c.path!r}",
                        path=c.path,
                    )
                # Ensure actual is scalar and present in list
                if isinstance(actual, (dict, list)):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"Scalar expected at {c.path!r}, got {type(actual).__name__}",
                        path=c.path,
                    )
                if actual not in c.value:
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Value {actual!r} at {c.path!r} not in allowed list",
                        path=c.path,
                    )

            case ConstraintOp.NOT_IN:
                if not isinstance(c.value, list):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"Constraint 'not_in' value must be a list for path {c.path!r}",
                        path=c.path,
                    )
                if isinstance(actual, (dict, list)):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"Scalar expected at {c.path!r}, got {type(actual).__name__}",
                        path=c.path,
                    )
                if actual in c.value:
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Value {actual!r} at {c.path!r} is forbidden (in not_in list)",
                        path=c.path,
                    )

            case ConstraintOp.LT:
                if (
                    not isinstance(actual, (int, float))
                    or isinstance(actual, bool)
                    or not isinstance(c.value, (int, float))
                    or isinstance(c.value, bool)
                ):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"Numeric types required for 'lt' at {c.path!r}",
                        path=c.path,
                    )
                if not (actual < c.value):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Value {actual} at {c.path!r} is not < {c.value}",
                        path=c.path,
                    )

            case ConstraintOp.LTE:
                if (
                    not isinstance(actual, (int, float))
                    or isinstance(actual, bool)
                    or not isinstance(c.value, (int, float))
                    or isinstance(c.value, bool)
                ):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"Numeric types required for 'lte' at {c.path!r}",
                        path=c.path,
                    )
                if not (actual <= c.value):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Value {actual} at {c.path!r} is not <= {c.value}",
                        path=c.path,
                    )

            case ConstraintOp.GT:
                if (
                    not isinstance(actual, (int, float))
                    or isinstance(actual, bool)
                    or not isinstance(c.value, (int, float))
                    or isinstance(c.value, bool)
                ):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"Numeric types required for 'gt' at {c.path!r}",
                        path=c.path,
                    )
                if not (actual > c.value):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Value {actual} at {c.path!r} is not > {c.value}",
                        path=c.path,
                    )

            case ConstraintOp.GTE:
                if (
                    not isinstance(actual, (int, float))
                    or isinstance(actual, bool)
                    or not isinstance(c.value, (int, float))
                    or isinstance(c.value, bool)
                ):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"Numeric types required for 'gte' at {c.path!r}",
                        path=c.path,
                    )
                if not (actual >= c.value):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Value {actual} at {c.path!r} is not >= {c.value}",
                        path=c.path,
                    )

            case ConstraintOp.PREFIX:
                if not isinstance(actual, str) or not isinstance(c.value, str):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"String types required for 'prefix' at {c.path!r}",
                        path=c.path,
                    )
                if not actual.startswith(c.value):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Value {actual!r} at {c.path!r} does not have prefix {c.value!r}",
                        path=c.path,
                    )

            case ConstraintOp.SUBSET_OF:
                if not isinstance(actual, list) or not isinstance(c.value, list):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"List types required for 'subset_of' at {c.path!r}",
                        path=c.path,
                    )
                allowed_set = set(c.value)
                if not all(item in allowed_set for item in actual):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Items in {actual!r} at {c.path!r} are not subset of {c.value!r}",
                        path=c.path,
                    )

            case ConstraintOp.MATCHES:
                if not isinstance(actual, str) or not isinstance(c.value, str):
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_TYPE_MISMATCH,
                        f"String types required for 'matches' at {c.path!r}",
                        path=c.path,
                    )
                if len(c.value) > MAX_REGEX_LENGTH:
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Regex pattern exceeds max length ({MAX_REGEX_LENGTH}) at {c.path!r}",
                        path=c.path,
                    )
                try:
                    compiled = re.compile(c.value)
                    if not compiled.search(actual):
                        return PolicyDecision.deny(
                            ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                            f"Value {actual!r} at {c.path!r} does not match pattern {c.value!r}",
                            path=c.path,
                        )
                except re.error as e:
                    return PolicyDecision.deny(
                        ReasonCode.ARGUMENT_CONSTRAINT_FAILED,
                        f"Malformed regex pattern at {c.path!r}: {e}",
                        path=c.path,
                    )

    return PolicyDecision.allow()
