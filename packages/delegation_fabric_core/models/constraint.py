"""Constraint model for deterministic argument authorization."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ConstraintOp(str, Enum):
    """Supported constraint operators."""

    EQ = "eq"
    NEQ = "neq"
    IN = "in"
    NOT_IN = "not_in"
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"
    PREFIX = "prefix"
    SUBSET_OF = "subset_of"
    MATCHES = "matches"  # bounded regex
    EXISTS = "exists"


class Constraint(BaseModel):
    """A single deterministic constraint on a tool argument.

    path: dotted path into the arguments object (e.g. 'vendor.id', 'amount_minor')
    op:   the comparison operator
    value: the reference value; None only valid for 'exists'
    """

    path: str = Field(..., min_length=1, max_length=200)
    op: ConstraintOp
    value: Any | None = None  # JsonValue
