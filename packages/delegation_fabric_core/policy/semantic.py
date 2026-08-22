"""Semantic Governance integration (AUTHORIZATION.md § 6, PLAN.md Day 5).

Probabilistic intent/business-constraint checking layered ON TOP of the
deterministic policy engine. It is additional evidence — never the sole
source of transaction authorization:

    if semantic_policy_enforced and semantic_verdict != ALLOW:
        deny(SEMANTIC_POLICY_DENIED)

Modes:
- off:     no evaluation
- dry_run: verdict + rationale recorded as evidence; never denies
- enforce: a BLOCK verdict denies with SEMANTIC_POLICY_DENIED

The managed NL engine is the production implementation; these deterministic
intent heuristics are the portable stand-in with identical interfaces.
"""

from __future__ import annotations

import os
import re
from enum import Enum

from pydantic import BaseModel, Field

_SECRET_TOOL_RE = re.compile(r"secret|credential|api_key|bank_account|password", re.IGNORECASE)


class SemanticMode(str, Enum):
    OFF = "off"
    DRY_RUN = "dry_run"
    ENFORCE = "enforce"


class RuleResult(BaseModel):
    rule: str
    passed: bool
    rationale: str = ""


class SemanticVerdict(BaseModel):
    allowed: bool
    mode: SemanticMode
    results: list[RuleResult] = Field(default_factory=list)
    rationale: str = ""

    @property
    def blocked(self) -> bool:
        return not self.allowed


def get_semantic_mode() -> SemanticMode:
    raw = os.environ.get("DF_SEMANTIC_GOVERNANCE_MODE", "dry_run")
    try:
        return SemanticMode(raw)
    except ValueError:
        # Fail safe to the advisory default rather than crashing every request.
        return SemanticMode.DRY_RUN


def _rule_no_secret_capability(tool: str) -> RuleResult:
    """Business constraint: agents never touch credential/secret surfaces."""
    passed = not _SECRET_TOOL_RE.search(tool)
    return RuleResult(
        rule="no_secret_capability",
        passed=passed,
        rationale="" if passed else f"tool {tool!r} targets a secret/credential surface",
    )


def _rule_positive_amount(arguments: dict[str, object]) -> RuleResult:
    """Intent check: instructed payment amounts must be positive integers."""
    amount = arguments.get("amount_minor")
    if amount is None:
        return RuleResult(rule="positive_amount", passed=True)
    passed = isinstance(amount, int) and not isinstance(amount, bool) and amount > 0
    return RuleResult(
        rule="positive_amount",
        passed=passed,
        rationale="" if passed else f"amount_minor={amount!r} fails positive-integer intent check",
    )


def _rule_no_injection_payload(arguments: dict[str, object]) -> RuleResult:
    """Supplier-controlled document content must not carry injection markers."""
    blob = " ".join(str(v) for v in arguments.values() if isinstance(v, str))
    suspicious = re.search(
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions?"
        r"|disregard\s+(all\s+)?(your\s+)?(instructions|rules)"
        r"|exfiltrat\w*",
        blob,
        re.IGNORECASE,
    )
    return RuleResult(
        rule="no_injection_payload",
        passed=suspicious is None,
        rationale="" if suspicious is None else "argument strings contain injection-style content",
    )


def evaluate_semantic_intent(
    purpose: str, tool: str, arguments: dict[str, object], mode: SemanticMode | None = None
) -> SemanticVerdict:
    resolved_mode = mode or get_semantic_mode()
    if resolved_mode == SemanticMode.OFF:
        return SemanticVerdict(
            allowed=True, mode=resolved_mode, rationale="semantic governance off"
        )

    results = [
        _rule_no_secret_capability(tool),
        _rule_no_injection_payload(arguments),
        _rule_positive_amount(arguments),
    ]
    allowed = all(r.passed for r in results)
    failed = [r.rule for r in results if not r.passed]
    return SemanticVerdict(
        allowed=allowed,
        mode=resolved_mode,
        results=results,
        rationale="all intent checks passed"
        if allowed
        else f"failed intent rules: {', '.join(failed)}",
    )


def should_deny(verdict: SemanticVerdict) -> bool:
    """Enforce-mode blocks deny; dry-run findings are advisory only."""
    return verdict.mode == SemanticMode.ENFORCE and verdict.blocked


__all__ = [
    "RuleResult",
    "SemanticMode",
    "SemanticVerdict",
    "evaluate_semantic_intent",
    "get_semantic_mode",
    "should_deny",
]
