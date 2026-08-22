"""Content screening port and implementations (PLAN.md Day 5 — Model Armor).

Screens user/supplier-controlled content before it reaches model context or
authorization decisions. Findings are EVIDENCE recorded in the audit chain,
never the sole authorization decision (SECURITY.md).

Local heuristic screener is the portable fallback; Cloud Model Armor is used
when DF_MODEL_ARMOR_TEMPLATE is configured.
"""

from __future__ import annotations

import hashlib
import os
import re
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel, Field


class FindingCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    DANGEROUS_INSTRUCTION = "dangerous_instruction"
    SENSITIVE_DATA = "sensitive_data"


class ArmorFinding(BaseModel):
    category: FindingCategory
    detail: str = ""
    # Only a hash of the matched snippet is retained — never raw content.
    match_sha256: str = ""


class ScreenResult(BaseModel):
    verdict: str  # "allow" | "block"
    findings: list[ArmorFinding] = Field(default_factory=list)
    screener: str = "local-heuristics"


class ArmorPort(Protocol):
    async def screen(self, text: str) -> ScreenResult: ...


_INJECTION_PATTERNS: tuple[tuple[FindingCategory, re.Pattern[str]], ...] = (
    (
        FindingCategory.PROMPT_INJECTION,
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"
            r"|disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|rules)"
            r"|forget\s+(everything|all|your)\s+(instructions|training)"
            r"|new\s+instructions?:\s*you\s+are",
            re.IGNORECASE,
        ),
    ),
    (
        FindingCategory.DANGEROUS_INSTRUCTION,
        re.compile(
            r"exfiltrat\w*|siphon\s+funds?|drain\s+the\s+account"
            r"|transfer\s+everything\s+to"
            r"|reveal\s+(your\s+)?(system\s+prompt|credentials|api\s+keys?)"
            r"|wire\s+the\s+full\s+balance",
            re.IGNORECASE,
        ),
    ),
)

_SENSITIVE_DATA_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("possible_bank_account", re.compile(r"\b\d{11,18}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("api_key_prefix", re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{12,})\b")),
    (
        "internal_account_marker",
        re.compile(r"\b(SECRET_ACC|INTERNAL_ONLY|BANK_ACCOUNT_)[A-Za-z0-9_]*\b"),
    ),
)


class LocalScreeningArmor:
    """Deterministic regex/heuristic screener — the portable fallback."""

    def __init__(self) -> None:
        self.screener = "local-heuristics"

    @staticmethod
    def _hash(match: str) -> str:
        return f"sha256:{hashlib.sha256(match.encode()).hexdigest()[:16]}"

    async def screen(self, text: str) -> ScreenResult:
        findings: list[ArmorFinding] = []

        for category, pattern in _INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                findings.append(
                    ArmorFinding(
                        category=category,
                        detail=f"matched pattern for {category.value}",
                        match_sha256=self._hash(m.group(0)),
                    )
                )

        for label, pattern in _SENSITIVE_DATA_PATTERNS:
            m = pattern.search(text)
            if m:
                findings.append(
                    ArmorFinding(
                        category=FindingCategory.SENSITIVE_DATA,
                        detail=label,
                        match_sha256=self._hash(m.group(0)),
                    )
                )

        verdict = (
            "block"
            if any(f.category != FindingCategory.SENSITIVE_DATA for f in findings)
            or len(findings) >= 2
            else "allow"
        )
        return ScreenResult(verdict=verdict, findings=findings, screener=self.screener)


class CloudModelArmor:
    """Google Cloud Model Armor client (lazy imports, template-based)."""

    def __init__(self, template_name: str) -> None:
        self.template_name = template_name
        self.screener = f"model-armor:{template_name.split('/')[-1]}"

    def _screen_sync(self, text: str) -> dict[str, Any]:
        import json as _json

        import google.auth as _google_auth
        import httpx
        from google.auth.transport.requests import Request as _AuthRequest

        creds, _ = _google_auth.default()
        creds.refresh(_AuthRequest())  # type: ignore[no-untyped-call]
        resp = httpx.post(
            f"https://modelarmor.googleapis.com/v1/{self.template_name}:screenContent",
            headers={"Authorization": f"Bearer {creds.token}"},
            json={"user_prompt_data": {"text": text}},
            timeout=10.0,
        )
        resp.raise_for_status()
        result: dict[str, Any] = _json.loads(resp.text)
        return result

    async def screen(self, text: str) -> ScreenResult:
        import asyncio

        raw = await asyncio.to_thread(self._screen_sync, text)
        findings: list[ArmorFinding] = []
        sanitized = raw.get("sanitization_result", {})

        pi = sanitized.get("pi_and_jailbreak_filter_result")
        if pi and pi.get("filter_match_state") == "MATCH_FOUND":
            findings.append(ArmorFinding(category=FindingCategory.PROMPT_INJECTION))
        sdp = sanitized.get("sdp_filter_result", {})
        for side in ("inspect_result", "deidentify_result"):
            r = sdp.get(side) or {}
            if r.get("filter_match_state") == "MATCH_FOUND":
                findings.append(ArmorFinding(category=FindingCategory.SENSITIVE_DATA))

        csam = sanitized.get("csam_filter_result")
        if csam and csam.get("filter_match_state") == "MATCH_FOUND":
            findings.append(ArmorFinding(category=FindingCategory.DANGEROUS_INSTRUCTION))

        blocked = any(
            res.get("filter_match_state") == "MATCH_FOUND" and res.get("confidence") == "HIGH"
            for res in [
                pi or {},
                *[(sdp.get(side) or {}) for side in ("inspect_result", "deidentify_result")],
            ]
        ) or bool(csam and csam.get("filter_match_state") == "MATCH_FOUND")

        return ScreenResult(
            verdict="block" if blocked else "allow",
            findings=findings,
            screener=self.screener,
        )


def create_armor_from_env() -> ArmorPort:
    template = os.environ.get("DF_MODEL_ARMOR_TEMPLATE")
    if template:
        return CloudModelArmor(template)
    return LocalScreeningArmor()


__all__ = [
    "ArmorFinding",
    "ArmorPort",
    "CloudModelArmor",
    "FindingCategory",
    "LocalScreeningArmor",
    "ScreenResult",
    "create_armor_from_env",
]
