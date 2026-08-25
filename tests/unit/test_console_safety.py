"""Console safety tests: escaping discipline and secret masking.

The console renders everything client-side, so the safety contract lives in
the page's JS (esc()/mask() and escaper-wrapped helpers) mirrored by the
Python helpers in apps.control_plane.console. These tests enforce:

1. escape_console_value neutralizes malicious payloads (e.g. a delegation
   sponsor field carrying script/attribute-injection markup).
2. mask_console_value never returns material for token-like field names.
3. The shipped page never interpolates a raw JS variable into HTML — every
   template-literal hole must go through an escaper-wrapped helper.
"""

from __future__ import annotations

import re

from apps.control_plane.console import (
    _PAGE,
    _SENSITIVE_KEY_RE,
    escape_console_value,
    mask_console_value,
)

# Escaper-wrapped producers allowed inside template-literal holes. Each one
# internally routes every dynamic value through esc().
_SAFE_INTERPOLATION_PREFIXES = (
    "esc(",
    "mask(",
    "statusPill(",
    "riskPill(",
    "approvalQueue(",
    "revokedCell(",
    "durationRow(",
    "maskedCell(",
    "sponsorLabel(",
)

_UNSAFE_INTERPOLATION_RE = re.compile(
    r"\$\{\s*(?!" + "|".join(re.escape(p) for p in _SAFE_INTERPOLATION_PREFIXES) + r")"
)


def test_escape_neutralizes_script_injection_in_sponsor_field() -> None:
    payload = "<script>alert('pwned')</script>"
    escaped = escape_console_value(payload)
    assert "<script>" not in escaped
    assert escaped == "&lt;script&gt;alert(&#39;pwned&#39;)&lt;/script&gt;"


def test_escape_neutralizes_attribute_and_entity_attacks() -> None:
    for payload in (
        '" onmouseover="alert(1)',
        "'><img src=x onerror=alert(1)>",
        "</td></tr><script>alert(2)</script>",
        "user:priya@example.com & <b>bold</b>",
    ):
        escaped = escape_console_value(payload)
        assert "<" not in escaped and ">" not in escaped and '"' not in escaped
        assert "'" not in escaped


def test_escape_handles_none_and_non_strings() -> None:
    assert escape_console_value(None) == ""
    assert escape_console_value(42) == "42"
    assert escape_console_value(True) == "True"


def test_mask_hides_token_like_fields() -> None:
    for key in (
        "token",
        "access_token",
        "grant_token",
        "secret",
        "client_secret",
        "api_key",
        "API-KEY",
        "password",
        "credential",
        "refreshToken",
    ):
        assert mask_console_value(key, "super-secret-material") == "\u2022" * 8


def test_mask_passes_through_benign_fields() -> None:
    assert mask_console_value("sponsor", "user:priya@example.com") == "user:priya@example.com"
    assert mask_console_value("purpose", "weekly_vendor_settlement") == "weekly_vendor_settlement"
    assert mask_console_value("token_count_note", None) == "\u2022" * 8  # name still matches


def test_sensitive_key_regex_matches_conventions() -> None:
    assert _SENSITIVE_KEY_RE.search("execution_grant_token")
    assert not _SENSITIVE_KEY_RE.search("task_id")


def test_page_has_no_raw_interpolation_into_html() -> None:
    matches = _UNSAFE_INTERPOLATION_RE.findall(_PAGE)
    assert matches == [], f"Raw template interpolation found at: {matches}"


def test_page_masks_and_escapes_helpers_are_present() -> None:
    # The client-side mirrors must ship with the page.
    assert "const esc = (v)" in _PAGE
    assert "const mask = (key, v)" in _PAGE
    assert "SENSITIVE_KEY" in _PAGE


def test_page_exposes_all_seven_views() -> None:
    for tab_id in (
        "tab-registry",
        "tab-agent",
        "tab-delegations",
        "tab-approvals",
        "tab-task",
        "tab-audit",
        "tab-security",
    ):
        assert tab_id in _PAGE
