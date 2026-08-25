"""Unit tests for Day 7 observability: histograms, Prometheus rendering, trace-aware logs."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterator
from typing import Any

import pytest
from delegation_fabric_adapters.observability import (
    LATENCY_BUCKETS_MS,
    Metrics,
    configure_logging,
    log_event,
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────


class _FakeSpanContext:
    def __init__(self, trace_id: int, span_id: int = 7) -> None:
        self.trace_id = trace_id
        self.span_id = span_id

    @property
    def is_valid(self) -> bool:
        return self.trace_id != 0 and self.span_id != 0


class _FakeSpan:
    def __init__(self, ctx: _FakeSpanContext) -> None:
        self._ctx = ctx

    def get_span_context(self) -> _FakeSpanContext:
        return self._ctx


@pytest.fixture
def captured_records() -> Iterator[list[logging.LogRecord]]:
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("delegation_fabric")
    original_handlers = logger.handlers[:]
    original_level = logger.level
    logger.handlers = [_Capture()]
    logger.setLevel(logging.INFO)
    try:
        yield records
    finally:
        logger.handlers = original_handlers
        logger.setLevel(original_level)


def _fields_of(records: list[logging.LogRecord], message: str) -> dict[str, Any]:
    matching = [r for r in records if r.getMessage() == message]
    assert matching, f"no record with message {message!r} among {[r.getMessage() for r in records]}"
    fields = matching[-1].df_fields
    assert isinstance(fields, dict)
    return fields


# ─── Histogram behavior ───────────────────────────────────────────────────────


def test_latency_buckets_constant() -> None:
    assert LATENCY_BUCKETS_MS == (5, 10, 25, 50, 100, 250, 500, 1000, 2500)


def test_histogram_bucket_placement_and_cumulative_counts() -> None:
    m = Metrics()
    m.observe("grant_issue_latency_ms", 7.0)  # <=10
    m.observe("grant_issue_latency_ms", 3.0)  # <=5
    m.observe("grant_issue_latency_ms", 4000.0)  # >2500, only +Inf

    hist = m.histogram_snapshot()["grant_issue_latency_ms"]
    assert hist["count"] == 3
    assert hist["sum"] == pytest.approx(4010.0)
    counts = hist["counts"]
    assert len(counts) == len(LATENCY_BUCKETS_MS)
    # cumulative: le=5 ->1, le=10 ->2, le=25 ->2, ..., le=2500 ->2
    assert counts[0] == 1
    assert counts[1] == 2
    assert all(c == 2 for c in counts[2:])
    assert hist["buckets"] == list(LATENCY_BUCKETS_MS)


def test_histogram_labels_isolate_series() -> None:
    m = Metrics()
    m.observe("gateway_execution_latency_ms", 20.0, tool="invoice.read")
    m.observe("gateway_execution_latency_ms", 600.0, tool="payment.instruct")

    snap = m.histogram_snapshot()
    assert snap["gateway_execution_latency_ms{tool=invoice.read}"]["count"] == 1
    assert snap["gateway_execution_latency_ms{tool=payment.instruct}"]["count"] == 1
    assert snap["gateway_execution_latency_ms{tool=invoice.read}"]["sum"] == pytest.approx(20.0)


def test_inc_backward_compat_flat_snapshot_keys() -> None:
    m = Metrics()
    m.inc("grant_replay_total")
    m.inc("grant_denied_total", reason="APPROVAL_REQUIRED")
    m.inc("grant_denied_total", reason="APPROVAL_REQUIRED")

    snap = m.snapshot()
    assert snap["grant_replay_total"] == 1
    assert snap["grant_denied_total{reason=APPROVAL_REQUIRED}"] == 2
    assert set(snap) == {"grant_replay_total", "grant_denied_total{reason=APPROVAL_REQUIRED}"}


# ─── Prometheus rendering ─────────────────────────────────────────────────────


def test_prometheus_renders_counter_families() -> None:
    m = Metrics()
    m.inc("grant_issued_total")
    m.inc("grant_denied_total", reason="DELEGATION_EXPIRED")

    text = m.prometheus()
    assert "# TYPE grant_issued_total counter" in text
    assert "grant_issued_total 1" in text
    assert "# TYPE grant_denied_total counter" in text
    assert 'grant_denied_total{reason="DELEGATION_EXPIRED"} 1' in text


def test_prometheus_renders_histogram_buckets_count_sum() -> None:
    m = Metrics()
    m.observe("gateway_execution_latency_ms", 7.0)
    m.observe("gateway_execution_latency_ms", 3000.0)

    text = m.prometheus()
    assert "# TYPE gateway_execution_latency_ms histogram" in text
    assert 'gateway_execution_latency_ms_bucket{le="5"} 0' in text
    assert 'gateway_execution_latency_ms_bucket{le="10"} 1' in text
    assert 'gateway_execution_latency_ms_bucket{le="2500"} 1' in text
    assert 'gateway_execution_latency_ms_bucket{le="+Inf"} 2' in text
    assert "gateway_execution_latency_ms_count 2" in text
    assert "gateway_execution_latency_ms_sum 3007" in text


def test_prometheus_histogram_with_labels_merges_le_sorted() -> None:
    m = Metrics()
    m.observe("tool_latency", 30.0, status="success", tool="vendor.read")

    text = m.prometheus()
    assert 'tool_latency_bucket{le="50",status="success",tool="vendor.read"} 1' in text
    assert 'tool_latency_count{status="success",tool="vendor.read"} 1' in text
    assert 'tool_latency_sum{status="success",tool="vendor.read"} 30' in text


# ─── trace_id injection ───────────────────────────────────────────────────────


def test_log_event_injects_trace_id_from_active_span(
    monkeypatch: pytest.MonkeyPatch, captured_records: list[logging.LogRecord]
) -> None:
    from opentelemetry import trace as otel_trace

    monkeypatch.setattr(
        otel_trace,
        "get_current_span",
        lambda: _FakeSpan(_FakeSpanContext(trace_id=0xDEADBEEFCAFEF00D)),
    )

    log_event("with span", task_id="t1")
    fields = _fields_of(captured_records, "with span")
    assert fields["trace_id"] == "0" * 16 + "deadbeefcafef00d"
    assert len(fields["trace_id"]) == 32
    assert fields["task_id"] == "t1"


def test_log_event_skips_invalid_span_context(
    monkeypatch: pytest.MonkeyPatch, captured_records: list[logging.LogRecord]
) -> None:
    from opentelemetry import trace as otel_trace

    monkeypatch.setattr(
        otel_trace, "get_current_span", lambda: _FakeSpan(_FakeSpanContext(trace_id=0))
    )

    log_event("invalid span")
    assert "trace_id" not in _fields_of(captured_records, "invalid span")


def test_log_event_without_otel_graceful_noop(
    monkeypatch: pytest.MonkeyPatch, captured_records: list[logging.LogRecord]
) -> None:
    monkeypatch.setitem(sys.modules, "opentelemetry", None)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", None)

    log_event("no otel installed", decision="allow")
    fields = _fields_of(captured_records, "no otel installed")
    assert fields["decision"] == "allow"
    assert "trace_id" not in fields


def test_explicit_trace_id_wins_over_active_span(
    monkeypatch: pytest.MonkeyPatch, captured_records: list[logging.LogRecord]
) -> None:
    from opentelemetry import trace as otel_trace

    monkeypatch.setattr(
        otel_trace, "get_current_span", lambda: _FakeSpan(_FakeSpanContext(trace_id=42))
    )
    log_event("explicit", trace_id="custom-trace")
    assert _fields_of(captured_records, "explicit")["trace_id"] == "custom-trace"


def test_json_formatter_emits_trace_id_field(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from opentelemetry import trace as otel_trace

    monkeypatch.setattr(
        otel_trace, "get_current_span", lambda: _FakeSpan(_FakeSpanContext(trace_id=(1 << 64) - 1))
    )
    configure_logging()
    log_event("json line", task_id="t9")
    out = capsys.readouterr().out
    payload = json.loads(out.strip().splitlines()[-1])
    assert payload["trace_id"] == format((1 << 64) - 1, "032x")
    assert payload["task_id"] == "t9"
