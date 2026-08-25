"""Structured logging, counters and latency histograms (PLAN.md Day 7).

Logs carry the required correlation fields; ``trace_id`` is auto-injected from
the active OpenTelemetry span when one exists. ``Metrics.snapshot()`` serves
the documented counter families, ``Metrics.histogram_snapshot()`` the latency
families, and ``Metrics.prometheus()`` renders everything in Prometheus text
exposition format served by each service's ``/metrics`` endpoint.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any

_LOG = logging.getLogger("delegation_fabric")

LATENCY_BUCKETS_MS: tuple[float, ...] = (5, 10, 25, 50, 100, 250, 500, 1000, 2500)

_LabelKey = tuple[tuple[str, str], ...]


def _current_trace_id() -> str | None:
    """32-char hex trace id of the active OTel span; None when absent/invalid."""
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    try:
        ctx = trace.get_current_span().get_span_context()
    except Exception:
        return None
    if ctx is None or not getattr(ctx, "is_valid", False):
        return None
    return f"{ctx.trace_id:032x}"


def configure_logging() -> None:
    """JSON structured logging to stdout; honors DF_ENV/DF_LOG_LEVEL."""
    level = os.environ.get("DF_LOG_LEVEL", "INFO").upper()

    class _JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            import json

            payload: dict[str, Any] = {
                "severity": record.levelname,
                "message": record.getMessage(),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "logger": record.name,
            }
            extra = getattr(record, "df_fields", None)
            if isinstance(extra, dict):
                payload.update(extra)
            if record.exc_info and record.exc_info[0] is not None:
                payload["exception"] = record.exc_info[0].__name__
            return json.dumps(payload)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    _LOG.handlers = [handler]
    _LOG.setLevel(level)
    _LOG.propagate = False


def log_event(message: str, **fields: Any) -> None:
    if "trace_id" not in fields:
        trace_id = _current_trace_id()
        if trace_id:
            fields["trace_id"] = trace_id
    _LOG.info(message, extra={"df_fields": fields})


def _label_key(labels: dict[str, str]) -> _LabelKey:
    return tuple(sorted(labels.items()))


def _flat_key(name: str, labels: _LabelKey) -> str:
    if labels:
        label_str = ",".join(f"{k}={v}" for k, v in labels)
        return f"{name}{{{label_str}}}"
    return name


def _prom_labels(label_key: _LabelKey) -> str:
    escaped = (
        k + '="' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
        for k, v in label_key
    )
    joined = ",".join(escaped)
    return "{" + joined + "}" if joined else ""


class _HistogramSeries:
    """Bounded-bucket cumulative histogram for one labeled metric series."""

    __slots__ = ("buckets", "count", "counts", "sum")

    def __init__(self, buckets: tuple[float, ...]) -> None:
        self.buckets = buckets
        self.counts = [0] * len(buckets)
        self.count = 0
        self.sum = 0.0

    def observe(self, value_ms: float) -> None:
        self.count += 1
        self.sum += value_ms
        # Cumulative Prometheus semantics: one observation lands in every
        # bucket whose upper bound is >= the observed value.
        for i, bound in enumerate(self.buckets):
            if value_ms <= bound:
                self.counts[i] += 1


class Metrics:
    """Process-local monotonic counters and bounded-bucket latency histograms.

    Single-event-loop constraint: there is deliberately no thread-safety
    lock. Mutation is safe from async handlers because plain int/dict
    read-modify-write steps never yield to the event loop mid-update, so all
    access is effectively serialized on one loop. A future sync threadpool
    endpoint touching these metrics would need to add a lock.
    """

    def __init__(self) -> None:
        self._counters: dict[tuple[str, _LabelKey], int] = {}
        self._histograms: dict[tuple[str, _LabelKey], _HistogramSeries] = {}

    def inc(self, name: str, **labels: str) -> None:
        key = (name, _label_key(labels))
        self._counters[key] = self._counters.get(key, 0) + 1

    def observe(self, name: str, value_ms: float, **labels: str) -> None:
        key = (name, _label_key(labels))
        series = self._histograms.get(key)
        if series is None:
            series = _HistogramSeries(LATENCY_BUCKETS_MS)
            self._histograms[key] = series
        series.observe(value_ms)

    def reset(self) -> None:
        self._counters.clear()
        self._histograms.clear()

    def snapshot(self) -> dict[str, int]:
        """Flat ``name{k=v}`` -> count mapping, identical to the legacy shape."""
        return {_flat_key(name, lk): v for (name, lk), v in self._counters.items()}

    def histogram_snapshot(self) -> dict[str, dict[str, Any]]:
        """Flat key -> {buckets, counts(cumulative), count, sum} for histograms."""
        out: dict[str, dict[str, Any]] = {}
        for (name, lk), s in self._histograms.items():
            out[_flat_key(name, lk)] = {
                "buckets": list(s.buckets),
                "counts": list(s.counts),
                "count": s.count,
                "sum": s.sum,
            }
        return out

    def prometheus(self) -> str:
        """Full Prometheus text exposition of counters and histograms."""
        lines: list[str] = []
        counter_groups: dict[str, list[tuple[_LabelKey, int]]] = {}
        for (name, lk), value in self._counters.items():
            counter_groups.setdefault(name, []).append((lk, value))
        for name in sorted(counter_groups):
            lines.append(f"# TYPE {name} counter")
            for lk, value in sorted(counter_groups[name]):
                lines.append(f"{name}{_prom_labels(lk)} {value}")

        histogram_groups: dict[str, list[tuple[_LabelKey, _HistogramSeries]]] = {}
        for (name, lk), series in self._histograms.items():
            histogram_groups.setdefault(name, []).append((lk, series))
        for name in sorted(histogram_groups):
            lines.append(f"# TYPE {name} histogram")
            for lk, s in sorted(histogram_groups[name]):
                for bound, cumulative in zip(s.buckets, s.counts, strict=True):
                    le = (("le", f"{bound:g}"),)
                    lines.append(
                        f"{name}_bucket{_prom_labels(tuple(sorted((*lk, *le))))} {cumulative}"
                    )
                inf = (("le", "+Inf"),)
                lines.append(f"{name}_bucket{_prom_labels(tuple(sorted((*lk, *inf))))} {s.count}")
                lines.append(f"{name}_count{_prom_labels(lk)} {s.count}")
                lines.append(f"{name}_sum{_prom_labels(lk)} {s.sum:g}")
        return "\n".join(lines) + ("\n" if lines else "")


METRICS = Metrics()
