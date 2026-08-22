"""Structured logging and in-process metric counters (PLAN.md Day 7).

Logs carry the required correlation fields; metrics expose the documented
counter families via ``Metrics.snapshot()`` served by each service.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any

_LOG = logging.getLogger("delegation_fabric")


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
    _LOG.info(message, extra={"df_fields": fields})


class Metrics:
    """Process-local monotonic counters for the documented metric families."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}

    def inc(self, name: str, **labels: str) -> None:
        key = name
        if labels:
            label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
            key = f"{name}{{{label_str}}}"
        self._counters[key] = self._counters.get(key, 0) + 1

    def snapshot(self) -> dict[str, int]:
        return dict(self._counters)


METRICS = Metrics()
