"""OpenTelemetry tracing adapters with graceful degradation for local runs.

Module import is side-effect free: every OpenTelemetry and Google Cloud
dependency is imported lazily inside guarded blocks so services run correctly
with no telemetry stack installed.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import Any


class _NoopTracer:
    """Stand-in for ``opentelemetry.trace.Tracer`` when OTel is unavailable."""

    def start_as_current_span(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> AbstractContextManager[None]:
        return self._span()

    def start_span(self, *args: Any, **kwargs: Any) -> None:
        return None

    @contextmanager
    def _span(self) -> Iterator[None]:
        yield


def configure_tracing(service_name: str) -> None:
    """Install a global TracerProvider tagged for this service.

    Uses Cloud Trace export when ``GOOGLE_CLOUD_PROJECT`` is set and the GCP
    exporter is importable; otherwise installs an exporter-less provider that
    discards spans. Never raises in local or test environments.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
    except ImportError:
        return

    resource = Resource.create(
        {
            "service.name": service_name,
            "deployment.environment": os.environ.get("DF_ENV", "local"),
        }
    )
    provider = TracerProvider(resource=resource)

    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if project_id:
        try:
            from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            exporter = CloudTraceSpanExporter(project_id=project_id)  # type: ignore[no-untyped-call]
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except ImportError:
            pass

    if not isinstance(trace.get_tracer_provider(), TracerProvider):
        trace.set_tracer_provider(provider)


def instrument_fastapi_app(app: Any) -> None:
    """Attach FastAPI auto-instrumentation when available; never raises."""
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        return

    try:
        FastAPIInstrumentor.instrument_app(app)
    except Exception:
        return


def get_tracer(name: str) -> Any:
    """Thin wrapper over ``opentelemetry.trace.get_tracer`` with local fallback."""
    try:
        from opentelemetry import trace
    except ImportError:
        return _NoopTracer()
    return trace.get_tracer(name)
