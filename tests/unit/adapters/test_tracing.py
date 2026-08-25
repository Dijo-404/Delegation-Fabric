"""Unit tests for tracing adapter idempotency and graceful degradation."""

from typing import Any

from delegation_fabric_adapters.tracing import configure_tracing, get_tracer


def test_configure_tracing_is_idempotent(monkeypatch: Any) -> None:
    """A second call must not construct or install another provider.

    Regression guard: the pre-fix implementation built a Resource +
    TracerProvider (and, on Cloud Run, a BatchSpanProcessor worker thread)
    before discovering an SDK provider was already installed and discarding
    it — leaking orphaned threads on repeat calls.
    """
    from opentelemetry import trace as ot_trace
    from opentelemetry.sdk.trace import TracerProvider

    installed: list[object] = []
    holder: dict[str, object] = {"provider": object()}  # default non-SDK global provider

    def fake_get_tracer_provider() -> Any:
        return holder["provider"]

    def fake_set_tracer_provider(provider: Any) -> None:
        installed.append(provider)
        holder["provider"] = provider

    monkeypatch.setattr(ot_trace, "get_tracer_provider", fake_get_tracer_provider)
    monkeypatch.setattr(ot_trace, "set_tracer_provider", fake_set_tracer_provider)

    configure_tracing("svc-a")
    configure_tracing("svc-b")

    assert len(installed) == 1
    assert isinstance(installed[0], TracerProvider)


def test_configure_tracing_noop_when_sdk_missing(monkeypatch: Any) -> None:
    """Without the OTel SDK importable, configuration degrades to a no-op."""

    import builtins

    real_import = builtins.__import__

    def blocked(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("opentelemetry"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    configure_tracing("svc")  # must not raise


def test_get_tracer_returns_object_without_sdk(monkeypatch: Any) -> None:
    """Tracer access falls back to a noop when OTel is unavailable."""

    import builtins

    real_import = builtins.__import__

    def blocked(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("opentelemetry"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    assert get_tracer("x") is not None
