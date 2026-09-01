"""Optional OpenTelemetry tracing.

Instrumentation is best-effort: if the ``otel`` optional dependencies are not
installed, :func:`setup_tracing` is a no-op so the platform still runs.
"""

from __future__ import annotations

from typing import Any

from src.config import Settings
from src.observability.logging import get_logger

_logger = get_logger(__name__)


def setup_tracing(app: Any, settings: Settings) -> None:
    """Instrument the FastAPI app with OTLP tracing when available."""
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        _logger.info("otel_not_installed", detail="Tracing disabled; install .[otel] to enable")
        return

    resource = Resource.create({"service.name": settings.service_name})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)
    _logger.info("otel_enabled", service=settings.service_name)
