"""OpenTelemetry tracing helpers for the Guarded MCP Runtime."""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Iterable

from opentelemetry import context as otel_context
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider as SDKTracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Span, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from mcp_runtime.config import MCPRuntimeSettings
from platform_common import AuditEvent

TRACE_PROPAGATOR = TraceContextTextMapPropagator()
_TRACEPARENT_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_ALL_ZERO_TRACE_ID = "0" * 32
_ALL_ZERO_PARENT_ID = "0" * 16


def extract_trace_context(headers: Iterable[tuple[bytes, bytes]]) -> otel_context.Context:
    """Extract W3C traceparent/tracestate context from raw ASGI headers."""
    carrier: dict[str, str] = {}
    for raw_name, raw_value in headers:
        key = raw_name.decode("latin-1").lower()
        if key not in carrier:
            carrier[key] = raw_value.decode("latin-1")
    return TRACE_PROPAGATOR.extract(carrier=carrier)


def extract_trace_id(
    headers: Iterable[tuple[bytes, bytes]],
    *,
    fallback_trace_id: str | None = None,
) -> str:
    """Extract a valid W3C traceparent 32-hex trace-id or return a fallback."""
    for name, value in headers:
        if name.lower() == b"traceparent":
            raw = value.decode("latin-1").strip().lower()
            match = _TRACEPARENT_RE.fullmatch(raw)
            if match is not None:
                version, trace_id, parent_id, _flags = match.groups()
                if (
                    version != "ff"
                    and trace_id != _ALL_ZERO_TRACE_ID
                    and parent_id != _ALL_ZERO_PARENT_ID
                ):
                    return trace_id
    if fallback_trace_id and fallback_trace_id.strip():
        return fallback_trace_id.strip()
    return uuid.uuid4().hex


def annotate_mcp_span(
    span: Span,
    *,
    event: AuditEvent,
    had_exception: bool = False,
) -> None:
    """Attach privacy-safe operational attributes from an MCP Audit Event to an OTel span."""
    if not span.is_recording():
        return
    span.set_attribute("http.route", "/mcp")
    span.set_attribute("http.response.status_code", event.status_code)
    span.set_attribute("gateway.request_id", event.request_id)
    span.set_attribute("gateway.team", event.team)
    span.set_attribute("gateway.role", event.role)
    span.set_attribute("gateway.policy_version", event.policy_version)
    span.set_attribute("gateway.policy_action", event.policy_action)
    if event.run_id:
        span.set_attribute("gateway.run_id", event.run_id)
        span.set_attribute("mcp.run_id", event.run_id)
    if event.tool_name:
        span.set_attribute("gateway.tool_name", event.tool_name)
        span.set_attribute("mcp.tool_name", event.tool_name)
    if event.outcome:
        span.set_attribute("mcp.outcome", event.outcome)

    if had_exception:
        return
    if event.status_code >= 500:
        span.set_status(Status(StatusCode.ERROR))
    elif event.status_code < 400:
        span.set_status(Status(StatusCode.OK))
    else:
        span.set_attribute("gateway.denied", True)


def _normalize_otlp_traces_endpoint(raw_endpoint: str) -> str:
    cleaned = raw_endpoint.strip().rstrip("/")
    if not cleaned.endswith("/v1/traces"):
        return f"{cleaned}/v1/traces"
    return cleaned


def init_tracer_provider(settings: MCPRuntimeSettings) -> SDKTracerProvider | None:
    """Create an OTLP-backed TracerProvider when configured, else return None for clean no-op."""
    explicit_endpoint = (settings.otel_exporter_otlp_endpoint or "").strip()
    env_traces_endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "").strip()
    env_base_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()

    if explicit_endpoint:
        exporter = OTLPSpanExporter(endpoint=_normalize_otlp_traces_endpoint(explicit_endpoint))
    elif env_traces_endpoint or env_base_endpoint:
        exporter = OTLPSpanExporter()
    else:
        return None

    provider = SDKTracerProvider(
        resource=Resource.create({"service.name": settings.otel_service_name})
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    return provider
