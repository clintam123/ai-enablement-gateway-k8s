"""Prometheus metrics and OpenTelemetry tracing helpers for the Control Plane."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, MutableMapping

from opentelemetry import context as otel_context
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider as SDKTracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Span, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)

from gateway_api.config import ControlPlaneSettings
from platform_common import AuditEvent

TRACE_PROPAGATOR = TraceContextTextMapPropagator()

REQUEST_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
OVERHEAD_DURATION_BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5)


class ControlPlaneMetrics:
    """Isolated Prometheus metrics registry for a single Control Plane app instance."""

    def __init__(self, *, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.requests_total = Counter(
            "gateway_requests_total",
            "Total governed Control Plane requests",
            ["route", "team", "model_alias", "status"],
            registry=self.registry,
        )
        self.request_duration_seconds = Histogram(
            "gateway_request_duration_seconds",
            "Total Control Plane request duration in seconds",
            ["route", "model_alias", "stream"],
            buckets=REQUEST_DURATION_BUCKETS,
            registry=self.registry,
        )
        self.overhead_duration_seconds = Histogram(
            "gateway_overhead_duration_seconds",
            "Control Plane processing duration excluding upstream HTTP time in seconds",
            ["route"],
            buckets=OVERHEAD_DURATION_BUCKETS,
            registry=self.registry,
        )
        self.llm_tokens_total = Counter(
            "gateway_llm_tokens_total",
            "Total LLM Tokens processed by Team, Model Alias, and token type",
            ["team", "model_alias", "token_type"],
            registry=self.registry,
        )
        self.estimated_cost_usd_total = Counter(
            "gateway_estimated_cost_usd_total",
            "Total estimated USD spend by Team and Model Alias",
            ["team", "model_alias"],
            registry=self.registry,
        )
        self.policy_denials_total = Counter(
            "gateway_policy_denials_total",
            "Total 403 and 429 policy denials by Team and reason",
            ["team", "reason"],
            registry=self.registry,
        )
        self.upstream_failovers_total = Counter(
            "gateway_upstream_failovers_total",
            "Total primary-to-fallback upstream failovers",
            ["team", "requested_model", "routed_model"],
            registry=self.registry,
        )

    def observe(
        self,
        event: AuditEvent,
        *,
        route: str = "/v1/chat/completions",
        stream: bool = False,
        duration_seconds: float | None = None,
        upstream_duration_seconds: float = 0.0,
        effective_model: str | None = None,
        denial_reason: str | None = None,
    ) -> None:
        """Record Prometheus counters and histograms from one finalized Audit Event."""
        team = event.team or "unknown"
        model_alias = effective_model or event.requested_model or event.routed_model or "unknown"
        status_label = str(event.status_code)
        stream_label = "true" if stream else "false"
        total_duration = (
            max(0.0, duration_seconds)
            if duration_seconds is not None
            else max(0.0, event.latency_ms / 1000.0)
        )
        overhead_duration = max(0.0, total_duration - max(0.0, upstream_duration_seconds))

        self.requests_total.labels(
            route=route,
            team=team,
            model_alias=model_alias,
            status=status_label,
        ).inc()
        self.request_duration_seconds.labels(
            route=route,
            model_alias=model_alias,
            stream=stream_label,
        ).observe(total_duration)
        self.overhead_duration_seconds.labels(route=route).observe(overhead_duration)

        if event.prompt_tokens > 0:
            self.llm_tokens_total.labels(
                team=team,
                model_alias=model_alias,
                token_type="prompt",
            ).inc(event.prompt_tokens)
        if event.completion_tokens > 0:
            self.llm_tokens_total.labels(
                team=team,
                model_alias=model_alias,
                token_type="completion",
            ).inc(event.completion_tokens)
        if event.estimated_cost_usd > 0.0:
            self.estimated_cost_usd_total.labels(
                team=team,
                model_alias=model_alias,
            ).inc(event.estimated_cost_usd)

        if event.status_code in (403, 429):
            resolved_reason = (
                denial_reason
                or (event.triggered_rules[0] if event.triggered_rules else None)
                or f"http_{event.status_code}"
            )
            self.policy_denials_total.labels(team=team, reason=resolved_reason).inc()

        if event.fallback_used:
            self.upstream_failovers_total.labels(
                team=team,
                requested_model=event.requested_model or "unknown",
                routed_model=event.routed_model or "unknown",
            ).inc()

    def render_latest(self) -> tuple[bytes, str]:
        """Render isolated Prometheus metrics payload and content type."""
        return generate_latest(self.registry), CONTENT_TYPE_LATEST


def extract_trace_context(
    headers: Iterable[tuple[bytes, bytes]],
) -> otel_context.Context:
    """Extract W3C traceparent/tracestate context from raw ASGI header pairs."""
    carrier: dict[str, str] = {}
    for raw_name, raw_value in headers:
        key = raw_name.decode("latin-1").lower()
        if key not in carrier:
            carrier[key] = raw_value.decode("latin-1")
    return TRACE_PROPAGATOR.extract(carrier=carrier)


def inject_trace_headers(
    outbound_headers: MutableMapping[str, str],
    *,
    request_headers: Mapping[str, str] | None = None,
) -> None:
    """Inject W3C traceparent/tracestate from the active span or valid incoming headers."""
    TRACE_PROPAGATOR.inject(carrier=outbound_headers)
    if "traceparent" not in outbound_headers and request_headers is not None:
        carrier = {key.lower(): value for key, value in request_headers.items()}
        if carrier.get("traceparent"):
            extracted = TRACE_PROPAGATOR.extract(carrier=carrier)
            TRACE_PROPAGATOR.inject(carrier=outbound_headers, context=extracted)


def annotate_span_from_event(
    span: Span,
    *,
    route: str,
    event: AuditEvent,
    stream: bool,
    had_exception: bool = False,
) -> None:
    """Attach privacy-safe operational attributes from an Audit Event to an OTel span."""
    if not span.is_recording():
        return
    span.set_attribute("http.route", route)
    span.set_attribute("http.response.status_code", event.status_code)
    span.set_attribute("gateway.request_id", event.request_id)
    span.set_attribute("gateway.team", event.team)
    span.set_attribute("gateway.role", event.role)
    span.set_attribute("gateway.policy_version", event.policy_version)
    span.set_attribute("gateway.policy_action", event.policy_action)
    span.set_attribute("gateway.fallback_used", event.fallback_used)
    span.set_attribute("gateway.stream", stream)
    span.set_attribute("gateway.prompt_tokens", event.prompt_tokens)
    span.set_attribute("gateway.completion_tokens", event.completion_tokens)
    span.set_attribute("gateway.estimated_cost_usd", event.estimated_cost_usd)
    if event.requested_model:
        span.set_attribute("gateway.requested_model", event.requested_model)
    if event.routed_model:
        span.set_attribute("gateway.routed_model", event.routed_model)
    if event.tool_name:
        span.set_attribute("gateway.tool_name", event.tool_name)
    if event.run_id:
        span.set_attribute("gateway.run_id", event.run_id)
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


def init_tracer_provider(settings: ControlPlaneSettings) -> SDKTracerProvider | None:
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
