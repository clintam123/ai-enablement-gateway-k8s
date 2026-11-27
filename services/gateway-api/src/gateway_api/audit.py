"""Privacy-safe structured Audit Event emission and pure ASGI AuditMiddleware."""

from __future__ import annotations

import inspect
import logging
import re
import time
import uuid
from collections.abc import Callable
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, Status, StatusCode, TracerProvider
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from gateway_api.telemetry import (
    ControlPlaneMetrics,
    annotate_span_from_event,
    extract_trace_context,
)
from platform_common import ActorContext, AuditEvent, LoadedPolicyBundle, PolicyBundle

AUDIT_LOGGER_NAME = "gateway_api.audit"
_TRACEPARENT_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_ALL_ZERO_TRACE_ID = "0" * 32
_ALL_ZERO_PARENT_ID = "0" * 16

AuditSink = Callable[[AuditEvent], Any] | list[AuditEvent]


def is_governed_path(path: str) -> bool:
    """Return True for governed LLM and MCP Control Plane request paths."""
    return path == "/v1/chat/completions" or path == "/mcp" or path.startswith("/mcp/")


def extract_trace_id(headers: list[tuple[bytes, bytes]] | tuple[tuple[bytes, bytes], ...]) -> str:
    """Extract a valid W3C traceparent 32-hex trace-id or generate a fresh uuid4 hex."""
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
    return uuid.uuid4().hex


def estimate_cost_usd(
    policy: PolicyBundle,
    model_alias: str | None,
    prompt_tokens: int,
    completion_tokens: int,
) -> float:
    """Estimate USD spend from Policy Bundle per-1k LLM Token pricing for a Model Alias."""
    if not model_alias:
        return 0.0
    alias_policy = policy.models.get(model_alias)
    if alias_policy is None:
        return 0.0
    safe_prompt = max(0, prompt_tokens)
    safe_completion = max(0, completion_tokens)
    cost = (safe_prompt / 1000.0) * alias_policy.prompt_usd_per_1k_tokens + (
        safe_completion / 1000.0
    ) * alias_policy.completion_usd_per_1k_tokens
    return round(cost, 10)


class AuditEmitter:
    """Structured 1-line JSON logger and optional injectable Audit Event sink."""

    def __init__(
        self,
        audit_sink: AuditSink | None = None,
        *,
        logger_name: str = AUDIT_LOGGER_NAME,
    ) -> None:
        self._audit_sink = audit_sink
        self._logger = logging.getLogger(logger_name)

    async def emit(self, event: AuditEvent) -> None:
        """Emit one privacy-safe JSON Audit Event to the audit logger and optional sink."""
        self._logger.info(event.model_dump_json())
        if self._audit_sink is None:
            return
        if isinstance(self._audit_sink, list):
            self._audit_sink.append(event)
            return
        result = self._audit_sink(event)
        if inspect.isawaitable(result):
            await result


def _initialize_audit_state(
    state: dict[str, Any],
    headers: list[tuple[bytes, bytes]] | tuple[tuple[bytes, bytes], ...],
) -> None:
    state.setdefault("request_id", uuid.uuid4().hex)
    state.setdefault("trace_id", extract_trace_id(headers))
    state.setdefault("policy_action", None)
    state.setdefault("triggered_rules", [])
    state.setdefault("redacted_entity_types", [])
    state.setdefault("prompt_sha256", None)
    state.setdefault("requested_model", None)
    state.setdefault("effective_model", None)
    state.setdefault("target_model", None)
    state.setdefault("routed_model", None)
    state.setdefault("fallback_used", False)
    state.setdefault("prompt_tokens", None)
    state.setdefault("completion_tokens", None)
    state.setdefault("streamed_completion_chars", 0)
    state.setdefault("stream", False)
    state.setdefault("upstream_duration_seconds", 0.0)
    state.setdefault("policy_denial_reason", None)
    state.setdefault("tool_name", None)
    state.setdefault("run_id", None)
    state.setdefault("outcome", None)


def _resolve_policy_action(state: dict[str, Any], status_code: int) -> str:
    recorded = state.get("policy_action")
    if isinstance(recorded, str) and recorded:
        return recorded
    if status_code in (401, 403, 422, 429):
        return "deny"
    if status_code >= 500:
        return "error"
    return "allow"


def _resolve_completion_tokens(state: dict[str, Any]) -> int:
    recorded = state.get("completion_tokens")
    if isinstance(recorded, int) and not isinstance(recorded, bool):
        return max(0, recorded)
    streamed_chars = state.get("streamed_completion_chars")
    if isinstance(streamed_chars, int) and streamed_chars > 0:
        return max(1, streamed_chars // 4)
    return 0


def _build_audit_event(
    *,
    state: dict[str, Any],
    loaded_policy: LoadedPolicyBundle,
    status_code: int,
    latency_ms: float,
) -> AuditEvent:
    actor = state.get("actor")
    if isinstance(actor, ActorContext):
        actor_id = actor.actor_id
        team = actor.team
        role = actor.role
    else:
        actor_id = "anonymous"
        team = "unknown"
        role = "anonymous"

    requested_model = state.get("requested_model")
    effective_model = state.get("effective_model") or state.get("target_model")
    routed_model = state.get("routed_model")
    billing_alias = effective_model or requested_model or routed_model

    raw_prompt_tokens = state.get("prompt_tokens")
    prompt_tokens = (
        max(0, raw_prompt_tokens)
        if isinstance(raw_prompt_tokens, int) and not isinstance(raw_prompt_tokens, bool)
        else 0
    )
    completion_tokens = _resolve_completion_tokens(state)

    return AuditEvent(
        trace_id=str(state["trace_id"]),
        request_id=str(state["request_id"]),
        actor_id=actor_id,
        team=team,
        role=role,
        requested_model=requested_model,
        routed_model=routed_model,
        tool_name=state.get("tool_name"),
        run_id=state.get("run_id"),
        fallback_used=bool(state.get("fallback_used", False)),
        policy_version=loaded_policy.policy_version,
        policy_action=_resolve_policy_action(state, status_code),
        triggered_rules=list(state.get("triggered_rules") or ()),
        redacted_entity_types=list(state.get("redacted_entity_types") or ()),
        prompt_sha256=state.get("prompt_sha256"),
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        estimated_cost_usd=estimate_cost_usd(
            loaded_policy.bundle,
            billing_alias,
            prompt_tokens,
            completion_tokens,
        ),
        latency_ms=round(max(0.0, latency_ms), 3),
        status_code=status_code,
        outcome=state.get("outcome"),
    )


class AuditMiddleware:
    """Pure ASGI middleware emitting one privacy-safe Audit Event after response/stream ends."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        emitter: AuditEmitter,
        loaded_policy: LoadedPolicyBundle,
        metrics: ControlPlaneMetrics | None = None,
        tracer_provider: TracerProvider | None = None,
    ) -> None:
        self.app = app
        self.emitter = emitter
        self.loaded_policy = loaded_policy
        self.metrics = metrics
        self.tracer_provider = tracer_provider or trace.NoOpTracerProvider()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or not is_governed_path(path):
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", ())
        state = scope.setdefault("state", {})
        _initialize_audit_state(state, headers)

        started_at = time.perf_counter()
        status_code: int | None = None

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
            await send(message)

        span_name = "gateway.mcp" if path == "/mcp" or path.startswith("/mcp/") else "gateway.chat"
        tracer = self.tracer_provider.get_tracer("gateway_api.telemetry")
        parent_ctx = extract_trace_context(headers)

        with tracer.start_as_current_span(
            span_name,
            context=parent_ctx,
            kind=SpanKind.SERVER,
        ) as span:
            span_ctx = span.get_span_context()
            if span_ctx.is_valid:
                state["trace_id"] = f"{span_ctx.trace_id:032x}"
            had_exception = False
            try:
                await self.app(scope, receive, send_wrapper)
            except BaseException as exc:
                had_exception = True
                if span.is_recording():
                    span.set_attribute("error.type", type(exc).__name__)
                    span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                raise
            finally:
                latency_seconds = max(0.0, time.perf_counter() - started_at)
                final_status = status_code if status_code is not None else 500
                event = _build_audit_event(
                    state=state,
                    loaded_policy=self.loaded_policy,
                    status_code=final_status,
                    latency_ms=latency_seconds * 1000.0,
                )
                route_obj = scope.get("route")
                route = getattr(route_obj, "path", None) or path or "/"
                annotate_span_from_event(
                    span,
                    route=route,
                    event=event,
                    stream=bool(state.get("stream", False)),
                    had_exception=had_exception,
                )
                if self.metrics is not None:
                    self.metrics.observe(
                        event,
                        route=route,
                        stream=bool(state.get("stream", False)),
                        duration_seconds=latency_seconds,
                        upstream_duration_seconds=float(
                            state.get("upstream_duration_seconds") or 0.0
                        ),
                        effective_model=state.get("effective_model") or state.get("target_model"),
                        denial_reason=state.get("policy_denial_reason"),
                    )
                await self.emitter.emit(event)
