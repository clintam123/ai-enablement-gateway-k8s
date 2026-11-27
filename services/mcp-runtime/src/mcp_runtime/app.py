"""Guarded MCP Runtime FastAPI application factory and pure ASGI guard/audit middleware."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from opentelemetry import trace
from opentelemetry.trace import SpanKind, Status, StatusCode, TracerProvider
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_runtime.config import MCPRuntimeSettings
from mcp_runtime.loop_cap import (
    MCPRuntimeUnavailableError,
    consume_run_tool_call,
    ensure_redis_ready,
)
from mcp_runtime.telemetry import (
    annotate_mcp_span,
    extract_trace_context,
    extract_trace_id,
    init_tracer_provider,
)
from mcp_runtime.tools import ACTOR_ASSERTION_CTX, build_mcp_server
from platform_common import (
    INTERNAL_IDENTITY_HEADER,
    MIN_INTERNAL_IDENTITY_SECRET_BYTES,
    AuditEvent,
    InternalIdentityAssertion,
    InternalIdentityError,
    LoadedPolicyBundle,
    load_policy_bundle,
    verify_internal_identity_assertion,
)

MCP_AUDIT_LOGGER_NAME = "mcp_runtime.audit"

AuditSink = Callable[[AuditEvent], Any] | list[AuditEvent]

_JSONRPC_INTERNAL_ERROR = -32000
_JSONRPC_AUTH_ERROR = -32001
_JSONRPC_RBAC_ERROR = -32003
_JSONRPC_TIMEOUT_ERROR = -32004
_JSONRPC_LOOP_CAP_ERROR = -32029


def _is_mcp_path(path: str) -> bool:
    return path == "/mcp" or path.startswith("/mcp/")


def _is_secret_configured(secret: str | None) -> bool:
    return (
        isinstance(secret, str)
        and len(secret.encode("utf-8")) >= MIN_INTERNAL_IDENTITY_SECRET_BYTES
    )


def _get_header(
    headers: list[tuple[bytes, bytes]] | tuple[tuple[bytes, bytes], ...],
    key: str,
) -> str | None:
    target = key.lower().encode("latin-1")
    for raw_name, raw_value in headers:
        if raw_name.lower() == target:
            return raw_value.decode("latin-1")
    return None


def _upsert_response_headers(
    headers: list[tuple[bytes, bytes]],
    updates: dict[str, str],
) -> list[tuple[bytes, bytes]]:
    lowered_keys = {k.lower().encode("latin-1") for k in updates}
    filtered = [(name, val) for name, val in headers if name.lower() not in lowered_keys]
    for name, val in updates.items():
        filtered.append((name.lower().encode("latin-1"), val.encode("latin-1")))
    return filtered


async def _read_request_body(receive: Receive) -> tuple[bytes, list[Message]]:
    chunks: list[bytes] = []
    extra_messages: list[Message] = []
    while True:
        message = await receive()
        msg_type = message["type"]
        if msg_type == "http.request":
            chunk = message.get("body", b"")
            if chunk:
                chunks.append(chunk)
            if not message.get("more_body", False):
                break
        else:
            extra_messages.append(message)
            if msg_type == "http.disconnect":
                break
    return b"".join(chunks), extra_messages


def _make_replay_receive(
    raw_body: bytes,
    extra_messages: list[Message],
    original_receive: Receive,
) -> Receive:
    sent_body = False
    pending = list(extra_messages)

    async def replay_receive() -> Message:
        nonlocal sent_body
        if not sent_body:
            sent_body = True
            return {"type": "http.request", "body": raw_body, "more_body": False}
        if pending:
            return pending.pop(0)
        return await original_receive()

    return replay_receive


def _parse_jsonrpc_body(raw_body: bytes) -> tuple[str | int | None, str, Any]:
    if not raw_body:
        return None, "", None
    try:
        parsed = json.loads(raw_body)
    except (ValueError, UnicodeDecodeError):
        return None, "", None
    if not isinstance(parsed, dict):
        return None, "", None
    raw_id = parsed.get("id")
    rpc_id = raw_id if isinstance(raw_id, str | int) and not isinstance(raw_id, bool) else None
    raw_method = parsed.get("method")
    method_name = raw_method if isinstance(raw_method, str) else ""
    return rpc_id, method_name, parsed.get("params")


def _jsonrpc_error_payload(
    *,
    rpc_id: str | int | None,
    code: int,
    message: str,
    reason: str,
) -> bytes:
    payload = {
        "jsonrpc": "2.0",
        "id": rpc_id if rpc_id is not None else "server-error",
        "error": {
            "code": code,
            "message": message,
            "data": {"reason": reason},
        },
    }
    return json.dumps(payload).encode("utf-8")


async def _send_json_response(
    send: Send,
    *,
    status_code: int,
    body: bytes,
    headers: dict[str, str],
) -> None:
    raw_headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    for k, v in headers.items():
        raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": raw_headers,
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


@dataclass
class _RequestOutcome:
    """Mutable per-request state captured for Audit Event and OTel span emission."""

    request_id: str
    trace_id: str
    run_id: str | None = None
    assertion: InternalIdentityAssertion | None = None
    tool_name: str | None = None
    status_code: int = 500
    policy_action: str = "error"
    outcome: str = "error"
    triggered_rules: list[str] | None = None


class AuditEmitter:
    """Structured 1-line JSON logger and optional injectable Audit Event sink."""

    def __init__(
        self,
        audit_sink: AuditSink | None = None,
        *,
        logger_name: str = MCP_AUDIT_LOGGER_NAME,
    ) -> None:
        self._audit_sink = audit_sink
        self._logger = logging.getLogger(logger_name)

    async def emit(self, event: AuditEvent) -> None:
        """Emit one privacy-safe JSON Audit Event to the logger and optional sink."""
        self._logger.info(event.model_dump_json())
        if self._audit_sink is None:
            return
        if isinstance(self._audit_sink, list):
            self._audit_sink.append(event)
            return
        result = self._audit_sink(event)
        if inspect.isawaitable(result):
            await result


class MCPGuardAndAuditMiddleware:
    """Pure ASGI L7 zero-trust guard, RBAC, loop cap, timeout, and Audit middleware for /mcp."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: MCPRuntimeSettings,
        loaded_policy: LoadedPolicyBundle,
        emitter: AuditEmitter,
        redis_client: Any | None,
        tracer_provider: TracerProvider,
    ) -> None:
        self.app = app
        self.settings = settings
        self.loaded_policy = loaded_policy
        self.emitter = emitter
        self.redis_client = redis_client
        self.tracer_provider = tracer_provider

    def _authorize_tool_call(
        self,
        *,
        assertion: InternalIdentityAssertion,
        tool_name: str,
        arguments: Any,
    ) -> str | None:
        team_policy = self.loaded_policy.bundle.teams.get(assertion.team)
        if team_policy is None:
            return "team_not_allowed"
        allowed_tools = team_policy.mcp_tool_allowlist.get(assertion.role, ())
        if tool_name not in allowed_tools:
            return "mcp_tool_not_allowed"
        if (
            tool_name == "check_model_catalog"
            and assertion.role != "admin"
            and isinstance(arguments, dict)
            and isinstance(arguments.get("team"), str)
        ):
            requested_team = arguments["team"].strip()
            if requested_team != assertion.team:
                return "mcp_cross_team_denied"
        return None

    async def _send_rejection(
        self,
        send: Send,
        *,
        state: _RequestOutcome,
        extra_headers: dict[str, str],
        status_code: int,
        rpc_id: str | int | None,
        rpc_code: int,
        message: str,
        reason: str,
        policy_action: str,
        outcome: str,
    ) -> None:
        state.status_code = status_code
        state.policy_action = policy_action
        state.outcome = outcome
        state.triggered_rules = [reason]
        extra_headers["x-policy-denial-reason"] = reason
        await _send_json_response(
            send,
            status_code=status_code,
            body=_jsonrpc_error_payload(
                rpc_id=rpc_id,
                code=rpc_code,
                message=message,
                reason=reason,
            ),
            headers=extra_headers,
        )

    async def _authenticate_request(
        self,
        headers: list[tuple[bytes, bytes]] | tuple[tuple[bytes, bytes], ...],
        send: Send,
        *,
        state: _RequestOutcome,
        extra_headers: dict[str, str],
    ) -> InternalIdentityAssertion | None:
        secret = self.settings.internal_identity_secret
        if not _is_secret_configured(secret):
            await self._send_rejection(
                send,
                state=state,
                extra_headers=extra_headers,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                rpc_id=None,
                rpc_code=_JSONRPC_INTERNAL_ERROR,
                message="MCP Runtime internal identity secret is not configured",
                reason="internal_identity_secret_unconfigured",
                policy_action="error",
                outcome="internal_auth_unconfigured",
            )
            return None

        assert secret is not None
        raw_assertion = _get_header(headers, INTERNAL_IDENTITY_HEADER)
        try:
            return verify_internal_identity_assertion(
                raw_assertion,
                secret=secret,
                leeway_seconds=self.settings.internal_identity_leeway_seconds,
            )
        except InternalIdentityError as exc:
            await self._send_rejection(
                send,
                state=state,
                extra_headers=extra_headers,
                status_code=status.HTTP_401_UNAUTHORIZED,
                rpc_id=None,
                rpc_code=_JSONRPC_AUTH_ERROR,
                message=exc.message,
                reason=exc.code,
                policy_action="deny",
                outcome="auth_denied",
            )
            return None

    async def _enforce_tool_call_guards(
        self,
        send: Send,
        *,
        assertion: InternalIdentityAssertion,
        params: dict[str, Any],
        rpc_id: str | int | None,
        state: _RequestOutcome,
        extra_headers: dict[str, str],
    ) -> bool:
        raw_tool_name = params.get("name")
        tool_name = raw_tool_name.strip() if isinstance(raw_tool_name, str) else ""
        if not tool_name:
            await self._send_rejection(
                send,
                state=state,
                extra_headers=extra_headers,
                status_code=status.HTTP_403_FORBIDDEN,
                rpc_id=rpc_id,
                rpc_code=_JSONRPC_RBAC_ERROR,
                message="MCP Tool name is missing or invalid",
                reason="mcp_tool_not_allowed",
                policy_action="deny",
                outcome="rbac_denied",
            )
            return False

        state.tool_name = tool_name
        denial_reason = self._authorize_tool_call(
            assertion=assertion,
            tool_name=tool_name,
            arguments=params.get("arguments"),
        )
        if denial_reason is not None:
            await self._send_rejection(
                send,
                state=state,
                extra_headers=extra_headers,
                status_code=status.HTTP_403_FORBIDDEN,
                rpc_id=rpc_id,
                rpc_code=_JSONRPC_RBAC_ERROR,
                message=(
                    f"Actor '{assertion.actor_id}' ({assertion.team}/{assertion.role}) "
                    f"is denied MCP Tool '{tool_name}': {denial_reason}"
                ),
                reason=denial_reason,
                policy_action="deny",
                outcome="rbac_denied",
            )
            return False

        defaults = self.loaded_policy.bundle.defaults
        max_calls = (
            self.settings.max_tool_calls_per_run
            if self.settings.max_tool_calls_per_run is not None
            else defaults.mcp_max_tool_calls_per_run
        )
        run_ttl = (
            self.settings.run_ttl_seconds
            if self.settings.run_ttl_seconds is not None
            else defaults.mcp_run_ttl_seconds
        )
        try:
            loop_decision = await consume_run_tool_call(
                team=assertion.team,
                run_id=assertion.run_id,
                max_calls=max_calls,
                ttl_seconds=run_ttl,
                redis_client=self.redis_client,
                require_redis=self.settings.require_redis,
                timeout_seconds=self.settings.redis_socket_timeout_seconds,
            )
        except MCPRuntimeUnavailableError:
            await self._send_rejection(
                send,
                state=state,
                extra_headers=extra_headers,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                rpc_id=rpc_id,
                rpc_code=_JSONRPC_INTERNAL_ERROR,
                message="Redis is unavailable for MCP Run loop-cap enforcement",
                reason="redis_unavailable",
                policy_action="error",
                outcome="redis_unavailable",
            )
            return False

        extra_headers["x-mcp-run-calls"] = str(loop_decision.current_calls)
        extra_headers["x-mcp-run-limit"] = str(loop_decision.max_calls)
        if not loop_decision.allowed:
            await self._send_rejection(
                send,
                state=state,
                extra_headers=extra_headers,
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                rpc_id=rpc_id,
                rpc_code=_JSONRPC_LOOP_CAP_ERROR,
                message=(
                    f"Run '{assertion.run_id}' exceeded max MCP Tool calls "
                    f"({loop_decision.max_calls})"
                ),
                reason="mcp_run_loop_cap_exceeded",
                policy_action="deny",
                outcome="loop_capped",
            )
            return False
        return True

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or not _is_mcp_path(path):
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", ())
        started_at = time.perf_counter()
        request_id = _get_header(headers, "x-request-id") or uuid.uuid4().hex
        header_run_id = _get_header(headers, "x-run-id")
        parent_ctx = extract_trace_context(headers)
        tracer = self.tracer_provider.get_tracer("mcp_runtime.telemetry")

        with tracer.start_as_current_span(
            "mcp.request",
            context=parent_ctx,
            kind=SpanKind.SERVER,
        ) as span:
            span_ctx = span.get_span_context()
            span_trace_id = f"{span_ctx.trace_id:032x}" if span_ctx.is_valid else None
            initial_trace_id = span_trace_id or extract_trace_id(headers)

            state = _RequestOutcome(
                request_id=request_id,
                trace_id=initial_trace_id,
                run_id=header_run_id,
            )
            extra_headers: dict[str, str] = {
                "x-policy-version": self.loaded_policy.policy_version,
                "x-trace-id": initial_trace_id,
            }
            if header_run_id:
                extra_headers["x-run-id"] = header_run_id

            had_exception = False
            try:
                assertion = await self._authenticate_request(
                    headers,
                    send,
                    state=state,
                    extra_headers=extra_headers,
                )
                if assertion is None:
                    return

                state.assertion = assertion
                state.run_id = assertion.run_id
                state.trace_id = span_trace_id or extract_trace_id(
                    headers,
                    fallback_trace_id=assertion.trace_id,
                )
                extra_headers["x-trace-id"] = state.trace_id
                extra_headers["x-run-id"] = assertion.run_id

                rpc_id: str | int | None = None
                method_name = ""
                params: Any = None
                downstream_receive = receive
                if scope.get("method", "").upper() == "POST":
                    raw_body, extra_messages = await _read_request_body(receive)
                    downstream_receive = _make_replay_receive(raw_body, extra_messages, receive)
                    rpc_id, method_name, params = _parse_jsonrpc_body(raw_body)

                is_tool_call = method_name == "tools/call" and isinstance(params, dict)
                if is_tool_call:
                    allowed = await self._enforce_tool_call_guards(
                        send,
                        assertion=assertion,
                        params=params,
                        rpc_id=rpc_id,
                        state=state,
                        extra_headers=extra_headers,
                    )
                    if not allowed:
                        return

                captured_status = 200
                response_started = False

                async def send_wrapper(message: Message) -> None:
                    nonlocal captured_status, response_started
                    if message["type"] == "http.response.start":
                        response_started = True
                        captured_status = int(message["status"])
                        patched = dict(message)
                        patched["headers"] = _upsert_response_headers(
                            list(message.get("headers", ())),
                            extra_headers,
                        )
                        await send(patched)
                        return
                    await send(message)

                timeout_seconds = (
                    self.settings.tool_timeout_seconds
                    if self.settings.tool_timeout_seconds is not None
                    else self.loaded_policy.bundle.defaults.mcp_tool_timeout_seconds
                )
                ctx_token = ACTOR_ASSERTION_CTX.set(assertion)
                try:
                    if is_tool_call:
                        await asyncio.wait_for(
                            self.app(scope, downstream_receive, send_wrapper),
                            timeout=timeout_seconds,
                        )
                    else:
                        await self.app(scope, downstream_receive, send_wrapper)
                except TimeoutError:
                    if not response_started:
                        await self._send_rejection(
                            send,
                            state=state,
                            extra_headers=extra_headers,
                            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                            rpc_id=rpc_id,
                            rpc_code=_JSONRPC_TIMEOUT_ERROR,
                            message=(
                                f"MCP Tool '{state.tool_name}' timed out after {timeout_seconds}s"
                            ),
                            reason="mcp_tool_timeout",
                            policy_action="error",
                            outcome="timed_out",
                        )
                    return
                finally:
                    ACTOR_ASSERTION_CTX.reset(ctx_token)

                state.status_code = captured_status
                if captured_status >= 500:
                    state.policy_action = "error"
                    state.outcome = "error"
                elif captured_status >= 400:
                    state.policy_action = "deny"
                    state.outcome = "denied"
                else:
                    state.policy_action = "allow"
                    state.outcome = "allowed"
            except BaseException as exc:
                had_exception = True
                state.status_code = 500
                state.policy_action = "error"
                state.outcome = "error"
                if span.is_recording():
                    span.set_attribute("error.type", type(exc).__name__)
                    span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                raise
            finally:
                latency_ms = round(max(0.0, (time.perf_counter() - started_at) * 1000.0), 3)
                actor = state.assertion
                event = AuditEvent(
                    trace_id=state.trace_id,
                    request_id=state.request_id,
                    actor_id=actor.actor_id if actor is not None else "anonymous",
                    team=actor.team if actor is not None else "unknown",
                    role=actor.role if actor is not None else "anonymous",
                    tool_name=state.tool_name,
                    run_id=state.run_id,
                    policy_version=self.loaded_policy.policy_version,
                    policy_action=state.policy_action,
                    triggered_rules=list(state.triggered_rules or ()),
                    latency_ms=latency_ms,
                    status_code=state.status_code,
                    outcome=state.outcome,
                )
                annotate_mcp_span(span, event=event, had_exception=had_exception)
                await self.emitter.emit(event)


def create_app(
    settings: MCPRuntimeSettings | None = None,
    *,
    audit_sink: AuditSink | None = None,
    redis_client: Any | None = None,
    tracer_provider: TracerProvider | None = None,
    tool_delay_seconds: float | None = None,
) -> FastAPI:
    """Create the Guarded MCP Runtime FastAPI application."""
    resolved_settings = settings or MCPRuntimeSettings()
    loaded_policy = load_policy_bundle(resolved_settings.policy_bundle_path)
    audit_emitter = AuditEmitter(audit_sink)
    resolved_delay = (
        tool_delay_seconds
        if tool_delay_seconds is not None
        else resolved_settings.tool_delay_seconds
    )

    owns_tracer_provider = False
    if tracer_provider is not None:
        resolved_tracer_provider = tracer_provider
    else:
        otlp_provider = init_tracer_provider(resolved_settings)
        if otlp_provider is not None:
            resolved_tracer_provider = otlp_provider
            owns_tracer_provider = True
        else:
            resolved_tracer_provider = trace.NoOpTracerProvider()

    owns_redis_client = False
    resolved_redis_client = redis_client
    if resolved_redis_client is None and resolved_settings.redis_url:
        resolved_redis_client = aioredis.from_url(
            resolved_settings.redis_url,
            decode_responses=True,
            socket_timeout=resolved_settings.redis_socket_timeout_seconds,
            socket_connect_timeout=resolved_settings.redis_socket_timeout_seconds,
        )
        owns_redis_client = True

    mcp, mcp_asgi_app = build_mcp_server(
        loaded_policy=loaded_policy,
        tool_delay_seconds=resolved_delay,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            async with mcp.session_manager.run():
                yield
        finally:
            if owns_redis_client and resolved_redis_client is not None:
                await resolved_redis_client.aclose()
            if owns_tracer_provider:
                shutdown = getattr(resolved_tracer_provider, "shutdown", None)
                if callable(shutdown):
                    shutdown()

    app = FastAPI(
        title="AI Enablement Gateway — Guarded MCP Runtime",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.policy_bundle = loaded_policy
    app.state.audit_emitter = audit_emitter
    app.state.redis_client = resolved_redis_client
    app.state.tracer_provider = resolved_tracer_provider
    app.state.mcp = mcp

    app.add_middleware(
        MCPGuardAndAuditMiddleware,
        settings=resolved_settings,
        loaded_policy=loaded_policy,
        emitter=audit_emitter,
        redis_client=resolved_redis_client,
        tracer_provider=resolved_tracer_provider,
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        bundle_state: LoadedPolicyBundle | None = getattr(app.state, "policy_bundle", None)
        if bundle_state is None:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "not_ready", "reason": "policy_not_loaded"},
            )
        if not _is_secret_configured(resolved_settings.internal_identity_secret):
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "not_ready", "reason": "internal_identity_unconfigured"},
            )
        current_redis = getattr(app.state, "redis_client", None)
        if resolved_settings.require_redis or current_redis is not None:
            try:
                await ensure_redis_ready(
                    current_redis,
                    timeout_seconds=resolved_settings.redis_socket_timeout_seconds,
                )
            except MCPRuntimeUnavailableError:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"status": "not_ready", "reason": "redis_unavailable"},
                )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "ready", "policy_version": bundle_state.policy_version},
        )

    app.mount("/", mcp_asgi_app)
    return app
