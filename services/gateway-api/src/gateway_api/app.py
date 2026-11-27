"""Control Plane FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from opentelemetry import trace
from opentelemetry.trace import TracerProvider

from gateway_api.audit import AUDIT_LOGGER_NAME, AuditEmitter, AuditMiddleware, AuditSink
from gateway_api.auth import AuthVerifier, GatewayAuthError, authenticate_and_authorize
from gateway_api.config import ControlPlaneSettings
from gateway_api.guardrails import GuardrailDeniedError, evaluate_guardrails
from gateway_api.mcp_proxy import forward_mcp_request
from gateway_api.quotas import (
    GatewayQuotaError,
    ensure_redis_ready,
    reconcile_non_streaming_response,
    reconcile_quota,
    reserve_quota,
    wrap_streaming_response,
)
from gateway_api.router_client import forward_chat_completion
from gateway_api.telemetry import ControlPlaneMetrics, init_tracer_provider
from platform_common import (
    ChatCompletionRequest,
    LoadedPolicyBundle,
    build_openai_error,
    load_policy_bundle,
)


def create_app(
    settings: ControlPlaneSettings | None = None,
    *,
    model_router_transport: httpx.AsyncBaseTransport | None = None,
    http_client: httpx.AsyncClient | None = None,
    mcp_runtime_transport: httpx.AsyncBaseTransport | None = None,
    mcp_http_client: httpx.AsyncClient | None = None,
    audit_sink: AuditSink | None = None,
    redis_client: Any | None = None,
    tracer_provider: TracerProvider | None = None,
    metrics: ControlPlaneMetrics | None = None,
) -> FastAPI:
    """Create a Control Plane FastAPI application with an atomically loaded Policy Bundle."""
    resolved_settings = settings or ControlPlaneSettings()
    loaded_policy: LoadedPolicyBundle = load_policy_bundle(resolved_settings.policy_bundle_path)
    auth_verifier = AuthVerifier(resolved_settings)
    audit_emitter = AuditEmitter(audit_sink, logger_name=AUDIT_LOGGER_NAME)
    resolved_metrics = metrics or ControlPlaneMetrics()
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
    owns_http_client = http_client is None
    owns_mcp_http_client = mcp_http_client is None
    owns_redis_client = False

    resolved_http_client = http_client or httpx.AsyncClient(
        base_url=resolved_settings.model_router_base_url.rstrip("/"),
        timeout=httpx.Timeout(resolved_settings.model_router_timeout_seconds),
        transport=model_router_transport,
    )
    resolved_mcp_http_client = mcp_http_client or httpx.AsyncClient(
        base_url=resolved_settings.mcp_runtime_base_url.rstrip("/"),
        timeout=httpx.Timeout(resolved_settings.mcp_runtime_timeout_seconds),
        transport=mcp_runtime_transport,
    )

    resolved_redis_client = redis_client
    if resolved_redis_client is None and resolved_settings.redis_url:
        resolved_redis_client = aioredis.from_url(
            resolved_settings.redis_url,
            decode_responses=True,
            socket_timeout=resolved_settings.redis_socket_timeout_seconds,
            socket_connect_timeout=resolved_settings.redis_socket_timeout_seconds,
        )
        owns_redis_client = True

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owns_http_client and not resolved_http_client.is_closed:
                await resolved_http_client.aclose()
            if owns_mcp_http_client and not resolved_mcp_http_client.is_closed:
                await resolved_mcp_http_client.aclose()
            if owns_redis_client and resolved_redis_client is not None:
                await resolved_redis_client.aclose()
            if owns_tracer_provider:
                shutdown = getattr(resolved_tracer_provider, "shutdown", None)
                if callable(shutdown):
                    shutdown()

    app = FastAPI(
        title="AI Enablement Gateway — Control Plane",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.policy_bundle = loaded_policy
    app.state.auth_verifier = auth_verifier
    app.state.audit_emitter = audit_emitter
    app.state.metrics = resolved_metrics
    app.state.tracer_provider = resolved_tracer_provider
    app.state.http_client = resolved_http_client
    app.state.mcp_http_client = resolved_mcp_http_client
    app.state.redis_client = resolved_redis_client

    app.add_middleware(
        AuditMiddleware,
        emitter=audit_emitter,
        loaded_policy=loaded_policy,
        metrics=resolved_metrics,
        tracer_provider=resolved_tracer_provider,
    )

    @app.exception_handler(GatewayAuthError)
    async def handle_gateway_auth_error(
        request: Request,
        exc: GatewayAuthError,
    ) -> JSONResponse:
        request.state.policy_action = "deny"
        if request.url.path == "/mcp":
            request.state.outcome = (
                "auth_denied" if exc.status_code == status.HTTP_401_UNAUTHORIZED else "rbac_denied"
            )
        reason = exc.denial_reason or exc.code
        if reason:
            request.state.triggered_rules = [reason]
            if exc.status_code == status.HTTP_403_FORBIDDEN:
                request.state.policy_denial_reason = reason
        headers = {"x-policy-version": loaded_policy.policy_version}
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            headers["www-authenticate"] = "Bearer"
        if exc.denial_reason:
            headers["x-policy-denial-reason"] = exc.denial_reason
        return JSONResponse(
            status_code=exc.status_code,
            content=build_openai_error(
                exc.message,
                exc.error_type,
                code=exc.code,
                param=exc.param,
            ),
            headers=headers,
        )

    @app.exception_handler(GuardrailDeniedError)
    async def handle_guardrail_denied_error(
        request: Request,
        exc: GuardrailDeniedError,
    ) -> JSONResponse:
        request.state.policy_denial_reason = exc.rule_id
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=build_openai_error(
                exc.message,
                exc.error_type,
                code=exc.code,
                param=exc.param,
            ),
            headers={
                "x-policy-version": loaded_policy.policy_version,
                "x-policy-denial-reason": exc.rule_id,
            },
        )

    @app.exception_handler(GatewayQuotaError)
    async def handle_gateway_quota_error(
        request: Request,
        exc: GatewayQuotaError,
    ) -> JSONResponse:
        request.state.policy_action = (
            "error" if exc.status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR else "deny"
        )
        reason = exc.denial_reason or exc.code
        if reason:
            existing_rules = list(getattr(request.state, "triggered_rules", None) or ())
            if reason not in existing_rules:
                existing_rules.append(reason)
            request.state.triggered_rules = existing_rules
            if exc.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_429_TOO_MANY_REQUESTS):
                request.state.policy_denial_reason = reason
        headers = {"x-policy-version": loaded_policy.policy_version, **exc.headers}
        if exc.denial_reason and "x-policy-denial-reason" not in headers:
            headers["x-policy-denial-reason"] = exc.denial_reason
        return JSONResponse(
            status_code=exc.status_code,
            content=build_openai_error(
                exc.message,
                exc.error_type,
                code=exc.code,
            ),
            headers=headers,
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics_endpoint() -> Response:
        payload, media_type = resolved_metrics.render_latest()
        return Response(content=payload, media_type=media_type)

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        bundle_state: LoadedPolicyBundle | None = getattr(app.state, "policy_bundle", None)
        if bundle_state is None:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=build_openai_error(
                    "Policy Bundle is not loaded",
                    "service_unavailable_error",
                    code="policy_not_loaded",
                ),
            )
        current_redis = getattr(app.state, "redis_client", None)
        if resolved_settings.require_redis or current_redis is not None:
            try:
                await ensure_redis_ready(
                    current_redis,
                    timeout_seconds=resolved_settings.redis_socket_timeout_seconds,
                )
            except GatewayQuotaError as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content=build_openai_error(
                        exc.message,
                        exc.error_type,
                        code=exc.code,
                    ),
                )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "ready",
                "policy_version": bundle_state.policy_version,
            },
        )

    @app.post("/v1/chat/completions")
    async def chat_completions(
        payload: ChatCompletionRequest,
        request: Request,
    ) -> Response:
        request.state.requested_model = payload.model
        request.state.stream = bool(payload.stream)
        effective_model = await authenticate_and_authorize(request, payload.model)
        decision = evaluate_guardrails(payload, loaded_policy.bundle)
        request.state.policy_action = decision.policy_action
        request.state.triggered_rules = list(decision.triggered_rules)
        request.state.redacted_entity_types = list(decision.redacted_entity_types)
        request.state.prompt_sha256 = decision.prompt_sha256
        if decision.policy_action == "deny":
            raise GuardrailDeniedError(decision)

        target_model = getattr(request.state, "target_model", None) or effective_model
        current_redis = getattr(app.state, "redis_client", None)
        reservation = await reserve_quota(
            request=request,
            payload=decision.sanitized_payload,
            actor=request.state.actor,
            model_alias=target_model,
            loaded_policy=loaded_policy,
            redis_client=current_redis,
            require_redis=resolved_settings.require_redis,
            timeout_seconds=resolved_settings.redis_socket_timeout_seconds,
        )
        try:
            response = await forward_chat_completion(
                payload=decision.sanitized_payload,
                request=request,
                settings=resolved_settings,
                http_client=resolved_http_client,
                policy_version=loaded_policy.policy_version,
                target_model=target_model,
            )
        except BaseException:
            if reservation is not None:
                with anyio.CancelScope(shield=True):
                    await reconcile_quota(
                        request=request,
                        reservation=reservation,
                        redis_client=current_redis,
                        timeout_seconds=resolved_settings.redis_socket_timeout_seconds,
                        prompt_tokens=0,
                        completion_tokens=0,
                    )
            raise

        if reservation is not None:
            if isinstance(response, StreamingResponse):
                return wrap_streaming_response(
                    request=request,
                    response=response,
                    reservation=reservation,
                    redis_client=current_redis,
                    timeout_seconds=resolved_settings.redis_socket_timeout_seconds,
                )
            await reconcile_non_streaming_response(
                request=request,
                response=response,
                reservation=reservation,
                redis_client=current_redis,
                timeout_seconds=resolved_settings.redis_socket_timeout_seconds,
            )
        return response

    @app.api_route("/mcp", methods=["POST", "GET", "DELETE"])
    async def mcp_endpoint(request: Request) -> Response:
        return await forward_mcp_request(request)

    return app
