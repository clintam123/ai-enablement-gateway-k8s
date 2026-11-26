"""Control Plane FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse

from gateway_api.audit import AuditEmitter, AuditMiddleware, AuditSink
from gateway_api.auth import AuthVerifier, GatewayAuthError, authenticate_and_authorize
from gateway_api.config import ControlPlaneSettings
from gateway_api.guardrails import GuardrailDeniedError, evaluate_guardrails
from gateway_api.router_client import forward_chat_completion
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
    audit_sink: AuditSink | None = None,
) -> FastAPI:
    """Create a Control Plane FastAPI application with an atomically loaded Policy Bundle."""
    resolved_settings = settings or ControlPlaneSettings()
    loaded_policy: LoadedPolicyBundle = load_policy_bundle(resolved_settings.policy_bundle_path)
    auth_verifier = AuthVerifier(resolved_settings)
    audit_emitter = AuditEmitter(audit_sink)
    owns_http_client = http_client is None

    resolved_http_client = http_client or httpx.AsyncClient(
        base_url=resolved_settings.model_router_base_url.rstrip("/"),
        timeout=httpx.Timeout(resolved_settings.model_router_timeout_seconds),
        transport=model_router_transport,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owns_http_client and not resolved_http_client.is_closed:
                await resolved_http_client.aclose()

    app = FastAPI(
        title="AI Enablement Gateway — Control Plane",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.policy_bundle = loaded_policy
    app.state.auth_verifier = auth_verifier
    app.state.audit_emitter = audit_emitter
    app.state.http_client = resolved_http_client

    app.add_middleware(
        AuditMiddleware,
        emitter=audit_emitter,
        loaded_policy=loaded_policy,
    )

    @app.exception_handler(GatewayAuthError)
    async def handle_gateway_auth_error(
        request: Request,
        exc: GatewayAuthError,
    ) -> JSONResponse:
        request.state.policy_action = "deny"
        reason = exc.denial_reason or exc.code
        if reason:
            request.state.triggered_rules = [reason]
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
        _request: Request,
        exc: GuardrailDeniedError,
    ) -> JSONResponse:
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

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

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
        effective_model = await authenticate_and_authorize(request, payload.model)
        decision = evaluate_guardrails(payload, loaded_policy.bundle)
        request.state.policy_action = decision.policy_action
        request.state.triggered_rules = list(decision.triggered_rules)
        request.state.redacted_entity_types = list(decision.redacted_entity_types)
        request.state.prompt_sha256 = decision.prompt_sha256
        if decision.policy_action == "deny":
            raise GuardrailDeniedError(decision)
        target_model = getattr(request.state, "target_model", None) or effective_model
        return await forward_chat_completion(
            payload=decision.sanitized_payload,
            request=request,
            settings=resolved_settings,
            http_client=resolved_http_client,
            policy_version=loaded_policy.policy_version,
            target_model=target_model,
        )

    return app
