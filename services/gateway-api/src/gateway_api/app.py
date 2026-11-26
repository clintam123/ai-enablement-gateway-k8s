"""Control Plane FastAPI application factory."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

from gateway_api.config import ControlPlaneSettings
from platform_common import (
    ChatCompletionRequest,
    LoadedPolicyBundle,
    build_openai_error,
    load_policy_bundle,
)


def _build_model_router_headers(
    request: Request,
    settings: ControlPlaneSettings,
) -> dict[str, str]:
    headers: dict[str, str] = {"content-type": "application/json"}
    if settings.model_router_api_key:
        headers["authorization"] = f"Bearer {settings.model_router_api_key}"
    if settings.mock_mode_enabled:
        mock_behavior = request.headers.get("x-mock-behavior")
        if mock_behavior:
            headers["x-mock-behavior"] = mock_behavior
    return headers


def create_app(
    settings: ControlPlaneSettings | None = None,
    *,
    model_router_transport: httpx.AsyncBaseTransport | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Create a Control Plane FastAPI application with an atomically loaded Policy Bundle."""
    resolved_settings = settings or ControlPlaneSettings()
    loaded_policy: LoadedPolicyBundle = load_policy_bundle(resolved_settings.policy_bundle_path)
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
    app.state.http_client = resolved_http_client

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
        forward_headers = _build_model_router_headers(request, resolved_settings)
        response_headers = {"x-policy-version": loaded_policy.policy_version}
        body = payload.model_dump(exclude_none=True)
        timeout_seconds = resolved_settings.model_router_timeout_seconds

        if payload.stream:
            router_request = resolved_http_client.build_request(
                "POST",
                "/v1/chat/completions",
                json=body,
                headers=forward_headers,
            )
            try:
                provider_response = await asyncio.wait_for(
                    resolved_http_client.send(router_request, stream=True),
                    timeout=timeout_seconds,
                )
            except (httpx.TimeoutException, TimeoutError):
                return JSONResponse(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    content=build_openai_error(
                        "Model Router timed out waiting for Provider response",
                        "gateway_timeout_error",
                        code="provider_timeout",
                    ),
                    headers=response_headers,
                )
            except httpx.HTTPError:
                return JSONResponse(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    content=build_openai_error(
                        "Model Router is unreachable",
                        "bad_gateway_error",
                        code="model_router_unreachable",
                    ),
                    headers=response_headers,
                )

            if provider_response.status_code >= 400:
                error_body = await provider_response.aread()
                await provider_response.aclose()
                return Response(
                    content=error_body,
                    status_code=provider_response.status_code,
                    media_type=provider_response.headers.get("content-type", "application/json"),
                    headers=response_headers,
                )

            async def stream_passthrough() -> AsyncIterator[bytes]:
                try:
                    async for chunk in provider_response.aiter_bytes():
                        yield chunk
                finally:
                    await provider_response.aclose()

            return StreamingResponse(
                stream_passthrough(),
                status_code=provider_response.status_code,
                media_type=provider_response.headers.get("content-type", "text/event-stream"),
                headers={**response_headers, "cache-control": "no-cache"},
            )

        try:
            provider_response = await asyncio.wait_for(
                resolved_http_client.post(
                    "/v1/chat/completions",
                    json=body,
                    headers=forward_headers,
                ),
                timeout=timeout_seconds,
            )
        except (httpx.TimeoutException, TimeoutError):
            return JSONResponse(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                content=build_openai_error(
                    "Model Router timed out waiting for Provider response",
                    "gateway_timeout_error",
                    code="provider_timeout",
                ),
                headers=response_headers,
            )
        except httpx.HTTPError:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content=build_openai_error(
                    "Model Router is unreachable",
                    "bad_gateway_error",
                    code="model_router_unreachable",
                ),
                headers=response_headers,
            )

        return Response(
            content=provider_response.content,
            status_code=provider_response.status_code,
            media_type=provider_response.headers.get("content-type", "application/json"),
            headers=response_headers,
        )

    return app
