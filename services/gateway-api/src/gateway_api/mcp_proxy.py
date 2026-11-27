"""Control Plane /mcp Streamable HTTP signed-identity proxy."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator

import httpx
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

from gateway_api.auth import authenticate_request
from gateway_api.config import ControlPlaneSettings
from gateway_api.telemetry import inject_trace_headers
from platform_common import (
    INTERNAL_IDENTITY_HEADER,
    MIN_INTERNAL_IDENTITY_SECRET_BYTES,
    LoadedPolicyBundle,
    build_openai_error,
    sign_internal_identity_assertion,
)

_PROPAGATED_UPSTREAM_HEADERS = (
    "x-policy-denial-reason",
    "x-mcp-run-calls",
    "x-mcp-run-limit",
    "mcp-session-id",
)
_OPTIONAL_MCP_REQUEST_HEADERS = (
    "mcp-protocol-version",
    "mcp-session-id",
    "last-event-id",
)


def _resolve_run_id(request: Request) -> str:
    raw_run_id = request.headers.get("x-run-id")
    if isinstance(raw_run_id, str) and raw_run_id.strip():
        return raw_run_id.strip()
    return f"run-{uuid.uuid4().hex[:16]}"


def _extract_tool_name(raw_body: bytes) -> str | None:
    if not raw_body:
        return None
    try:
        parsed = json.loads(raw_body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(parsed, dict) or parsed.get("method") != "tools/call":
        return None
    params = parsed.get("params")
    if not isinstance(params, dict):
        return None
    tool_name = params.get("name")
    if isinstance(tool_name, str) and tool_name.strip():
        return tool_name.strip()
    return None


def _normalize_accept_header(raw_accept: str | None) -> str:
    parts = [part.strip() for part in (raw_accept or "").split(",") if part.strip()]
    lowered = {part.split(";", 1)[0].strip().lower() for part in parts}
    if "application/json" not in lowered:
        parts.append("application/json")
    if "text/event-stream" not in lowered:
        parts.append("text/event-stream")
    return ", ".join(parts)


def _infer_mcp_outcome(status_code: int, denial_reason: str | None) -> str:
    if status_code == 401:
        return "auth_denied"
    if status_code == 403:
        return "rbac_denied"
    if status_code == 429:
        return "loop_capped"
    if status_code == 504:
        return "timed_out"
    if status_code == 503 and denial_reason == "redis_unavailable":
        return "redis_unavailable"
    if status_code >= 500:
        return "error"
    if status_code >= 400:
        return "denied"
    return "allowed"


async def proxy_mcp_request(request: Request) -> Response:
    """Authenticate caller, mint signed internal identity assertion, and proxy /mcp."""
    settings: ControlPlaneSettings = request.app.state.settings
    loaded_policy: LoadedPolicyBundle = request.app.state.policy_bundle
    mcp_http_client: httpx.AsyncClient = request.app.state.mcp_http_client

    run_id = _resolve_run_id(request)
    request.state.run_id = run_id

    raw_body = await request.body()
    tool_name = _extract_tool_name(raw_body)
    if tool_name is not None:
        request.state.tool_name = tool_name

    actor = await authenticate_request(request)

    trace_id = str(getattr(request.state, "trace_id", "") or uuid.uuid4().hex)
    request_id = str(getattr(request.state, "request_id", "") or uuid.uuid4().hex)
    base_headers = {
        "x-policy-version": loaded_policy.policy_version,
        "x-run-id": run_id,
        "x-trace-id": trace_id,
    }

    secret = settings.internal_identity_secret
    if (
        not isinstance(secret, str)
        or len(secret.encode("utf-8")) < MIN_INTERNAL_IDENTITY_SECRET_BYTES
    ):
        request.state.policy_action = "error"
        request.state.triggered_rules = ["internal_identity_secret_unconfigured"]
        request.state.outcome = "internal_auth_unconfigured"
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=build_openai_error(
                "Internal MCP identity signing secret is not configured",
                "service_unavailable_error",
                code="internal_identity_unconfigured",
            ),
            headers=base_headers,
        )

    assertion = sign_internal_identity_assertion(
        actor=actor,
        run_id=run_id,
        trace_id=trace_id,
        secret=secret,
        ttl_seconds=settings.internal_identity_ttl_seconds,
    )

    outbound_headers: dict[str, str] = {
        INTERNAL_IDENTITY_HEADER: assertion,
        "x-run-id": run_id,
        "x-request-id": request_id,
        "content-type": request.headers.get("content-type") or "application/json",
        "accept": _normalize_accept_header(request.headers.get("accept")),
    }
    for header_name in _OPTIONAL_MCP_REQUEST_HEADERS:
        header_value = request.headers.get(header_name)
        if header_value:
            outbound_headers[header_name] = header_value
    inject_trace_headers(outbound_headers, request_headers=request.headers)

    target_path = "/mcp" if not request.url.query else f"/mcp?{request.url.query}"
    outbound_request = mcp_http_client.build_request(
        request.method,
        target_path,
        content=raw_body if raw_body else None,
        headers=outbound_headers,
    )

    upstream_started = time.perf_counter()
    try:
        upstream_response = await asyncio.wait_for(
            mcp_http_client.send(outbound_request, stream=True),
            timeout=settings.mcp_runtime_timeout_seconds,
        )
    except (httpx.TimeoutException, TimeoutError):
        request.state.upstream_duration_seconds = max(0.0, time.perf_counter() - upstream_started)
        request.state.policy_action = "error"
        request.state.triggered_rules = ["mcp_runtime_timeout"]
        request.state.outcome = "timed_out"
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content=build_openai_error(
                "Control Plane timed out waiting for MCP Runtime response",
                "gateway_timeout_error",
                code="mcp_runtime_timeout",
            ),
            headers=base_headers,
        )
    except httpx.HTTPError:
        request.state.upstream_duration_seconds = max(0.0, time.perf_counter() - upstream_started)
        request.state.policy_action = "error"
        request.state.triggered_rules = ["mcp_runtime_unreachable"]
        request.state.outcome = "upstream_unreachable"
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content=build_openai_error(
                "MCP Runtime is unreachable",
                "bad_gateway_error",
                code="mcp_runtime_unreachable",
            ),
            headers=base_headers,
        )

    request.state.upstream_duration_seconds = max(0.0, time.perf_counter() - upstream_started)
    upstream_status = upstream_response.status_code
    if upstream_status in (401, 403, 429):
        request.state.policy_action = "deny"
    elif upstream_status >= 500:
        request.state.policy_action = "error"
    else:
        request.state.policy_action = "allow"

    denial_reason = upstream_response.headers.get("x-policy-denial-reason")
    if denial_reason:
        request.state.triggered_rules = [denial_reason]
        if upstream_status in (403, 429):
            request.state.policy_denial_reason = denial_reason
    elif upstream_status in (403, 429):
        fallback_reason = (
            "mcp_run_loop_cap_exceeded" if upstream_status == 429 else "mcp_rbac_denied"
        )
        request.state.policy_denial_reason = fallback_reason
        request.state.triggered_rules = [fallback_reason]

    request.state.outcome = _infer_mcp_outcome(upstream_status, denial_reason)

    response_headers = {
        "x-policy-version": loaded_policy.policy_version,
        "x-run-id": upstream_response.headers.get("x-run-id") or run_id,
        "x-trace-id": upstream_response.headers.get("x-trace-id") or trace_id,
    }
    for header_name in _PROPAGATED_UPSTREAM_HEADERS:
        header_value = upstream_response.headers.get(header_name)
        if header_value is not None:
            response_headers[header_name] = header_value

    content_type = upstream_response.headers.get("content-type")
    if content_type and content_type.split(";", 1)[0].strip().lower() == "text/event-stream":

        async def stream_passthrough() -> AsyncIterator[bytes]:
            aiter = upstream_response.aiter_bytes().__aiter__()
            try:
                while True:
                    wait_started = time.perf_counter()
                    try:
                        chunk = await aiter.__anext__()
                    except StopAsyncIteration:
                        break
                    finally:
                        request.state.upstream_duration_seconds += max(
                            0.0, time.perf_counter() - wait_started
                        )
                    yield chunk
            finally:
                close_started = time.perf_counter()
                try:
                    await upstream_response.aclose()
                finally:
                    request.state.upstream_duration_seconds += max(
                        0.0, time.perf_counter() - close_started
                    )

        return StreamingResponse(
            stream_passthrough(),
            status_code=upstream_status,
            media_type=content_type,
            headers={**response_headers, "cache-control": "no-cache"},
        )

    read_started = time.perf_counter()
    try:
        body = await asyncio.wait_for(
            upstream_response.aread(),
            timeout=settings.mcp_runtime_timeout_seconds,
        )
    except (httpx.TimeoutException, TimeoutError):
        request.state.upstream_duration_seconds += max(0.0, time.perf_counter() - read_started)
        request.state.policy_action = "error"
        request.state.triggered_rules = ["mcp_runtime_timeout"]
        request.state.outcome = "timed_out"
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content=build_openai_error(
                "Control Plane timed out waiting for MCP Runtime response body",
                "gateway_timeout_error",
                code="mcp_runtime_timeout",
            ),
            headers=base_headers,
        )
    finally:
        await upstream_response.aclose()
        request.state.upstream_duration_seconds += max(0.0, time.perf_counter() - read_started)

    return Response(
        content=body,
        status_code=upstream_status,
        media_type=content_type,
        headers=response_headers,
    )
