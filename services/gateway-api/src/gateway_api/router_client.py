"""Model Router HTTP forwarding, header telemetry extraction, and SSE usage tracking."""

from __future__ import annotations

import asyncio
import codecs
import json
import time
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

from gateway_api.config import ControlPlaneSettings
from gateway_api.telemetry import inject_trace_headers
from platform_common import ChatCompletionRequest, build_openai_error


@dataclass(frozen=True, slots=True)
class RoutingMetadata:
    """Routing and failover outcome extracted from Model Router response headers."""

    routed_model: str
    fallback_used: bool
    attempted_fallbacks: int = 0


def build_model_router_headers(
    request: Request,
    settings: ControlPlaneSettings,
) -> dict[str, str]:
    """Build outbound headers for the Model Router, never forwarding caller Credentials."""
    headers: dict[str, str] = {"content-type": "application/json"}
    if settings.model_router_api_key:
        headers["authorization"] = f"Bearer {settings.model_router_api_key}"
    if settings.mock_mode_enabled:
        mock_behavior = request.headers.get("x-mock-behavior")
        if mock_behavior:
            headers["x-mock-behavior"] = mock_behavior
    inject_trace_headers(headers, request_headers=request.headers)
    return headers


def prepare_model_router_payload(
    payload: ChatCompletionRequest,
    *,
    target_model: str | None = None,
) -> dict[str, Any]:
    """Serialize outgoing payload and enforce stream_options.include_usage on streams."""
    body = payload.model_dump(exclude_none=True)
    body["model"] = target_model or payload.model
    if payload.stream:
        stream_options = dict(body.get("stream_options") or {})
        stream_options["include_usage"] = True
        body["stream_options"] = stream_options
    return body


def extract_routing_metadata(
    headers: Mapping[str, str],
    target_model: str,
) -> RoutingMetadata:
    """Extract routed_model and fallback_used from LiteLLM Proxy response headers."""
    normalized = httpx.Headers(headers)
    raw_fallbacks = (normalized.get("x-litellm-attempted-fallbacks") or "").strip()
    try:
        attempted_fallbacks = int(raw_fallbacks) if raw_fallbacks else 0
    except ValueError:
        attempted_fallbacks = 0

    routed_model = (
        (normalized.get("x-litellm-model-id") or "").strip()
        or (normalized.get("x-litellm-model-group") or "").strip()
        or target_model
    )
    return RoutingMetadata(
        routed_model=routed_model,
        fallback_used=attempted_fallbacks > 0,
        attempted_fallbacks=attempted_fallbacks,
    )


def routing_response_headers(metadata: RoutingMetadata) -> dict[str, str]:
    """Format public Control Plane routing telemetry response headers."""
    return {
        "x-routed-model": metadata.routed_model,
        "x-fallback-used": "true" if metadata.fallback_used else "false",
    }


def _initialize_request_telemetry(request: Request) -> None:
    request.state.routed_model = None
    request.state.fallback_used = False
    request.state.attempted_fallbacks = 0
    request.state.prompt_tokens = None
    request.state.completion_tokens = None
    request.state.total_tokens = None
    request.state.streamed_completion_chars = 0
    request.state.upstream_duration_seconds = 0.0


def _record_routing_metadata(request: Request, metadata: RoutingMetadata) -> None:
    request.state.routed_model = metadata.routed_model
    request.state.fallback_used = metadata.fallback_used
    request.state.attempted_fallbacks = metadata.attempted_fallbacks


def _record_usage(request: Request, usage: Mapping[str, Any]) -> None:
    prompt_tokens = usage.get("prompt_tokens")
    completion_tokens = usage.get("completion_tokens")
    total_tokens = usage.get("total_tokens")
    if isinstance(prompt_tokens, int) and not isinstance(prompt_tokens, bool):
        request.state.prompt_tokens = prompt_tokens
    if isinstance(completion_tokens, int) and not isinstance(completion_tokens, bool):
        request.state.completion_tokens = completion_tokens
    if isinstance(total_tokens, int) and not isinstance(total_tokens, bool):
        request.state.total_tokens = total_tokens
    elif isinstance(request.state.prompt_tokens, int) and isinstance(
        request.state.completion_tokens, int
    ):
        request.state.total_tokens = request.state.prompt_tokens + request.state.completion_tokens


def _record_json_usage(request: Request, content: bytes) -> None:
    try:
        parsed = json.loads(content)
    except (ValueError, UnicodeDecodeError):
        return
    if isinstance(parsed, dict):
        usage = parsed.get("usage")
        if isinstance(usage, Mapping):
            _record_usage(request, usage)


def _process_sse_line(request: Request, raw_line: str) -> None:
    line = raw_line.rstrip("\r")
    if not line.startswith("data:"):
        return
    payload_str = line[5:].strip()
    if not payload_str or payload_str == "[DONE]":
        return
    try:
        event = json.loads(payload_str)
    except ValueError:
        return
    if not isinstance(event, dict):
        return

    choices = event.get("choices")
    if isinstance(choices, list):
        for choice in choices:
            if isinstance(choice, dict):
                delta = choice.get("delta")
                if isinstance(delta, dict):
                    content = delta.get("content")
                    if isinstance(content, str):
                        request.state.streamed_completion_chars += len(content)

    usage = event.get("usage")
    if isinstance(usage, Mapping):
        _record_usage(request, usage)


class _SSETelemetryScanner:
    """Incrementally scan SSE lines for usage and character count without buffering output."""

    def __init__(self, request: Request) -> None:
        self._request = request
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._buffer = ""

    def feed(self, chunk: bytes) -> None:
        self._buffer += self._decoder.decode(chunk, final=False)
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            _process_sse_line(self._request, line)

    def flush(self) -> None:
        self._buffer += self._decoder.decode(b"", final=True)
        if self._buffer:
            for line in self._buffer.split("\n"):
                if line:
                    _process_sse_line(self._request, line)
            self._buffer = ""


def _gateway_error_response(
    *,
    status_code: int,
    message: str,
    error_type: str,
    code: str,
    headers: dict[str, str],
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=build_openai_error(message, error_type, code=code),
        headers=headers,
    )


async def forward_chat_completion(
    *,
    payload: ChatCompletionRequest,
    request: Request,
    settings: ControlPlaneSettings,
    http_client: httpx.AsyncClient,
    policy_version: str,
    target_model: str | None = None,
) -> Response:
    """Forward a chat completion request to the Model Router and record telemetry."""
    _initialize_request_telemetry(request)
    resolved_target_model = target_model or payload.model
    forward_headers = build_model_router_headers(request, settings)
    body = prepare_model_router_payload(payload, target_model=resolved_target_model)
    base_headers = {"x-policy-version": policy_version}

    router_request = http_client.build_request(
        "POST",
        "/v1/chat/completions",
        json=body,
        headers=forward_headers,
    )
    upstream_started = time.perf_counter()
    try:
        provider_response = await asyncio.wait_for(
            http_client.send(router_request, stream=payload.stream),
            timeout=settings.model_router_timeout_seconds,
        )
    except (httpx.TimeoutException, TimeoutError):
        request.state.upstream_duration_seconds = max(0.0, time.perf_counter() - upstream_started)
        return _gateway_error_response(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            message="Model Router timed out waiting for Provider response",
            error_type="gateway_timeout_error",
            code="provider_timeout",
            headers=base_headers,
        )
    except httpx.HTTPError:
        request.state.upstream_duration_seconds = max(0.0, time.perf_counter() - upstream_started)
        return _gateway_error_response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            message="Model Router is unreachable",
            error_type="bad_gateway_error",
            code="model_router_unreachable",
            headers=base_headers,
        )

    request.state.upstream_duration_seconds = max(0.0, time.perf_counter() - upstream_started)
    metadata = extract_routing_metadata(provider_response.headers, resolved_target_model)
    _record_routing_metadata(request, metadata)
    response_headers = {**base_headers, **routing_response_headers(metadata)}

    if payload.stream:
        if provider_response.status_code >= 400:
            error_read_started = time.perf_counter()
            try:
                error_body = await provider_response.aread()
            finally:
                await provider_response.aclose()
                request.state.upstream_duration_seconds += max(
                    0.0, time.perf_counter() - error_read_started
                )
            return Response(
                content=error_body,
                status_code=provider_response.status_code,
                media_type=provider_response.headers.get("content-type", "application/json"),
                headers=response_headers,
            )

        async def stream_passthrough() -> AsyncIterator[bytes]:
            scanner = _SSETelemetryScanner(request)
            aiter = provider_response.aiter_bytes().__aiter__()
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
                    scanner.feed(chunk)
                    yield chunk
            finally:
                scanner.flush()
                close_started = time.perf_counter()
                try:
                    await provider_response.aclose()
                finally:
                    request.state.upstream_duration_seconds += max(
                        0.0, time.perf_counter() - close_started
                    )

        return StreamingResponse(
            stream_passthrough(),
            status_code=provider_response.status_code,
            media_type=provider_response.headers.get("content-type", "text/event-stream"),
            headers={**response_headers, "cache-control": "no-cache"},
        )

    if provider_response.status_code < 400:
        _record_json_usage(request, provider_response.content)

    return Response(
        content=provider_response.content,
        status_code=provider_response.status_code,
        media_type=provider_response.headers.get("content-type", "application/json"),
        headers=response_headers,
    )
