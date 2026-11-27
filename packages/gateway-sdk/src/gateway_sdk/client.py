"""GovernedClient async SDK implementation built on httpx."""

from __future__ import annotations

import asyncio
import inspect
import itertools
import json
import re
import secrets
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Self, overload

import httpx

_TRACEPARENT_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_ALL_ZERO_TRACE_ID = "0" * 32
_ALL_ZERO_PARENT_ID = "0" * 16

SleepFn = Callable[[float], Awaitable[None]]
ToolPlanSpec = tuple[str, Mapping[str, Any] | None] | Mapping[str, Any] | None
ToolPlanner = Callable[[dict[str, Any]], ToolPlanSpec | Awaitable[ToolPlanSpec]]


class GatewayClientError(Exception):
    """Structured error raised on Gateway HTTP, transport, or JSON-RPC failures."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        reason: str | None = None,
        headers: Mapping[str, str] | None = None,
        payload: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.reason = reason
        self.headers: dict[str, str] = {k.lower(): v for k, v in (headers or {}).items()}
        self.payload = payload


@dataclass(frozen=True, slots=True)
class AgentLoopStep:
    """Single LLM completion + optional MCP Tool invocation within a governed Run."""

    step_index: int
    completion: dict[str, Any]
    tool_name: str | None = None
    tool_arguments: dict[str, Any] | None = None
    tool_result: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class AgentLoopResult:
    """Outcome of a bounded GovernedClient.run_agent_loop execution."""

    final_content: str | None
    run_id: str
    traceparent: str
    steps: list[AgentLoopStep]
    stopped_reason: str


def _generate_traceparent() -> str:
    return f"00-{uuid.uuid4().hex}-{secrets.token_hex(8)}-01"


def _resolve_traceparent(traceparent: str | None, *, default: str) -> str:
    if traceparent is None:
        return default
    normalized = traceparent.strip().lower()
    match = _TRACEPARENT_RE.fullmatch(normalized)
    if match is None:
        raise ValueError(f"Invalid W3C traceparent header: {traceparent!r}")
    version, trace_id, parent_id, _flags = match.groups()
    if version == "ff" or trace_id == _ALL_ZERO_TRACE_ID or parent_id == _ALL_ZERO_PARENT_ID:
        raise ValueError(f"Invalid W3C traceparent header: {traceparent!r}")
    return normalized


def _resolve_run_id(run_id: str | None, *, default: str) -> str:
    if run_id is None:
        return default
    cleaned = run_id.strip()
    if not cleaned:
        raise ValueError("run_id must be a non-empty string when provided")
    return cleaned


def _parse_json_bytes(raw: bytes) -> Any | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


def _build_error_from_response(
    response: httpx.Response,
    raw_body: bytes | None = None,
) -> GatewayClientError:
    body = response.content if raw_body is None else raw_body
    payload = _parse_json_bytes(body)
    headers = {k.lower(): v for k, v in response.headers.items()}
    reason = headers.get("x-policy-denial-reason")
    code: str | None = None
    message = f"Gateway request failed with HTTP {response.status_code}"

    if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
        err = payload["error"]
        raw_message = err.get("message")
        if isinstance(raw_message, str) and raw_message.strip():
            message = raw_message.strip()
        raw_code = err.get("code")
        if isinstance(raw_code, str) and raw_code.strip():
            code = raw_code.strip()
        elif isinstance(raw_code, int) and not isinstance(raw_code, bool):
            code = str(raw_code)
        data = err.get("data")
        if reason is None and isinstance(data, dict) and isinstance(data.get("reason"), str):
            reason = data["reason"].strip() or None

    if reason is None and code is not None:
        reason = code

    return GatewayClientError(
        message,
        status_code=response.status_code,
        code=code,
        reason=reason,
        headers=headers,
        payload=payload,
    )


def _parse_mcp_rpc_payload(response: httpx.Response) -> dict[str, Any]:
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type == "text/event-stream":
        last_obj: dict[str, Any] | None = None
        for raw_line in response.text.splitlines():
            line = raw_line.strip()
            if not line.startswith("data:"):
                continue
            data_str = line[5:].strip()
            if not data_str or data_str == "[DONE]":
                continue
            parsed_line = json.loads(data_str)
            if isinstance(parsed_line, dict):
                last_obj = parsed_line
        if last_obj is not None:
            return last_obj
        raise GatewayClientError(
            "MCP Runtime returned empty SSE JSON-RPC response",
            status_code=response.status_code,
            headers=response.headers,
            payload=response.text,
        )

    parsed = _parse_json_bytes(response.content)
    if not isinstance(parsed, dict):
        raise GatewayClientError(
            "MCP Runtime returned non-JSON response payload",
            status_code=response.status_code,
            headers=response.headers,
            payload=response.text,
        )
    return parsed


def _unwrap_mcp_tool_result(
    rpc_payload: dict[str, Any],
    *,
    response: httpx.Response,
) -> dict[str, Any]:
    if isinstance(rpc_payload.get("error"), dict):
        err = rpc_payload["error"]
        err_data = err.get("data")
        reason = (
            err_data.get("reason")
            if isinstance(err_data, dict) and isinstance(err_data.get("reason"), str)
            else response.headers.get("x-policy-denial-reason")
        )
        raw_code = err.get("code")
        code = str(raw_code) if raw_code is not None else None
        message = (
            err.get("message")
            if isinstance(err.get("message"), str) and err["message"].strip()
            else "MCP Tool JSON-RPC error"
        )
        raise GatewayClientError(
            message,
            status_code=response.status_code,
            code=code,
            reason=reason,
            headers=response.headers,
            payload=rpc_payload,
        )

    result = rpc_payload.get("result")
    if not isinstance(result, dict):
        raise GatewayClientError(
            "MCP Tool response missing JSON-RPC result object",
            status_code=response.status_code,
            headers=response.headers,
            payload=rpc_payload,
        )

    if result.get("isError"):
        error_text = "MCP Tool execution failed"
        content_items = result.get("content")
        if isinstance(content_items, list) and content_items:
            first = content_items[0]
            if isinstance(first, dict) and isinstance(first.get("text"), str):
                error_text = first["text"]
        raise GatewayClientError(
            error_text,
            status_code=response.status_code,
            code="mcp_tool_error",
            reason="mcp_tool_error",
            headers=response.headers,
            payload=rpc_payload,
        )

    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured

    content_items = result.get("content")
    if isinstance(content_items, list) and content_items:
        first = content_items[0]
        if isinstance(first, dict) and isinstance(first.get("text"), str):
            text = first["text"]
            try:
                decoded = json.loads(text)
            except ValueError:
                return {"text": text}
            if isinstance(decoded, dict):
                return decoded
            return {"value": decoded}
    return result


def _extract_assistant_content(completion: Mapping[str, Any]) -> str:
    choices = completion.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, Mapping):
        return ""
    message = first.get("message")
    if not isinstance(message, Mapping):
        return ""
    content = message.get("content")
    return content if isinstance(content, str) else ""


def _normalize_tool_plan(planned: ToolPlanSpec) -> tuple[str, dict[str, Any]]:
    if isinstance(planned, tuple) and len(planned) == 2:
        raw_name, raw_args = planned
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("Planned tool name must be a non-empty string")
        return raw_name.strip(), dict(raw_args or {})
    if isinstance(planned, Mapping):
        raw_name = planned.get("name") or planned.get("tool_name")
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("Planned tool mapping must include a non-empty 'name' or 'tool_name'")
        raw_args = planned.get("arguments")
        if raw_args is not None and not isinstance(raw_args, Mapping):
            raise TypeError("Planned tool 'arguments' must be a mapping when provided")
        return raw_name.strip(), dict(raw_args or {})
    raise TypeError(
        "tool_planner must return None, (tool_name, arguments), or {'name': ..., 'arguments': ...}"
    )


class GovernedClient:
    """Async client for governed Control Plane LLM completions and MCP Tool calls."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float | httpx.Timeout = 30.0,
        max_retries: int = 3,
        backoff_base_seconds: float = 0.1,
        run_id: str | None = None,
        traceparent: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep_fn: SleepFn | None = None,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ValueError("api_key must be a non-empty Credential string")
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if backoff_base_seconds < 0:
            raise ValueError("backoff_base_seconds must be >= 0")

        self.base_url = base_url.rstrip("/")
        self._api_key = api_key.strip()
        self.max_retries = max_retries
        self.backoff_base_seconds = backoff_base_seconds
        self.run_id = _resolve_run_id(run_id, default=f"run-{uuid.uuid4().hex[:16]}")
        self.traceparent = _resolve_traceparent(traceparent, default=_generate_traceparent())
        self._sleep: SleepFn = sleep_fn or asyncio.sleep
        self._rpc_ids = itertools.count(1)
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying httpx.AsyncClient."""
        await self._client.aclose()

    def _build_headers(
        self,
        *,
        run_id: str | None,
        traceparent: str | None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> tuple[str, str, dict[str, str]]:
        resolved_run_id = _resolve_run_id(run_id, default=self.run_id)
        resolved_traceparent = _resolve_traceparent(traceparent, default=self.traceparent)
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "X-Run-Id": resolved_run_id,
            "traceparent": resolved_traceparent,
        }
        if extra_headers:
            for key, value in extra_headers.items():
                headers[key] = value
        return resolved_run_id, resolved_traceparent, headers

    async def _send_with_retries(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any],
        headers: Mapping[str, str],
        stream: bool = False,
    ) -> httpx.Response:
        for attempt in range(self.max_retries + 1):
            request = self._client.build_request(method, path, json=json_body, headers=headers)
            try:
                response = await self._client.send(request, stream=stream)
            except httpx.TransportError as exc:
                if attempt < self.max_retries:
                    await self._sleep(self.backoff_base_seconds * (2**attempt))
                    continue
                raise GatewayClientError(f"Gateway transport error: {exc}") from exc

            if 500 <= response.status_code < 600:
                raw_body = await response.aread()
                await response.aclose()
                if attempt < self.max_retries:
                    await self._sleep(self.backoff_base_seconds * (2**attempt))
                    continue
                raise _build_error_from_response(response, raw_body)

            if response.status_code >= 400:
                raw_body = await response.aread()
                await response.aclose()
                raise _build_error_from_response(response, raw_body)

            return response

        raise AssertionError("Unreachable retry loop termination")

    @overload
    async def chat_completions(
        self,
        model: str,
        messages: Sequence[Mapping[str, Any]],
        *,
        stream: Literal[False] = False,
        max_tokens: int | None = None,
        temperature: float | None = None,
        run_id: str | None = None,
        traceparent: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]: ...

    @overload
    async def chat_completions(
        self,
        model: str,
        messages: Sequence[Mapping[str, Any]],
        *,
        stream: Literal[True],
        max_tokens: int | None = None,
        temperature: float | None = None,
        run_id: str | None = None,
        traceparent: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> AsyncIterator[dict[str, Any]]: ...

    async def chat_completions(
        self,
        model: str,
        messages: Sequence[Mapping[str, Any]],
        *,
        stream: bool = False,
        max_tokens: int | None = None,
        temperature: float | None = None,
        run_id: str | None = None,
        traceparent: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any] | AsyncIterator[dict[str, Any]]:
        """Call /v1/chat/completions (JSON or SSE stream) with retries on 5xx/transport errors."""
        payload: dict[str, Any] = {
            "model": model,
            "messages": [dict(msg) for msg in messages],
            "stream": stream,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if temperature is not None:
            payload["temperature"] = temperature

        _, _, headers = self._build_headers(
            run_id=run_id,
            traceparent=traceparent,
            extra_headers=extra_headers,
        )
        response = await self._send_with_retries(
            "POST",
            "/v1/chat/completions",
            json_body=payload,
            headers=headers,
            stream=stream,
        )
        if stream:
            return self._iter_sse_chunks(response)

        parsed = _parse_json_bytes(response.content)
        if not isinstance(parsed, dict):
            raise GatewayClientError(
                "Control Plane returned non-JSON chat completion payload",
                status_code=response.status_code,
                headers=response.headers,
                payload=response.text,
            )
        return parsed

    async def _iter_sse_chunks(self, response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
        try:
            async for raw_line in response.aiter_lines():
                line = raw_line.strip()
                if not line or line.startswith(":") or not line.startswith("data:"):
                    continue
                data_str = line[5:].strip()
                if not data_str:
                    continue
                if data_str == "[DONE]":
                    return
                try:
                    chunk = json.loads(data_str)
                except ValueError as exc:
                    raise GatewayClientError(
                        "Control Plane returned invalid JSON in SSE stream",
                        status_code=response.status_code,
                        headers=response.headers,
                        payload=data_str,
                    ) from exc
                if isinstance(chunk, dict):
                    yield chunk
        finally:
            await response.aclose()

    async def call_mcp_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        run_id: str | None = None,
        traceparent: str | None = None,
    ) -> dict[str, Any]:
        """Invoke a guarded MCP Tool via Control Plane POST /mcp JSON-RPC."""
        clean_tool = tool_name.strip()
        if not clean_tool:
            raise ValueError("tool_name must be a non-empty string")

        _, _, headers = self._build_headers(
            run_id=run_id,
            traceparent=traceparent,
            extra_headers={"Accept": "application/json, text/event-stream"},
        )
        rpc_body = {
            "jsonrpc": "2.0",
            "id": next(self._rpc_ids),
            "method": "tools/call",
            "params": {
                "name": clean_tool,
                "arguments": dict(arguments or {}),
            },
        }
        response = await self._send_with_retries(
            "POST",
            "/mcp",
            json_body=rpc_body,
            headers=headers,
            stream=False,
        )
        rpc_payload = _parse_mcp_rpc_payload(response)
        return _unwrap_mcp_tool_result(rpc_payload, response=response)

    async def run_agent_loop(
        self,
        model: str,
        messages: Sequence[Mapping[str, Any]],
        tool_planner: ToolPlanner,
        *,
        max_steps: int = 10,
        run_id: str | None = None,
        traceparent: str | None = None,
    ) -> AgentLoopResult:
        """Alternate chat_completions and call_mcp_tool under one Run and W3C trace."""
        if max_steps < 1:
            raise ValueError("max_steps must be >= 1")

        resolved_run_id = _resolve_run_id(run_id, default=self.run_id)
        resolved_traceparent = _resolve_traceparent(traceparent, default=self.traceparent)
        conversation: list[dict[str, Any]] = [dict(msg) for msg in messages]
        steps: list[AgentLoopStep] = []
        last_content: str | None = None

        for step_index in range(max_steps):
            completion = await self.chat_completions(
                model,
                conversation,
                run_id=resolved_run_id,
                traceparent=resolved_traceparent,
            )
            assistant_content = _extract_assistant_content(completion)
            last_content = assistant_content
            conversation.append({"role": "assistant", "content": assistant_content})

            planned = tool_planner(completion)
            if inspect.isawaitable(planned):
                planned = await planned

            if planned is None:
                steps.append(AgentLoopStep(step_index=step_index, completion=completion))
                return AgentLoopResult(
                    final_content=last_content,
                    run_id=resolved_run_id,
                    traceparent=resolved_traceparent,
                    steps=steps,
                    stopped_reason="completed",
                )

            tool_name, tool_args = _normalize_tool_plan(planned)
            try:
                tool_result = await self.call_mcp_tool(
                    tool_name,
                    tool_args,
                    run_id=resolved_run_id,
                    traceparent=resolved_traceparent,
                )
            except GatewayClientError as exc:
                if exc.status_code == 429 and (
                    exc.reason == "mcp_run_loop_cap_exceeded" or exc.reason is None
                ):
                    steps.append(
                        AgentLoopStep(
                            step_index=step_index,
                            completion=completion,
                            tool_name=tool_name,
                            tool_arguments=tool_args,
                            tool_result=None,
                        )
                    )
                    return AgentLoopResult(
                        final_content=last_content,
                        run_id=resolved_run_id,
                        traceparent=resolved_traceparent,
                        steps=steps,
                        stopped_reason="server_run_cap_exceeded",
                    )
                raise

            steps.append(
                AgentLoopStep(
                    step_index=step_index,
                    completion=completion,
                    tool_name=tool_name,
                    tool_arguments=tool_args,
                    tool_result=tool_result,
                )
            )
            conversation.append(
                {
                    "role": "tool",
                    "content": json.dumps(tool_result, sort_keys=True),
                }
            )

        return AgentLoopResult(
            final_content=last_content,
            run_id=resolved_run_id,
            traceparent=resolved_traceparent,
            steps=steps,
            stopped_reason="max_steps_reached",
        )
