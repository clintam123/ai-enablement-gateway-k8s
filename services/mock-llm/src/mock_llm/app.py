"""Deterministic OpenAI-compatible Mock Provider FastAPI application."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Literal

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from mock_llm.config import MockProviderSettings
from platform_common import (
    ChatCompletionChoice,
    ChatCompletionChunk,
    ChatCompletionChunkChoice,
    ChatCompletionChunkDelta,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    LLMTokenUsage,
    build_openai_error,
)


class FaultConfig(BaseModel):
    """Runtime fault-window configuration toggled via POST /admin/fault."""

    enabled: bool
    mode: Literal["fail_503", "timeout", "latency"] = "fail_503"
    latency_ms: int = Field(default=0, ge=0)
    duration_seconds: float | None = Field(default=None, gt=0.0)


@dataclass
class _FaultState:
    enabled: bool = False
    mode: Literal["fail_503", "timeout", "latency"] = "fail_503"
    latency_ms: int = 0
    expires_at: float | None = None

    def is_active(self) -> bool:
        if not self.enabled:
            return False
        if self.expires_at is not None and time.monotonic() >= self.expires_at:
            self.enabled = False
            self.expires_at = None
            return False
        return True


def count_llm_tokens(text: str) -> int:
    """Deterministically estimate LLM Token count using the canonical chars // 4 rule."""
    stripped = text.strip()
    if not stripped:
        return 0
    return max(1, len(stripped) // 4)


def _build_completion_text(
    provider_name: str,
    model_alias: str,
    prompt_text: str,
    max_tokens: int | None,
) -> str:
    digest = hashlib.sha256(f"{model_alias}:{prompt_text}".encode()).hexdigest()[:12]
    full_text = (
        f"[{provider_name}:{model_alias}] Deterministic completion for request digest {digest}."
    )
    if max_tokens is not None and count_llm_tokens(full_text) > max_tokens:
        max_chars = max_tokens * 4
        return full_text[:max_chars].rstrip() or full_text[:1]
    return full_text


def _build_completion_id(provider_name: str, model_alias: str, prompt_text: str) -> str:
    digest = hashlib.sha256(f"{provider_name}:{model_alias}:{prompt_text}".encode()).hexdigest()[
        :16
    ]
    return f"chatcmpl-{digest}"


def _split_stream_segments(text: str, segment_size: int = 16) -> list[str]:
    if not text:
        return []
    return [text[i : i + segment_size] for i in range(0, len(text), segment_size)]


def _parse_latency_directive(behavior: str) -> int | None:
    prefix = "latency_ms="
    if not behavior.startswith(prefix):
        return None
    raw_value = behavior.removeprefix(prefix).strip()
    if raw_value.isdigit():
        return int(raw_value)
    return None


def create_app(settings: MockProviderSettings | None = None) -> FastAPI:
    """Create a deterministic Mock Provider FastAPI application."""
    resolved_settings = settings or MockProviderSettings()
    fault_state = _FaultState()

    app = FastAPI(
        title=f"AI Enablement Gateway — Mock Provider ({resolved_settings.provider_name})",
        version="0.1.0",
    )
    app.state.settings = resolved_settings
    app.state.fault_state = fault_state

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "provider": resolved_settings.provider_name}

    @app.post("/admin/fault")
    async def configure_fault(config: FaultConfig) -> dict[str, object]:
        fault_state.enabled = config.enabled
        fault_state.mode = config.mode
        fault_state.latency_ms = config.latency_ms
        fault_state.expires_at = (
            time.monotonic() + config.duration_seconds
            if config.enabled and config.duration_seconds is not None
            else None
        )
        return {
            "provider": resolved_settings.provider_name,
            "enabled": fault_state.enabled,
            "mode": fault_state.mode,
            "latency_ms": fault_state.latency_ms,
            "duration_seconds": config.duration_seconds,
        }

    @app.post("/v1/chat/completions", response_model=None)
    async def chat_completions(
        payload: ChatCompletionRequest,
        request: Request,
    ) -> ChatCompletionResponse | Response:
        if fault_state.is_active():
            if fault_state.mode == "fail_503":
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content=build_openai_error(
                        f"Mock Provider {resolved_settings.provider_name} in fault window",
                        "service_unavailable_error",
                        code="mock_fault_503",
                    ),
                )
            if fault_state.mode == "timeout":
                await asyncio.sleep(resolved_settings.timeout_delay_ms / 1000.0)
                return JSONResponse(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    content=build_openai_error(
                        f"Mock Provider {resolved_settings.provider_name} simulated timeout",
                        "gateway_timeout_error",
                        code="provider_timeout",
                    ),
                )
            if fault_state.mode == "latency" and fault_state.latency_ms > 0:
                await asyncio.sleep(fault_state.latency_ms / 1000.0)

        if resolved_settings.mock_mode_enabled:
            behavior = request.headers.get("x-mock-behavior", "").strip()
            if behavior == "fail_503":
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content=build_openai_error(
                        f"Mock Provider {resolved_settings.provider_name} injected 503 fault",
                        "service_unavailable_error",
                        code="mock_fault_503",
                    ),
                )
            if behavior == "timeout":
                await asyncio.sleep(resolved_settings.timeout_delay_ms / 1000.0)
                return JSONResponse(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    content=build_openai_error(
                        f"Mock Provider {resolved_settings.provider_name} injected timeout",
                        "gateway_timeout_error",
                        code="provider_timeout",
                    ),
                )
            injected_latency_ms = _parse_latency_directive(behavior)
            if injected_latency_ms is not None and injected_latency_ms > 0:
                await asyncio.sleep(injected_latency_ms / 1000.0)

        if resolved_settings.base_latency_ms > 0:
            await asyncio.sleep(resolved_settings.base_latency_ms / 1000.0)

        prompt_text = "\n".join(message.content for message in payload.messages)
        prompt_tokens = sum(count_llm_tokens(message.content) for message in payload.messages)
        completion_text = _build_completion_text(
            provider_name=resolved_settings.provider_name,
            model_alias=payload.model,
            prompt_text=prompt_text,
            max_tokens=payload.max_tokens,
        )
        completion_tokens = count_llm_tokens(completion_text)
        usage = LLMTokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )
        completion_id = _build_completion_id(
            resolved_settings.provider_name, payload.model, prompt_text
        )
        created = int(time.time())

        if not payload.stream:
            return ChatCompletionResponse(
                id=completion_id,
                created=created,
                model=payload.model,
                choices=[
                    ChatCompletionChoice(
                        index=0,
                        message=ChatMessage(role="assistant", content=completion_text),
                        finish_reason="stop",
                    )
                ],
                usage=usage,
            )

        async def event_stream() -> AsyncIterator[str]:
            role_chunk = ChatCompletionChunk(
                id=completion_id,
                created=created,
                model=payload.model,
                choices=[
                    ChatCompletionChunkChoice(
                        index=0,
                        delta=ChatCompletionChunkDelta(role="assistant"),
                        finish_reason=None,
                    )
                ],
            )
            yield f"data: {role_chunk.model_dump_json(exclude_none=True)}\n\n"

            for segment in _split_stream_segments(completion_text):
                content_chunk = ChatCompletionChunk(
                    id=completion_id,
                    created=created,
                    model=payload.model,
                    choices=[
                        ChatCompletionChunkChoice(
                            index=0,
                            delta=ChatCompletionChunkDelta(content=segment),
                            finish_reason=None,
                        )
                    ],
                )
                yield f"data: {content_chunk.model_dump_json(exclude_none=True)}\n\n"

            stop_chunk = ChatCompletionChunk(
                id=completion_id,
                created=created,
                model=payload.model,
                choices=[
                    ChatCompletionChunkChoice(
                        index=0,
                        delta=ChatCompletionChunkDelta(),
                        finish_reason="stop",
                    )
                ],
            )
            yield f"data: {stop_chunk.model_dump_json(exclude_none=True)}\n\n"

            usage_chunk = ChatCompletionChunk(
                id=completion_id,
                created=created,
                model=payload.model,
                choices=[],
                usage=usage,
            )
            yield f"data: {usage_chunk.model_dump_json(exclude_none=True)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"cache-control": "no-cache"},
        )

    return app
