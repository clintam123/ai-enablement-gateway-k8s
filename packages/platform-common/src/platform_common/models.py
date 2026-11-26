"""Canonical domain models shared across Control Plane, Mock Provider, and MCP Runtime."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ActorContext(BaseModel):
    """Authenticated Actor resolved from a Credential."""

    model_config = ConfigDict(frozen=True)

    actor_id: str
    team: str
    role: str
    auth_method: Literal["jwt", "api_key", "anonymous"] = "anonymous"


class ChatMessage(BaseModel):
    """Single message within a chat completion request or response."""

    model_config = ConfigDict(extra="allow")

    role: str
    content: str


class StreamOptions(BaseModel):
    """OpenAI-compatible SSE streaming options."""

    model_config = ConfigDict(extra="allow")

    include_usage: bool = False


class ChatCompletionRequest(BaseModel):
    """OpenAI-compatible chat completion request referencing a Model Alias."""

    model_config = ConfigDict(extra="allow")

    model: str
    messages: list[ChatMessage] = Field(min_length=1)
    max_tokens: int | None = Field(default=None, ge=1)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    stream: bool = False
    stream_options: StreamOptions | None = None


class LLMTokenUsage(BaseModel):
    """Prompt and completion LLM Token counts billed against a Team's Budget Quota."""

    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)


class ChatCompletionChoice(BaseModel):
    """Non-streaming completion choice."""

    index: int = 0
    message: ChatMessage
    finish_reason: str | None = "stop"


class ChatCompletionResponse(BaseModel):
    """OpenAI-compatible non-streaming chat completion response."""

    id: str
    object: Literal["chat.completion"] = "chat.completion"
    created: int
    model: str
    choices: list[ChatCompletionChoice]
    usage: LLMTokenUsage


class ChatCompletionChunkDelta(BaseModel):
    """Incremental delta emitted inside an SSE chunk."""

    role: str | None = None
    content: str | None = None


class ChatCompletionChunkChoice(BaseModel):
    """Streaming completion choice."""

    index: int = 0
    delta: ChatCompletionChunkDelta
    finish_reason: str | None = None


class ChatCompletionChunk(BaseModel):
    """OpenAI-compatible SSE streaming chunk."""

    id: str
    object: Literal["chat.completion.chunk"] = "chat.completion.chunk"
    created: int
    model: str
    choices: list[ChatCompletionChunkChoice]
    usage: LLMTokenUsage | None = None


class AuditEvent(BaseModel):
    """Privacy-safe structured Audit Event emitted for governed LLM and MCP Tool calls."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    trace_id: str
    request_id: str
    actor_id: str
    team: str
    role: str
    requested_model: str | None = None
    routed_model: str | None = None
    tool_name: str | None = None
    run_id: str | None = None
    fallback_used: bool = False
    policy_version: str
    policy_action: str
    triggered_rules: list[str] = Field(default_factory=list)
    redacted_entity_types: list[str] = Field(default_factory=list)
    prompt_sha256: str | None = None
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    estimated_cost_usd: float = Field(default=0.0, ge=0.0)
    latency_ms: float = Field(default=0.0, ge=0.0)
    status_code: int


class OpenAIErrorDetail(BaseModel):
    """OpenAI-compatible error detail object."""

    message: str
    type: str
    param: str | None = None
    code: str | None = None


class OpenAIErrorPayload(BaseModel):
    """Top-level OpenAI-compatible error payload."""

    error: OpenAIErrorDetail


def build_openai_error(
    message: str,
    error_type: str,
    *,
    code: str | None = None,
    param: str | None = None,
) -> dict[str, object]:
    """Build a JSON-serializable OpenAI-compatible error dictionary."""
    return OpenAIErrorPayload(
        error=OpenAIErrorDetail(
            message=message,
            type=error_type,
            param=param,
            code=code,
        )
    ).model_dump()
