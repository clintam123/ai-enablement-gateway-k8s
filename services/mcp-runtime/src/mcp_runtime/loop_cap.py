"""Atomic Redis Lua per-Run tool-call loop cap and fail-closed readiness checks."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from weakref import WeakKeyDictionary

from redis.exceptions import RedisError

REDIS_FAILURE_EXCEPTIONS = (RedisError, TimeoutError, OSError)

RUN_LOOP_CAP_LUA = """
local key = KEYS[1]
local max_calls = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])

local cur = tonumber(redis.call('GET', key) or '0')
if cur >= max_calls then
    return {0, cur, max_calls}
end

local nxt = redis.call('INCR', key)
if redis.call('TTL', key) == -1 and ttl > 0 then
    redis.call('EXPIRE', key, ttl)
end
return {1, nxt, max_calls}
"""

_SCRIPT_CACHE: WeakKeyDictionary[Any, Any] = WeakKeyDictionary()


class MCPRuntimeUnavailableError(Exception):
    """Raised when Redis is missing or unreachable so MCP Runtime fails closed (503)."""


@dataclass(frozen=True, slots=True)
class LoopCapDecision:
    """Result of an atomic per-Run tool-call loop-cap check."""

    allowed: bool
    current_calls: int
    max_calls: int


def _get_loop_cap_script(redis_client: Any) -> Any:
    try:
        cached = _SCRIPT_CACHE.get(redis_client)
    except TypeError:
        return redis_client.register_script(RUN_LOOP_CAP_LUA)
    if cached is None:
        cached = redis_client.register_script(RUN_LOOP_CAP_LUA)
        _SCRIPT_CACHE[redis_client] = cached
    return cached


async def ensure_redis_ready(
    redis_client: Any | None,
    *,
    timeout_seconds: float,
) -> None:
    """Verify Redis connectivity for readiness checks, failing closed on error."""
    if redis_client is None:
        raise MCPRuntimeUnavailableError("Redis is not configured")
    try:
        pong = await asyncio.wait_for(redis_client.ping(), timeout=timeout_seconds)
    except REDIS_FAILURE_EXCEPTIONS as exc:
        raise MCPRuntimeUnavailableError("Redis is unreachable") from exc
    if not pong:
        raise MCPRuntimeUnavailableError("Redis ping returned false")


async def consume_run_tool_call(
    *,
    team: str,
    run_id: str,
    max_calls: int,
    ttl_seconds: int,
    redis_client: Any | None,
    require_redis: bool,
    timeout_seconds: float,
) -> LoopCapDecision:
    """Atomically increment per-Run MCP Tool calls in Redis unless max_calls is reached."""
    if redis_client is None:
        if require_redis:
            raise MCPRuntimeUnavailableError("Redis is unavailable")
        return LoopCapDecision(allowed=True, current_calls=1, max_calls=max_calls)

    key = f"mcp:run:{team}:{run_id}:calls"
    script = _get_loop_cap_script(redis_client)
    try:
        raw_result = await asyncio.wait_for(
            script(keys=[key], args=[max_calls, ttl_seconds]),
            timeout=timeout_seconds,
        )
    except REDIS_FAILURE_EXCEPTIONS as exc:
        raise MCPRuntimeUnavailableError(
            "Redis is unreachable during MCP Run loop cap check"
        ) from exc

    allowed = int(raw_result[0]) == 1
    current_calls = int(raw_result[1])
    limit = int(raw_result[2])
    return LoopCapDecision(allowed=allowed, current_calls=current_calls, max_calls=limit)
