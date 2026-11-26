"""Atomic Redis reserve-then-reconcile Budget Quota, RPM limiting, and fail-closed enforcement."""

from __future__ import annotations

import asyncio
import logging
import math
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from weakref import WeakKeyDictionary

import anyio
from fastapi import Request, Response, status
from fastapi.responses import StreamingResponse
from redis.exceptions import RedisError

from platform_common import ActorContext, ChatCompletionRequest, LoadedPolicyBundle

logger = logging.getLogger(__name__)

MICRO_USD_PER_USD = 1_000_000
_RPM_KEY_TTL_SECONDS = 120
_DAILY_BUDGET_KEY_TTL_SECONDS = 86_400 + 3_600
_RESERVATION_KEY_TTL_SECONDS = 3_600
REDIS_FAILURE_EXCEPTIONS = (RedisError, TimeoutError, OSError)

RESERVE_LUA = """
local rpm_key = KEYS[1]
local budget_key = KEYS[2]
local res_key = KEYS[3]

local rpm_limit = tonumber(ARGV[1])
local rpm_ttl = tonumber(ARGV[2])
local budget_limit = tonumber(ARGV[3])
local reserve_micros = tonumber(ARGV[4])
local budget_ttl = tonumber(ARGV[5])
local res_ttl = tonumber(ARGV[6])

local cur_rpm = tonumber(redis.call('GET', rpm_key) or '0')
local cur_budget = tonumber(redis.call('GET', budget_key) or '0')

if cur_rpm + 1 > rpm_limit then
    return {0, 'rpm_limit_exceeded', cur_rpm, cur_budget}
end

if cur_budget + reserve_micros > budget_limit then
    return {0, 'budget_quota_exceeded', cur_rpm, cur_budget}
end

local rpm_ttl_cur = redis.call('TTL', rpm_key)
local new_rpm = redis.call('INCRBY', rpm_key, 1)
if rpm_ttl_cur == -2 and rpm_ttl > 0 then
    redis.call('EXPIRE', rpm_key, rpm_ttl)
end

local budget_ttl_cur = redis.call('TTL', budget_key)
local new_budget = redis.call('INCRBY', budget_key, reserve_micros)
if budget_ttl_cur == -2 and budget_ttl > 0 then
    redis.call('EXPIRE', budget_key, budget_ttl)
end

redis.call('SET', res_key, tostring(reserve_micros), 'EX', res_ttl)
return {1, 'allowed', new_rpm, new_budget}
"""

RECONCILE_LUA = """
local budget_key = KEYS[1]
local res_key = KEYS[2]
local actual_micros = tonumber(ARGV[1])
local fallback_ttl = tonumber(ARGV[2])

local raw_reserved = redis.call('GET', res_key)
if not raw_reserved then
    local cur_budget = tonumber(redis.call('GET', budget_key) or '0')
    return {0, cur_budget, 0}
end

redis.call('DEL', res_key)
local reserved_micros = tonumber(raw_reserved)
local delta = actual_micros - reserved_micros
local cur_budget = tonumber(redis.call('GET', budget_key) or '0')
local nxt = cur_budget + delta
if nxt < 0 then
    nxt = 0
end

local ttl = redis.call('TTL', budget_key)
if ttl > 0 then
    redis.call('SET', budget_key, tostring(nxt))
    redis.call('EXPIRE', budget_key, ttl)
elseif ttl == -1 then
    redis.call('SET', budget_key, tostring(nxt))
elseif nxt > 0 then
    redis.call('SET', budget_key, tostring(nxt))
    if fallback_ttl > 0 then
        redis.call('EXPIRE', budget_key, fallback_ttl)
    end
end

return {1, nxt, delta}
"""

_SCRIPT_CACHE: WeakKeyDictionary[Any, dict[str, Any]] = WeakKeyDictionary()


def _get_registered_script(redis_client: Any, name: str, lua_source: str) -> Any:
    try:
        client_scripts = _SCRIPT_CACHE.get(redis_client)
        if client_scripts is None:
            client_scripts = {}
            _SCRIPT_CACHE[redis_client] = client_scripts
    except TypeError:
        return redis_client.register_script(lua_source)

    script = client_scripts.get(name)
    if script is None:
        script = redis_client.register_script(lua_source)
        client_scripts[name] = script
    return script


class GatewayQuotaError(Exception):
    """Structured quota denial or Redis unavailability failure converted to OpenAI JSON."""

    def __init__(
        self,
        *,
        status_code: int,
        message: str,
        error_type: str,
        code: str,
        headers: dict[str, str] | None = None,
        denial_reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.error_type = error_type
        self.code = code
        self.headers = dict(headers or {})
        self.denial_reason = denial_reason


@dataclass
class QuotaReservation:
    """In-flight Team Budget Quota reservation awaiting completion/disconnect reconciliation."""

    reservation_id: str
    team: str
    model_alias: str
    budget_key: str
    res_key: str
    reserved_micros: int
    est_prompt_tokens: int
    reserved_completion_tokens: int
    prompt_micros_per_1k: int
    completion_micros_per_1k: int
    reconciled: bool = False


def count_llm_tokens(text: str) -> int:
    """Deterministically estimate LLM Token count using the canonical chars // 4 rule."""
    stripped = text.strip()
    if not stripped:
        return 0
    return max(1, len(stripped) // 4)


def estimate_prompt_tokens(payload: ChatCompletionRequest) -> int:
    """Estimate prompt LLM Tokens across all request messages."""
    return sum(count_llm_tokens(message.content) for message in payload.messages)


def usd_to_micros(amount_usd: float) -> int:
    """Convert a USD float from Policy Bundle configuration into integer micro-USD."""
    return round(amount_usd * MICRO_USD_PER_USD)


def format_micros_usd(micros: int) -> str:
    """Format integer micro-USD as a fixed-scale decimal USD string without scientific notation."""
    return f"{max(0, micros) / MICRO_USD_PER_USD:.6f}"


def calculate_cost_micros(
    prompt_tokens: int,
    completion_tokens: int,
    *,
    prompt_micros_per_1k: int,
    completion_micros_per_1k: int,
) -> int:
    """Compute integer micro-USD cost (ceiling to 1 micro-USD when positive)."""
    nanodollars = (
        max(0, prompt_tokens) * prompt_micros_per_1k
        + max(0, completion_tokens) * completion_micros_per_1k
    )
    if nanodollars <= 0:
        return 0
    return (nanodollars + 999) // 1000


def _decode_lua_str(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


def _retry_after_seconds(denial_reason: str, now: datetime) -> int:
    if denial_reason == "rpm_limit_exceeded":
        return max(1, 60 - now.second)
    next_midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, math.ceil((next_midnight - now).total_seconds()))


async def ensure_redis_ready(
    redis_client: Any | None,
    *,
    timeout_seconds: float,
) -> None:
    """Verify Redis connectivity for readiness checks, failing closed on error."""
    if redis_client is None:
        raise GatewayQuotaError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            message="Redis is not configured",
            error_type="service_unavailable_error",
            code="redis_unavailable",
        )
    try:
        pong = await asyncio.wait_for(redis_client.ping(), timeout=timeout_seconds)
    except REDIS_FAILURE_EXCEPTIONS as exc:
        raise GatewayQuotaError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            message="Redis is unreachable",
            error_type="service_unavailable_error",
            code="redis_unavailable",
        ) from exc
    if not pong:
        raise GatewayQuotaError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            message="Redis ping returned false",
            error_type="service_unavailable_error",
            code="redis_unavailable",
        )


async def reserve_quota(
    *,
    request: Request,
    payload: ChatCompletionRequest,
    actor: ActorContext,
    model_alias: str,
    loaded_policy: LoadedPolicyBundle,
    redis_client: Any | None,
    require_redis: bool,
    timeout_seconds: float,
) -> QuotaReservation | None:
    """Atomically check RPM and reserve worst-case USD Budget Quota in Redis."""
    if redis_client is None:
        if require_redis:
            raise GatewayQuotaError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                message="Redis is unavailable",
                error_type="service_unavailable_error",
                code="redis_unavailable",
            )
        return None

    policy = loaded_policy.bundle
    team_policy = policy.teams.get(actor.team)
    if team_policy is None:
        raise GatewayQuotaError(
            status_code=status.HTTP_403_FORBIDDEN,
            message=f"Team '{actor.team}' is not authorized in the Policy Bundle",
            error_type="permission_error",
            code="team_not_allowed",
            denial_reason="team_not_allowed",
        )

    model_policy = policy.models.get(model_alias) or policy.models.get(payload.model)
    if model_policy is None:
        raise GatewayQuotaError(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message=f"Pricing policy missing for Model Alias '{model_alias}'",
            error_type="server_error",
            code="model_pricing_missing",
        )

    est_prompt_tokens = estimate_prompt_tokens(payload)
    reserved_completion_tokens = (
        payload.max_tokens
        or model_policy.max_tokens_ceiling
        or policy.defaults.default_max_tokens_ceiling
    )
    prompt_micros_per_1k = usd_to_micros(model_policy.prompt_usd_per_1k_tokens)
    completion_micros_per_1k = usd_to_micros(model_policy.completion_usd_per_1k_tokens)
    reserve_micros = calculate_cost_micros(
        est_prompt_tokens,
        reserved_completion_tokens,
        prompt_micros_per_1k=prompt_micros_per_1k,
        completion_micros_per_1k=completion_micros_per_1k,
    )

    rpm_limit = team_policy.requests_per_minute
    budget_limit_micros = usd_to_micros(team_policy.daily_budget_usd)

    now = datetime.now(UTC)
    utc_minute = now.strftime("%Y-%m-%dT%H:%M")
    utc_date = now.strftime("%Y-%m-%d")
    reservation_id = uuid.uuid4().hex

    rpm_key = f"rpm:{actor.team}:{utc_minute}"
    budget_key = f"budget:{actor.team}:{utc_date}"
    res_key = f"res:{reservation_id}"

    script = _get_registered_script(redis_client, "reserve", RESERVE_LUA)
    try:
        raw_result = await asyncio.wait_for(
            script(
                keys=[rpm_key, budget_key, res_key],
                args=[
                    rpm_limit,
                    _RPM_KEY_TTL_SECONDS,
                    budget_limit_micros,
                    reserve_micros,
                    _DAILY_BUDGET_KEY_TTL_SECONDS,
                    _RESERVATION_KEY_TTL_SECONDS,
                ],
            ),
            timeout=timeout_seconds,
        )
    except REDIS_FAILURE_EXCEPTIONS as exc:
        raise GatewayQuotaError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            message="Redis is unreachable during quota reservation",
            error_type="service_unavailable_error",
            code="redis_unavailable",
        ) from exc

    allowed = int(raw_result[0]) == 1
    reason = _decode_lua_str(raw_result[1])
    cur_rpm = int(raw_result[2])
    cur_budget = int(raw_result[3])

    if not allowed:
        request.state.policy_denial_reason = reason
        headers = {
            "retry-after": str(_retry_after_seconds(reason, now)),
            "x-ratelimit-limit-requests": str(rpm_limit),
            "x-ratelimit-remaining-requests": str(max(0, rpm_limit - cur_rpm)),
            "x-budget-limit-usd": format_micros_usd(budget_limit_micros),
            "x-budget-remaining-usd": format_micros_usd(max(0, budget_limit_micros - cur_budget)),
            "x-policy-denial-reason": reason,
        }
        message = (
            f"Team '{actor.team}' exceeded requests-per-minute limit ({rpm_limit})"
            if reason == "rpm_limit_exceeded"
            else f"Team '{actor.team}' exceeded daily UTC USD Budget Quota"
        )
        raise GatewayQuotaError(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            message=message,
            error_type="rate_limit_error",
            code=reason,
            headers=headers,
            denial_reason=reason,
        )

    reservation = QuotaReservation(
        reservation_id=reservation_id,
        team=actor.team,
        model_alias=model_alias,
        budget_key=budget_key,
        res_key=res_key,
        reserved_micros=reserve_micros,
        est_prompt_tokens=est_prompt_tokens,
        reserved_completion_tokens=reserved_completion_tokens,
        prompt_micros_per_1k=prompt_micros_per_1k,
        completion_micros_per_1k=completion_micros_per_1k,
    )
    request.state.quota_reservation = reservation
    request.state.estimated_cost_usd = reserve_micros / MICRO_USD_PER_USD
    return reservation


async def reconcile_quota(
    *,
    request: Request,
    reservation: QuotaReservation | None,
    redis_client: Any | None,
    timeout_seconds: float,
    prompt_tokens: int,
    completion_tokens: int,
) -> int | None:
    """Atomically reconcile actual LLM Token cost against an active Budget Quota reservation."""
    if reservation is None or redis_client is None or reservation.reconciled:
        return None
    reservation.reconciled = True

    actual_micros = calculate_cost_micros(
        prompt_tokens,
        completion_tokens,
        prompt_micros_per_1k=reservation.prompt_micros_per_1k,
        completion_micros_per_1k=reservation.completion_micros_per_1k,
    )
    request.state.estimated_cost_usd = actual_micros / MICRO_USD_PER_USD

    script = _get_registered_script(redis_client, "reconcile", RECONCILE_LUA)
    try:
        raw_result = await asyncio.wait_for(
            script(
                keys=[reservation.budget_key, reservation.res_key],
                args=[actual_micros, _DAILY_BUDGET_KEY_TTL_SECONDS],
            ),
            timeout=timeout_seconds,
        )
    except REDIS_FAILURE_EXCEPTIONS:
        logger.warning(
            "Failed to reconcile quota reservation %s for team %s; keeping reservation",
            reservation.reservation_id,
            reservation.team,
            exc_info=True,
        )
        return None
    return int(raw_result[1])


async def reconcile_non_streaming_response(
    *,
    request: Request,
    response: Response,
    reservation: QuotaReservation,
    redis_client: Any | None,
    timeout_seconds: float,
) -> None:
    """Reconcile non-streaming HTTP responses, refunding completely on upstream errors."""
    if response.status_code >= status.HTTP_400_BAD_REQUEST:
        await reconcile_quota(
            request=request,
            reservation=reservation,
            redis_client=redis_client,
            timeout_seconds=timeout_seconds,
            prompt_tokens=0,
            completion_tokens=0,
        )
        return

    actual_prompt = getattr(request.state, "prompt_tokens", None)
    actual_completion = getattr(request.state, "completion_tokens", None)
    await reconcile_quota(
        request=request,
        reservation=reservation,
        redis_client=redis_client,
        timeout_seconds=timeout_seconds,
        prompt_tokens=actual_prompt if actual_prompt is not None else reservation.est_prompt_tokens,
        completion_tokens=actual_completion if actual_completion is not None else 0,
    )


async def _reconcile_stream_outcome(
    *,
    request: Request,
    reservation: QuotaReservation,
    redis_client: Any | None,
    timeout_seconds: float,
    stream_failed: bool,
) -> None:
    actual_prompt = getattr(request.state, "prompt_tokens", None)
    actual_completion = getattr(request.state, "completion_tokens", None)

    if actual_prompt is not None and actual_completion is not None:
        prompt_tokens = actual_prompt
        completion_tokens = actual_completion
    else:
        streamed_chars = int(getattr(request.state, "streamed_completion_chars", 0) or 0)
        prompt_tokens = (
            actual_prompt if actual_prompt is not None else reservation.est_prompt_tokens
        )
        if streamed_chars == 0 and stream_failed:
            completion_tokens = 0
        else:
            completion_tokens = max(1, streamed_chars // 4)

    await reconcile_quota(
        request=request,
        reservation=reservation,
        redis_client=redis_client,
        timeout_seconds=timeout_seconds,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )


def wrap_streaming_response(
    *,
    request: Request,
    response: StreamingResponse,
    reservation: QuotaReservation,
    redis_client: Any | None,
    timeout_seconds: float,
) -> StreamingResponse:
    """Wrap StreamingResponse.body_iterator to reconcile usage on completion or disconnect."""
    original_iterator = response.body_iterator
    cancelled_exc = anyio.get_cancelled_exc_class()

    async def _reconciled_body() -> AsyncIterator[bytes | str]:
        stream_failed = False
        try:
            async for chunk in original_iterator:
                yield chunk
        except BaseException as exc:
            if not isinstance(exc, (cancelled_exc, GeneratorExit)):
                stream_failed = True
            raise
        finally:
            with anyio.CancelScope(shield=True):
                aclose = getattr(original_iterator, "aclose", None)
                if callable(aclose):
                    try:
                        await aclose()
                    except Exception:
                        logger.warning(
                            "Failed closing upstream iterator during stream cleanup",
                            exc_info=True,
                        )
                await _reconcile_stream_outcome(
                    request=request,
                    reservation=reservation,
                    redis_client=redis_client,
                    timeout_seconds=timeout_seconds,
                    stream_failed=stream_failed,
                )

    response.body_iterator = _reconciled_body()
    return response
