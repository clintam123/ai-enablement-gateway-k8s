"""Control Plane HTTP-seam tests for Redis Budget Quotas, RPM limits, and fail-closed 503."""

from __future__ import annotations

import asyncio
import hashlib
import socket
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import fakeredis
import httpx
import pytest
import uvicorn
import yaml
from redis.exceptions import RedisError

from gateway_api.app import create_app
from gateway_api.config import ControlPlaneSettings
from mock_llm.app import create_app as create_mock_provider_app
from mock_llm.config import MockProviderSettings
from scripts.generate_test_keys import generate_rsa_keypair, mint_rs256_jwt

POLICY_BUNDLE_PATH = Path(__file__).resolve().parent.parent / "policies" / "policy-bundle.yaml"


def _auth_headers(
    *,
    team: str = "platform-eng",
    role: str = "developer",
    actor_id: str = "quota-test-actor",
) -> tuple[dict[str, Any], dict[str, str]]:
    keypair = generate_rsa_keypair(seed=f"quota-{team}")
    token = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id=actor_id,
        team=team,
        role=role,
    )
    return keypair.jwks, {"Authorization": f"Bearer {token}"}


class _FailingRedis:
    """Stub Redis client simulating network/timeout failures on ping and script execution."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    async def ping(self) -> bool:
        raise self._exc

    def register_script(self, _script: str) -> Any:
        exc = self._exc

        async def _fail(*_args: Any, **_kwargs: Any) -> Any:
            raise exc

        return _fail


async def test_readyz_and_chat_fail_closed_with_503_when_redis_unconfigured() -> None:
    jwks, headers = _auth_headers()
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
            require_redis=True,
            redis_url=None,
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
        redis_client=None,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://control-plane",
    ) as client:
        health_resp = await client.get("/healthz")
        assert health_resp.status_code == 200

        ready_resp = await client.get("/readyz")
        assert ready_resp.status_code == 503
        assert ready_resp.json()["error"]["code"] == "redis_unavailable"

        chat_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Hello while Redis unconfigured"}],
            },
            headers=headers,
        )
        assert chat_resp.status_code == 503
        assert chat_resp.json()["error"]["code"] == "redis_unavailable"
        assert chat_resp.headers["x-policy-version"].startswith("v1+")


async def test_readyz_and_chat_fail_closed_with_503_when_redis_unreachable() -> None:
    jwks, headers = _auth_headers()
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )

    failures = (
        RedisError("connection refused"),
        TimeoutError("socket timed out"),
        OSError("down"),
    )
    for exc in failures:
        app = create_app(
            settings=ControlPlaneSettings(
                policy_bundle_path=POLICY_BUNDLE_PATH,
                model_router_base_url="http://mock-provider",
                jwt_jwks=jwks,
                require_redis=True,
            ),
            model_router_transport=httpx.ASGITransport(app=mock_app),
            redis_client=_FailingRedis(exc),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://control-plane",
        ) as client:
            ready_resp = await client.get("/readyz")
            assert ready_resp.status_code == 503
            assert ready_resp.json()["error"]["code"] == "redis_unavailable"

            chat_resp = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "chat-default",
                    "messages": [{"role": "user", "content": "Hello while Redis down"}],
                },
                headers=headers,
            )
            assert chat_resp.status_code == 503
            assert chat_resp.json()["error"]["code"] == "redis_unavailable"
            assert chat_resp.headers["x-policy-version"].startswith("v1+")


async def test_readyz_returns_200_when_redis_ping_succeeds() -> None:
    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)
    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
            require_redis=True,
        ),
        redis_client=redis_client,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://control-plane",
    ) as client:
        ready_resp = await client.get("/readyz")
        assert ready_resp.status_code == 200
        assert ready_resp.json()["status"] == "ready"
    await redis_client.aclose()


async def test_lifespan_closes_internal_redis_url_client_only() -> None:
    internal_fake = fakeredis.FakeAsyncRedis(decode_responses=True)
    internal_aclose = AsyncMock(wraps=internal_fake.aclose)
    internal_fake.aclose = internal_aclose  # type: ignore[method-assign]

    with patch("gateway_api.app.aioredis.from_url", return_value=internal_fake) as mock_from_url:
        app_internal = create_app(
            settings=ControlPlaneSettings(
                policy_bundle_path=POLICY_BUNDLE_PATH,
                model_router_base_url="http://mock-provider",
                redis_url="redis://redis:6379/0",
                redis_socket_timeout_seconds=1.5,
            ),
        )
        mock_from_url.assert_called_once_with(
            "redis://redis:6379/0",
            decode_responses=True,
            socket_timeout=1.5,
            socket_connect_timeout=1.5,
        )
        async with app_internal.router.lifespan_context(app_internal):
            pass
        assert internal_aclose.await_count == 1

    external_fake = fakeredis.FakeAsyncRedis(decode_responses=True)
    external_aclose = AsyncMock(wraps=external_fake.aclose)
    external_fake.aclose = external_aclose  # type: ignore[method-assign]

    app_external = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
            redis_url="redis://ignored:6379/0",
        ),
        redis_client=external_fake,
    )
    async with app_external.router.lifespan_context(app_external):
        pass
    assert external_aclose.await_count == 0
    await external_fake.aclose()


def _write_test_policy(
    tmp_path: Path,
    *,
    requests_per_minute: int = 60,
    daily_budget_usd: float = 10.0,
    prompt_rate: float = 0.001,
    completion_rate: float = 0.002,
    model_max_tokens_ceiling: int | None = 100,
    default_max_tokens_ceiling: int = 512,
) -> tuple[Path, str]:
    model_entry: dict[str, Any] = {
        "prompt_usd_per_1k_tokens": prompt_rate,
        "completion_usd_per_1k_tokens": completion_rate,
    }
    if model_max_tokens_ceiling is not None:
        model_entry["max_tokens_ceiling"] = model_max_tokens_ceiling

    data: dict[str, Any] = {
        "schema_version": "v1",
        "defaults": {
            "default_max_tokens_ceiling": default_max_tokens_ceiling,
            "requests_per_minute": 60,
            "daily_budget_usd": 10.0,
        },
        "models": {
            "chat-fast": model_entry,
        },
        "teams": {
            "product-eng": {
                "allowed_model_aliases": ["chat-fast"],
                "model_alias_remapping": {},
                "requests_per_minute": requests_per_minute,
                "daily_budget_usd": daily_budget_usd,
            },
        },
    }
    policy_path = tmp_path / "policy-bundle.yaml"
    raw = yaml.safe_dump(data).encode("utf-8")
    policy_path.write_bytes(raw)
    expected_version = f"v1+{hashlib.sha256(raw).hexdigest()[:8]}"
    return policy_path, expected_version


async def test_rpm_limit_exceeded_returns_429_with_required_headers_and_does_not_mutate_counters(
    tmp_path: Path,
) -> None:
    policy_path, expected_version = _write_test_policy(
        tmp_path,
        requests_per_minute=2,
        daily_budget_usd=10.0,
        prompt_rate=0.001,
        completion_rate=0.002,
    )
    jwks, headers = _auth_headers(team="product-eng")
    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)
    upstream_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(
            status_code=200,
            headers={"content-type": "application/json"},
            json={
                "id": f"chatcmpl-{upstream_calls}",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "chat-fast",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
        )

    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
        ),
        model_router_transport=httpx.MockTransport(handler),
        redis_client=redis_client,
    )

    payload = {
        "model": "chat-fast",
        "messages": [{"role": "user", "content": "x" * 40}],
        "max_tokens": 50,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://control-plane",
    ) as client:
        for _ in range(2):
            ok_resp = await client.post("/v1/chat/completions", json=payload, headers=headers)
            assert ok_resp.status_code == 200

        utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
        budget_key = f"budget:product-eng:{utc_date}"
        budget_before_denial = await redis_client.get(budget_key)

        denied_resp = await client.post("/v1/chat/completions", json=payload, headers=headers)

    assert denied_resp.status_code == 429
    assert denied_resp.headers["x-policy-version"] == expected_version
    assert denied_resp.headers["x-policy-denial-reason"] == "rpm_limit_exceeded"
    assert denied_resp.headers["x-ratelimit-limit-requests"] == "2"
    assert denied_resp.headers["x-ratelimit-remaining-requests"] == "0"
    assert float(denied_resp.headers["x-budget-limit-usd"]) == 10.0
    assert 0.0 <= float(denied_resp.headers["x-budget-remaining-usd"]) <= 10.0
    retry_after = int(denied_resp.headers["retry-after"])
    assert 1 <= retry_after <= 60

    err = denied_resp.json()["error"]
    assert err["type"] == "rate_limit_error"
    assert err["code"] == "rpm_limit_exceeded"

    assert upstream_calls == 2
    rpm_keys = await redis_client.keys("rpm:product-eng:*")
    assert len(rpm_keys) == 1
    assert await redis_client.get(rpm_keys[0]) == "2"
    assert await redis_client.get(budget_key) == budget_before_denial
    await redis_client.aclose()


async def test_budget_quota_exceeded_returns_429_without_mutating_rpm_or_budget(
    tmp_path: Path,
) -> None:
    policy_path, expected_version = _write_test_policy(
        tmp_path,
        requests_per_minute=60,
        daily_budget_usd=0.0005,
        prompt_rate=0.001,
        completion_rate=0.002,
    )
    jwks, headers = _auth_headers(team="product-eng")
    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)
    upstream_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(
            status_code=200,
            headers={"content-type": "application/json"},
            json={
                "id": f"chatcmpl-{upstream_calls}",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "chat-fast",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 100, "total_tokens": 110},
            },
        )

    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
        ),
        model_router_transport=httpx.MockTransport(handler),
        redis_client=redis_client,
    )

    payload = {
        "model": "chat-fast",
        "messages": [{"role": "user", "content": "x" * 40}],
        "max_tokens": 100,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://control-plane",
    ) as client:
        ok_one = await client.post("/v1/chat/completions", json=payload, headers=headers)
        ok_two = await client.post("/v1/chat/completions", json=payload, headers=headers)
        assert ok_one.status_code == 200
        assert ok_two.status_code == 200
        denied = await client.post("/v1/chat/completions", json=payload, headers=headers)

    assert denied.status_code == 429
    assert denied.headers["x-policy-version"] == expected_version
    assert denied.headers["x-policy-denial-reason"] == "budget_quota_exceeded"
    assert denied.headers["x-ratelimit-limit-requests"] == "60"
    assert denied.headers["x-ratelimit-remaining-requests"] == "58"
    assert denied.headers["x-budget-limit-usd"] == "0.000500"
    assert denied.headers["x-budget-remaining-usd"] == "0.000080"
    retry_after = int(denied.headers["retry-after"])
    assert 1 <= retry_after <= 86400

    err = denied.json()["error"]
    assert err["type"] == "rate_limit_error"
    assert err["code"] == "budget_quota_exceeded"

    assert upstream_calls == 2
    utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
    assert await redis_client.get(f"budget:product-eng:{utc_date}") == "420"
    rpm_keys = await redis_client.keys("rpm:product-eng:*")
    assert await redis_client.get(rpm_keys[0]) == "2"
    await redis_client.aclose()


async def test_concurrent_burst_across_replicas_prevents_budget_overshoot(
    tmp_path: Path,
) -> None:
    policy_path, _ = _write_test_policy(
        tmp_path,
        requests_per_minute=100,
        daily_budget_usd=0.0010,
        prompt_rate=0.001,
        completion_rate=0.002,
    )
    jwks, headers = _auth_headers(team="product-eng")
    shared_server = fakeredis.FakeServer()
    redis_a = fakeredis.FakeAsyncRedis(server=shared_server, decode_responses=True)
    redis_b = fakeredis.FakeAsyncRedis(server=shared_server, decode_responses=True)
    upstream_calls = 0

    class _SlowTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, _request: httpx.Request) -> httpx.Response:
            nonlocal upstream_calls
            upstream_calls += 1
            await asyncio.sleep(0.03)
            return httpx.Response(
                status_code=200,
                headers={"content-type": "application/json"},
                json={
                    "id": "chatcmpl-burst",
                    "object": "chat.completion",
                    "created": 1700000000,
                    "model": "chat-fast",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 100, "total_tokens": 110},
                },
            )

    transport = _SlowTransport()
    app_a = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
        ),
        model_router_transport=transport,
        redis_client=redis_a,
    )
    app_b = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
        ),
        model_router_transport=transport,
        redis_client=redis_b,
    )

    payload = {
        "model": "chat-fast",
        "messages": [{"role": "user", "content": "x" * 40}],
        "max_tokens": 100,
    }
    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_a), base_url="http://replica-a"
        ) as client_a,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_b), base_url="http://replica-b"
        ) as client_b,
    ):
        responses = await asyncio.gather(
            *[
                (client_a if i % 2 == 0 else client_b).post(
                    "/v1/chat/completions", json=payload, headers=headers
                )
                for i in range(10)
            ]
        )

    statuses = [resp.status_code for resp in responses]
    assert statuses.count(200) == 4
    assert statuses.count(429) == 6
    for resp in responses:
        if resp.status_code == 429:
            assert resp.headers["x-policy-denial-reason"] == "budget_quota_exceeded"
            assert resp.headers["x-budget-limit-usd"] == "0.001000"

    assert upstream_calls == 4
    utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
    assert await redis_a.get(f"budget:product-eng:{utc_date}") == "840"
    rpm_keys = await redis_a.keys("rpm:product-eng:*")
    assert await redis_a.get(rpm_keys[0]) == "4"
    await redis_a.aclose()
    await redis_b.aclose()


async def test_post_completion_refunds_unused_reservation_with_explicit_and_default_ceilings(
    tmp_path: Path,
) -> None:
    # daily_budget_usd = 0.000500 (500 micro-USD).
    # prompt_rate = 0.001/1k (1 micro/tok), completion_rate = 0.002/1k (2 micro/tok).
    # model_max_tokens_ceiling is omitted so policy.defaults.default_max_tokens_ceiling=200 applies.
    policy_path, _ = _write_test_policy(
        tmp_path,
        requests_per_minute=60,
        daily_budget_usd=0.0005,
        prompt_rate=0.001,
        completion_rate=0.002,
        model_max_tokens_ceiling=None,
        default_max_tokens_ceiling=200,
    )
    jwks, headers = _auth_headers(team="product-eng")
    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)

    entered_upstream = asyncio.Event()
    release_upstream = asyncio.Event()

    class _GatedTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, _request: httpx.Request) -> httpx.Response:
            entered_upstream.set()
            await release_upstream.wait()
            return httpx.Response(
                status_code=200,
                headers={"content-type": "application/json"},
                json={
                    "id": "chatcmpl-refund",
                    "object": "chat.completion",
                    "created": 1700000000,
                    "model": "chat-fast",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "short"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                },
            )

    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
        ),
        model_router_transport=_GatedTransport(),
        redis_client=redis_client,
    )
    utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
    budget_key = f"budget:product-eng:{utc_date}"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://control-plane",
    ) as client:
        # 1. Request omitting max_tokens -> reserves 10*1 + 200*2 = 410 micro-USD while in flight
        in_flight_task = asyncio.create_task(
            client.post(
                "/v1/chat/completions",
                json={
                    "model": "chat-fast",
                    "messages": [{"role": "user", "content": "x" * 40}],
                },
                headers=headers,
            )
        )
        await asyncio.wait_for(entered_upstream.wait(), timeout=2.0)
        assert await redis_client.get(budget_key) == "410"
        ttl_during = await redis_client.ttl(budget_key)
        assert ttl_during > 0
        assert len(await redis_client.keys("res:*")) == 1

        # Concurrent second request needing 410 micro-USD is rejected while first is in flight
        blocked_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "x" * 40}],
            },
            headers=headers,
        )
        assert blocked_resp.status_code == 429
        assert blocked_resp.headers["x-policy-denial-reason"] == "budget_quota_exceeded"

        # Release first request -> settles at actual 10*1 + 5*2 = 20 micro-USD!
        release_upstream.set()
        first_resp = await asyncio.wait_for(in_flight_task, timeout=2.0)
        assert first_resp.status_code == 200
        assert await redis_client.get(budget_key) == "20"
        assert await redis_client.ttl(budget_key) > 0
        assert await redis_client.keys("res:*") == []

        # 2. Now the second request with explicit max_tokens=150 (reserves 10 + 300 = 310) fits!
        second_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "x" * 40}],
                "max_tokens": 150,
            },
            headers=headers,
        )
        assert second_resp.status_code == 200
        # 20 + (10*1 + 5*2) = 40 micro-USD
        assert await redis_client.get(budget_key) == "40"

    await redis_client.aclose()


async def test_upstream_errors_refund_reservation_completely_and_preserve_ttl(
    tmp_path: Path,
) -> None:
    policy_path, _ = _write_test_policy(
        tmp_path,
        requests_per_minute=60,
        daily_budget_usd=0.0005,
        prompt_rate=0.001,
        completion_rate=0.002,
    )
    jwks, headers = _auth_headers(team="product-eng")
    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(
            provider_name="mock-llm-primary",
            mock_mode_enabled=True,
            timeout_delay_ms=200,
        )
    )
    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            model_router_timeout_seconds=0.05,
            mock_mode_enabled=True,
            jwt_jwks=jwks,
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
        redis_client=redis_client,
    )
    utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
    budget_key = f"budget:product-eng:{utc_date}"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://control-plane",
    ) as client:
        # 1. Successful baseline call spends a small known amount
        ok_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "x" * 40}],
                "max_tokens": 5,
            },
            headers=headers,
        )
        assert ok_resp.status_code == 200
        usage = ok_resp.json()["usage"]
        expected_spent = usage["prompt_tokens"] * 1 + usage["completion_tokens"] * 2
        assert await redis_client.get(budget_key) == str(expected_spent)

        # 2. Upstream 503 (non-streaming) -> full refund back to expected_spent
        err_503 = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "x" * 40}],
                "max_tokens": 100,
            },
            headers={**headers, "X-Mock-Behavior": "fail_503"},
        )
        assert err_503.status_code == 503
        assert await redis_client.get(budget_key) == str(expected_spent)
        assert await redis_client.ttl(budget_key) > 0
        assert await redis_client.keys("res:*") == []

        # 3. Upstream 503 (streaming) -> full refund back to expected_spent
        err_stream_503 = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "x" * 40}],
                "max_tokens": 100,
                "stream": True,
            },
            headers={**headers, "X-Mock-Behavior": "fail_503"},
        )
        assert err_stream_503.status_code == 503
        assert await redis_client.get(budget_key) == str(expected_spent)

        # 4. Upstream 504 timeout -> full refund back to expected_spent
        err_504 = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "x" * 40}],
                "max_tokens": 100,
            },
            headers={**headers, "X-Mock-Behavior": "timeout"},
        )
        assert err_504.status_code == 504
        assert await redis_client.get(budget_key) == str(expected_spent)
        assert await redis_client.ttl(budget_key) > 0

    await redis_client.aclose()


async def test_reconcile_lua_is_idempotent_and_clamps_at_zero() -> None:
    from gateway_api.quotas import RECONCILE_LUA

    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)
    budget_key = "budget:product-eng:2026-11-26"
    res_key = "res:test-idempotent-1"
    await redis_client.set(budget_key, "210", ex=3600)
    await redis_client.set(res_key, "210", ex=600)

    reconcile_script = redis_client.register_script(RECONCILE_LUA)
    first = await reconcile_script(keys=[budget_key, res_key], args=[20, 86400])
    assert first == [1, 20, -190]
    assert await redis_client.get(budget_key) == "20"
    assert 3500 <= await redis_client.ttl(budget_key) <= 3600
    assert await redis_client.get(res_key) is None

    # Second call with same reservation key must be a no-op (no double refund!)
    second = await reconcile_script(keys=[budget_key, res_key], args=[20, 86400])
    assert second == [0, 20, 0]
    assert await redis_client.get(budget_key) == "20"

    # Clamps at >= 0 if budget_key held less than refund delta
    res_key_2 = "res:test-clamp"
    await redis_client.set(budget_key, "50", ex=1800)
    await redis_client.set(res_key_2, "200", ex=600)
    clamped = await reconcile_script(keys=[budget_key, res_key_2], args=[0, 86400])
    assert clamped[0] == 1
    assert clamped[1] == 0
    assert await redis_client.get(budget_key) == "0"
    assert 1700 <= await redis_client.ttl(budget_key) <= 1800
    await redis_client.aclose()


class _AsyncByteStream(httpx.AsyncByteStream):
    def __init__(self, iterator: AsyncIterator[bytes]) -> None:
        self._iterator = iterator

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._iterator:
            yield chunk


def _build_asgi_chat_request(
    payload: dict[str, Any],
    *,
    extra_headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any], Any, asyncio.Event]:
    import json

    request_body = json.dumps(payload).encode("utf-8")
    request_sent = False
    disconnect_event = asyncio.Event()
    headers = [
        (b"host", b"control-plane"),
        (b"content-type", b"application/json"),
        (b"content-length", str(len(request_body)).encode("ascii")),
    ]
    for name, value in (extra_headers or {}).items():
        headers.append((name.lower().encode("latin-1"), value.encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/chat/completions",
        "raw_path": b"/v1/chat/completions",
        "query_string": b"",
        "headers": headers,
        "server": ("control-plane", 80),
        "client": ("127.0.0.1", 12345),
        "root_path": "",
    }

    async def receive() -> dict[str, Any]:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": request_body, "more_body": False}
        await disconnect_event.wait()
        return {"type": "http.disconnect"}

    return scope, receive, disconnect_event


async def test_sse_stream_completion_reconciles_final_usage_and_refunds_remainder(
    tmp_path: Path,
) -> None:
    policy_path, _ = _write_test_policy(
        tmp_path,
        requests_per_minute=60,
        daily_budget_usd=0.0010,
        prompt_rate=0.001,
        completion_rate=0.002,
    )
    jwks, headers = _auth_headers(team="product-eng")
    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
        redis_client=redis_client,
    )

    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://control-plane",
        ) as client,
        client.stream(
            "POST",
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "x" * 40}],
                "max_tokens": 100,
                "stream": True,
            },
            headers=headers,
        ) as sse_resp,
    ):
        assert sse_resp.status_code == 200
        lines = [
            line.removeprefix("data: ").strip()
            async for line in sse_resp.aiter_lines()
            if line.startswith("data: ")
        ]

    import json

    assert lines[-1] == "[DONE]"
    chunks = [json.loads(item) for item in lines[:-1]]
    usage = next(c["usage"] for c in chunks if c.get("usage") is not None)
    expected_micros = usage["prompt_tokens"] * 1 + usage["completion_tokens"] * 2
    assert expected_micros < 210  # reserved 10*1 + 100*2 = 210

    utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
    assert await redis_client.get(f"budget:product-eng:{utc_date}") == str(expected_micros)
    assert await redis_client.keys("res:*") == []
    await redis_client.aclose()


@pytest.mark.parametrize(
    ("partial_text", "expected_est_completion_tokens"),
    [
        ("twenty four chars output", 6),  # 24 // 4 = 6
        ("hi", 1),  # max(1, 2 // 4) = 1
    ],
)
async def test_mid_stream_sse_disconnect_reconciles_estimated_tokens_and_refunds_remainder(
    tmp_path: Path,
    partial_text: str,
    expected_est_completion_tokens: int,
) -> None:
    policy_path, _ = _write_test_policy(
        tmp_path,
        requests_per_minute=60,
        daily_budget_usd=0.0010,
        prompt_rate=0.001,
        completion_rate=0.002,
    )
    jwks, headers = _auth_headers(team="product-eng")
    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)

    upstream_closed = asyncio.Event()
    first_chunk_sent = asyncio.Event()
    release_tail = asyncio.Event()

    class _PartialStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            import json

            chunk_payload = json.dumps(
                {
                    "id": "cmpl-partial",
                    "object": "chat.completion.chunk",
                    "created": 1700000000,
                    "model": "chat-fast",
                    "choices": [{"index": 0, "delta": {"content": partial_text}}],
                }
            )
            yield f"data: {chunk_payload}\n\n".encode()
            await release_tail.wait()

        async def aclose(self) -> None:
            upstream_closed.set()

    class _DisconnectTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, _request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=200,
                headers={"content-type": "text/event-stream"},
                stream=_PartialStream(),
            )

    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
        ),
        model_router_transport=_DisconnectTransport(),
        redis_client=redis_client,
    )

    utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
    budget_key = f"budget:product-eng:{utc_date}"

    scope, receive, disconnect_event = _build_asgi_chat_request(
        {
            "model": "chat-fast",
            "messages": [{"role": "user", "content": "x" * 40}],  # 10 prompt tokens
            "max_tokens": 100,  # reserved = 10*1 + 100*2 = 210 micro-USD
            "stream": True,
        },
        extra_headers=headers,
    )

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.body" and partial_text.encode() in message.get(
            "body", b""
        ):
            first_chunk_sent.set()

    app_task = asyncio.create_task(app(scope, receive, send))
    await asyncio.wait_for(first_chunk_sent.wait(), timeout=2.0)
    # While stream is open, full 210 micro-USD is still reserved
    assert await redis_client.get(budget_key) == "210"

    # Abrupt client disconnect before final usage chunk arrives
    disconnect_event.set()
    await asyncio.wait_for(app_task, timeout=2.0)

    assert upstream_closed.is_set()
    expected_micros = 10 * 1 + expected_est_completion_tokens * 2
    assert await redis_client.get(budget_key) == str(expected_micros)
    assert await redis_client.keys("res:*") == []
    await redis_client.aclose()


async def test_mid_stream_sse_failure_before_content_reconciles_zero_completion_tokens(
    tmp_path: Path,
) -> None:
    policy_path, _ = _write_test_policy(
        tmp_path,
        requests_per_minute=60,
        daily_budget_usd=0.0010,
        prompt_rate=0.001,
        completion_rate=0.002,
    )
    jwks, headers = _auth_headers(team="product-eng")
    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)

    class _FailingStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield (
                b'data: {"id":"cmpl-fail","object":"chat.completion.chunk",'
                b'"created":1700000000,"model":"chat-fast",'
                b'"choices":[{"index":0,"delta":{"role":"assistant"}}]}\n\n'
            )
            raise httpx.ReadError("upstream dropped stream before content")

    class _FailingStreamTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, _request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=200,
                headers={"content-type": "text/event-stream"},
                stream=_FailingStream(),
            )

    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
        ),
        model_router_transport=_FailingStreamTransport(),
        redis_client=redis_client,
    )

    scope, receive, _disconnect = _build_asgi_chat_request(
        {
            "model": "chat-fast",
            "messages": [{"role": "user", "content": "x" * 40}],  # 10 prompt tokens
            "max_tokens": 100,  # reserved 210 micro-USD
            "stream": True,
        },
        extra_headers=headers,
    )

    async def send(_message: dict[str, Any]) -> None:
        return

    with pytest.raises(httpx.ReadError):
        await app(scope, receive, send)

    utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
    # 0 content chars streamed + stream failed -> completion_tokens=0, prompt_tokens=10 -> 10*1 = 10
    assert await redis_client.get(f"budget:product-eng:{utc_date}") == "10"
    assert await redis_client.keys("res:*") == []
    await redis_client.aclose()


async def test_live_http_sse_aclose_after_partial_chunks_triggers_reconciliation(
    tmp_path: Path,
) -> None:
    policy_path, _ = _write_test_policy(
        tmp_path,
        requests_per_minute=60,
        daily_budget_usd=0.0010,
        prompt_rate=0.001,
        completion_rate=0.002,
    )
    jwks, headers = _auth_headers(team="product-eng")
    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)

    partial_text = "sixteen chars!!!"  # 16 chars -> 16 // 4 = 4 completion tokens
    upstream_closed = asyncio.Event()
    release_tail = asyncio.Event()

    class _PartialStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            import json

            chunk_payload = json.dumps(
                {
                    "id": "cmpl-http-aclose",
                    "object": "chat.completion.chunk",
                    "created": 1700000000,
                    "model": "chat-fast",
                    "choices": [{"index": 0, "delta": {"content": partial_text}}],
                }
            )
            yield f"data: {chunk_payload}\n\n".encode()
            await release_tail.wait()

        async def aclose(self) -> None:
            upstream_closed.set()

    class _Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, _request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=200,
                headers={"content-type": "text/event-stream"},
                stream=_PartialStream(),
            )

    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
        ),
        model_router_transport=_Transport(),
        redis_client=redis_client,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.setblocking(False)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    serve_task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        await asyncio.sleep(0.01)

    utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
    budget_key = f"budget:product-eng:{utc_date}"

    try:
        async with (
            httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client,
            client.stream(
                "POST",
                "/v1/chat/completions",
                json={
                    "model": "chat-fast",
                    "messages": [{"role": "user", "content": "x" * 40}],  # 10 prompt tokens
                    "max_tokens": 100,  # reserved = 210 micro-USD
                    "stream": True,
                },
                headers=headers,
            ) as sse_resp,
        ):
            assert sse_resp.status_code == 200
            async for line in sse_resp.aiter_lines():
                if partial_text in line:
                    break
            assert await redis_client.get(budget_key) == "210"
            await sse_resp.aclose()

        await asyncio.wait_for(upstream_closed.wait(), timeout=2.0)
        # Allow uvicorn disconnect handler task to complete shielded finally reconciliation
        for _ in range(50):
            if await redis_client.keys("res:*") == []:
                break
            await asyncio.sleep(0.01)

        # 10 prompt * 1 + 4 completion * 2 = 18 micro-USD
        assert await redis_client.get(budget_key) == "18"
        assert await redis_client.keys("res:*") == []
    finally:
        release_tail.set()
        server.should_exit = True
        await serve_task
        sock.close()
        await redis_client.aclose()


async def test_remapped_model_alias_uses_target_model_pricing(tmp_path: Path) -> None:
    policy_data = {
        "schema_version": "v1",
        "defaults": {
            "default_max_tokens_ceiling": 512,
            "requests_per_minute": 60,
            "daily_budget_usd": 10.0,
        },
        "models": {
            "chat-fast": {
                "prompt_usd_per_1k_tokens": 0.001,
                "completion_usd_per_1k_tokens": 0.002,
                "max_tokens_ceiling": 100,
            }
        },
        "teams": {
            "product-eng": {
                "allowed_model_aliases": ["chat-legacy"],
                "model_alias_remapping": {"chat-legacy": "chat-fast"},
                "requests_per_minute": 60,
                "daily_budget_usd": 1.0,
            }
        },
    }
    policy_path = tmp_path / "policy-bundle.yaml"
    policy_path.write_text(yaml.safe_dump(policy_data), encoding="utf-8")

    jwks, headers = _auth_headers(team="product-eng")
    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={"content-type": "application/json"},
            json={
                "id": "chatcmpl-remap",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "chat-fast",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
        )

    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_path,
            model_router_base_url="http://mock-provider",
            jwt_jwks=jwks,
        ),
        model_router_transport=httpx.MockTransport(handler),
        redis_client=redis_client,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://control-plane",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-legacy",
                "messages": [{"role": "user", "content": "x" * 40}],
            },
            headers=headers,
        )
        assert resp.status_code == 200

    utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
    assert await redis_client.get(f"budget:product-eng:{utc_date}") == "20"
    await redis_client.aclose()
