from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from types import ModuleType
from typing import Any

import fakeredis
import httpx
import pytest
import yaml

from gateway_api.app import create_app
from gateway_api.config import ControlPlaneSettings
from mock_llm.app import create_app as create_mock_provider_app
from mock_llm.config import MockProviderSettings
from platform_common import load_policy_bundle
from scripts.generate_test_keys import generate_rsa_keypair, hash_api_key, mint_rs256_jwt

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_BUNDLE_PATH = REPO_ROOT / "policies" / "policy-bundle.yaml"
LITELLM_CONFIG_PATH = REPO_ROOT / "services" / "litellm-proxy" / "config.yaml"


def _test_auth_bundle() -> tuple[dict[str, Any], dict[str, str]]:
    keypair = generate_rsa_keypair()
    credential = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="router-test-actor",
        team="platform-eng",
        role="developer",
    )
    return keypair.jwks, {"Authorization": f"Bearer {credential}"}


def _load_validate_aliases_module() -> ModuleType:
    module_path = REPO_ROOT / "scripts" / "validate_aliases.py"
    spec = importlib.util.spec_from_file_location("validate_aliases", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


validate_policy_and_router_aliases = (
    _load_validate_aliases_module().validate_policy_and_router_aliases
)


def test_litellm_config_is_stateless_and_maps_policy_aliases_and_fallbacks() -> None:
    raw_text = LITELLM_CONFIG_PATH.read_text(encoding="utf-8")
    assert "database_url" not in raw_text.lower()

    config = yaml.safe_load(raw_text)
    assert isinstance(config, dict)

    general = config["general_settings"]
    assert general["master_key"] == "os.environ/LITELLM_MASTER_KEY"
    assert general["always_include_stream_usage"] is True

    litellm_settings = config["litellm_settings"]
    assert litellm_settings["drop_params"] is True
    assert litellm_settings["num_retries"] == 2
    assert litellm_settings["request_timeout"] == 15
    assert litellm_settings["fallbacks"] == [
        {"chat-default": ["chat-default-fallback"]},
        {"chat-fast": ["chat-fast-fallback"]},
        {"chat-premium": ["chat-premium-fallback"]},
    ]

    router_settings = config["router_settings"]
    assert router_settings["routing_strategy"] == "simple-shuffle"
    assert router_settings["num_retries"] == 2
    assert router_settings["timeout"] == 15
    assert router_settings["allowed_fails"] == 3
    assert router_settings["cooldown_time"] == 30

    loaded_policy = load_policy_bundle(POLICY_BUNDLE_PATH)
    entries = config["model_list"]
    by_name = {entry["model_name"]: entry for entry in entries}
    model_ids = [entry["model_info"]["id"] for entry in entries]
    assert len(model_ids) == len(set(model_ids))

    for alias in loaded_policy.bundle.models:
        assert alias in by_name
        primary_params = by_name[alias]["litellm_params"]
        assert primary_params["model"] == f"openai/{alias}"
        assert primary_params["api_base"] == "http://mock-llm-primary:8000/v1"

        fallback_alias = f"{alias}-fallback"
        assert fallback_alias in by_name
        fallback_params = by_name[fallback_alias]["litellm_params"]
        assert fallback_params["model"] == f"openai/{alias}"
        assert fallback_params["api_base"] == "http://mock-llm-fallback:8000/v1"

    assert "OPENAI_API_KEY" in raw_text
    assert "gemini/" in raw_text and "GEMINI_API_KEY" in raw_text
    assert ("hosted_vllm/" in raw_text or "openai/" in raw_text) and "vllm" in raw_text.lower()


def test_validate_aliases_passes_for_repo_bundle_and_router_config() -> None:
    validated = validate_policy_and_router_aliases(POLICY_BUNDLE_PATH, LITELLM_CONFIG_PATH)
    assert set(validated) == {"chat-default", "chat-fast", "chat-premium"}

    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "validate_aliases.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_validate_aliases_fails_when_policy_model_or_remapped_team_alias_missing(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "policy.yaml"
    router_path = tmp_path / "router.yaml"

    policy_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "v1",
                "models": {
                    "chat-default": {
                        "prompt_usd_per_1k_tokens": 0.001,
                        "completion_usd_per_1k_tokens": 0.002,
                    },
                    "chat-ghost": {
                        "prompt_usd_per_1k_tokens": 0.005,
                        "completion_usd_per_1k_tokens": 0.01,
                    },
                },
                "teams": {
                    "product-eng": {
                        "allowed_model_aliases": ["chat-default", "chat-team-only"],
                        "model_alias_remapping": {"chat-default": "chat-remapped-missing"},
                        "requests_per_minute": 60,
                        "daily_budget_usd": 10.0,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    router_path.write_text(
        yaml.safe_dump(
            {
                "model_list": [
                    {
                        "model_name": "chat-default",
                        "litellm_params": {"model": "openai/chat-default"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as exc_info:
        validate_policy_and_router_aliases(policy_path, router_path)

    message = str(exc_info.value)
    assert "chat-ghost" in message
    assert "chat-remapped-missing" in message
    assert "chat-team-only" in message

    proc = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "validate_aliases.py"),
            "--policy",
            str(policy_path),
            "--router-config",
            str(router_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "chat-ghost" in proc.stderr
    assert "chat-remapped-missing" in proc.stderr
    assert "chat-team-only" in proc.stderr


def test_validate_aliases_resolves_team_remapping_to_router_model_list(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    router_path = tmp_path / "router.yaml"

    policy_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "v1",
                "models": {
                    "chat-default": {
                        "prompt_usd_per_1k_tokens": 0.001,
                        "completion_usd_per_1k_tokens": 0.002,
                    }
                },
                "teams": {
                    "product-eng": {
                        "allowed_model_aliases": ["chat-legacy"],
                        "model_alias_remapping": {"chat-legacy": "chat-default"},
                        "requests_per_minute": 60,
                        "daily_budget_usd": 10.0,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    router_path.write_text(
        yaml.safe_dump(
            {
                "model_list": [
                    {
                        "model_name": "chat-default",
                        "litellm_params": {"model": "openai/chat-default"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    validated = validate_policy_and_router_aliases(policy_path, router_path)
    assert set(validated) == {"chat-default"}


def _wrap_capture_request_state(asgi_app: Any) -> tuple[Any, list[dict[str, Any]]]:
    """Capture ASGI scope['state'] after each request (including streaming) finishes."""
    captured: list[dict[str, Any]] = []

    async def middleware(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            scope.setdefault("state", {})
        try:
            await asgi_app(scope, receive, send)
        finally:
            if scope["type"] == "http":
                captured.append(dict(scope.get("state", {})))

    return middleware, captured


async def test_control_plane_forwards_master_key_and_records_primary_routing_metadata() -> None:
    observed_requests: list[httpx.Request] = []
    jwks, auth_headers = _test_auth_bundle()

    def handler(request: httpx.Request) -> httpx.Response:
        observed_requests.append(request)
        return httpx.Response(
            status_code=200,
            headers={
                "content-type": "application/json",
                "x-litellm-attempted-fallbacks": "0",
                "x-litellm-model-id": "chat-default-primary",
                "x-litellm-model-group": "chat-default",
            },
            json={
                "id": "chatcmpl-primary-1",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "chat-default",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 11,
                    "completion_tokens": 7,
                    "total_tokens": 18,
                },
            },
        )

    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://litellm-proxy:4000",
            model_router_api_key="master-secret-key",
            jwt_jwks=jwks,
        ),
        model_router_transport=httpx.MockTransport(handler),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
    )
    wrapped_app, captured_states = _wrap_capture_request_state(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=wrapped_app),
        base_url="http://control-plane",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Hello router"}],
                "stream": False,
            },
            headers=auth_headers,
        )

    assert resp.status_code == 200
    assert len(observed_requests) == 1
    assert observed_requests[0].headers["authorization"] == "Bearer master-secret-key"
    assert json.loads(observed_requests[0].content)["model"] == "chat-default"
    assert "stream_options" not in json.loads(observed_requests[0].content)

    assert resp.headers["x-routed-model"] == "chat-default-primary"
    assert resp.headers["x-fallback-used"] == "false"

    assert len(captured_states) == 1
    state = captured_states[0]
    assert state["routed_model"] == "chat-default-primary"
    assert state["fallback_used"] is False
    assert state["prompt_tokens"] == 11
    assert state["completion_tokens"] == 7
    assert state["total_tokens"] == 18


@pytest.mark.parametrize(
    ("litellm_headers", "expected_routed_model", "expected_fallback"),
    [
        (
            {
                "x-litellm-attempted-fallbacks": "1",
                "x-litellm-model-id": "fallback-1",
                "x-litellm-model-group": "chat-default-fallback",
            },
            "fallback-1",
            True,
        ),
        (
            {
                "x-litellm-attempted-fallbacks": "2",
                "x-litellm-model-group": "chat-fast-fallback",
            },
            "chat-fast-fallback",
            True,
        ),
        (
            {},
            "chat-fast",
            False,
        ),
    ],
)
async def test_control_plane_extracts_routed_model_and_fallback_from_litellm_headers(
    litellm_headers: dict[str, str],
    expected_routed_model: str,
    expected_fallback: bool,
) -> None:
    jwks, auth_headers = _test_auth_bundle()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={"content-type": "application/json", **litellm_headers},
            json={
                "id": "chatcmpl-test",
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
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
            },
        )

    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://litellm-proxy:4000",
            jwt_jwks=jwks,
        ),
        model_router_transport=httpx.MockTransport(handler),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
    )
    wrapped_app, captured_states = _wrap_capture_request_state(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=wrapped_app),
        base_url="http://control-plane",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "Test headers"}],
            },
            headers=auth_headers,
        )

    assert resp.status_code == 200
    assert resp.headers["x-routed-model"] == expected_routed_model
    assert resp.headers["x-fallback-used"] == ("true" if expected_fallback else "false")

    state = captured_states[0]
    assert state["routed_model"] == expected_routed_model
    assert state["fallback_used"] is expected_fallback


def _build_asgi_chat_request(
    payload: dict[str, Any],
    *,
    extra_headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any], Any, asyncio.Event]:
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


async def test_sse_streaming_injects_stream_options_and_records_usage_without_buffering() -> None:
    observed_bodies: list[dict[str, Any]] = []
    release_tail = asyncio.Event()

    class _GatedStreamingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            observed_bodies.append(json.loads(request.content))

            async def chunks() -> AsyncIterator[bytes]:
                yield (
                    b'data: {"id":"cmpl-1","object":"chat.completion.chunk",'
                    b'"created":1700000000,"model":"chat-default",'
                    b'"choices":[{"index":0,"delta":{"role":"assistant","content":"Hello "}}]}\n\n'
                )
                await release_tail.wait()
                # Split SSE event across byte boundaries to exercise incremental parsing
                usage_event = (
                    b'data: {"id":"cmpl-1","object":"chat.completion.chunk",'
                    b'"created":1700000000,"model":"chat-default",'
                    b'"choices":[{"index":0,"delta":{"content":"world"}}]}\n\n'
                    b'data: {"id":"cmpl-1","object":"chat.completion.chunk",'
                    b'"created":1700000000,"model":"chat-default","choices":[],'
                    b'"usage":{"prompt_tokens":9,"completion_tokens":14,"total_tokens":23}}\n\n'
                    b"data: [DONE]\n\n"
                )
                split_at = len(usage_event) // 2
                yield usage_event[:split_at]
                yield usage_event[split_at:]

            return httpx.Response(
                status_code=200,
                headers={
                    "content-type": "text/event-stream",
                    "x-litellm-attempted-fallbacks": "1",
                    "x-litellm-model-id": "fallback-1",
                    "x-litellm-model-group": "chat-default-fallback",
                },
                stream=_AsyncByteStream(chunks()),
            )

    jwks, auth_headers = _test_auth_bundle()
    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://litellm-proxy:4000",
            model_router_api_key="master-secret-key",
            jwt_jwks=jwks,
        ),
        model_router_transport=_GatedStreamingTransport(),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
    )
    wrapped_app, captured_states = _wrap_capture_request_state(app)

    scope, receive, _disconnect_event = _build_asgi_chat_request(
        {
            "model": "chat-default",
            "messages": [{"role": "user", "content": "Stream without stream_options"}],
            "stream": True,
        },
        extra_headers=auth_headers,
    )
    response_headers: dict[str, str] = {}
    response_status: int | None = None
    body_events: list[bytes] = []
    first_chunk_seen = asyncio.Event()

    async def send(message: dict[str, Any]) -> None:
        nonlocal response_status
        if message["type"] == "http.response.start":
            response_status = message["status"]
            for k, v in message["headers"]:
                response_headers[k.decode("latin-1").lower()] = v.decode("latin-1")
        elif message["type"] == "http.response.body":
            chunk = message.get("body", b"")
            if chunk:
                body_events.append(chunk)
                if b"Hello " in chunk:
                    first_chunk_seen.set()

    app_task = asyncio.create_task(wrapped_app(scope, receive, send))
    await asyncio.wait_for(first_chunk_seen.wait(), timeout=2.0)
    # First chunk arrived BEFORE upstream released the rest of the stream -> zero buffering!
    assert not release_tail.is_set()
    release_tail.set()
    await asyncio.wait_for(app_task, timeout=2.0)

    assert response_status == 200
    assert response_headers["x-routed-model"] == "fallback-1"
    assert response_headers["x-fallback-used"] == "true"

    assert len(observed_bodies) == 1
    assert observed_bodies[0]["stream_options"] == {"include_usage": True}

    full_sse = b"".join(body_events).decode("utf-8")
    data_lines = [
        line.removeprefix("data: ").strip()
        for line in full_sse.splitlines()
        if line.startswith("data: ")
    ]
    assert data_lines[-1] == "[DONE]"
    chunks = [json.loads(item) for item in data_lines[:-1]]
    usage_chunks = [c["usage"] for c in chunks if c.get("usage") is not None]
    assert usage_chunks == [{"prompt_tokens": 9, "completion_tokens": 14, "total_tokens": 23}]

    assert len(captured_states) == 1
    state = captured_states[0]
    assert state["routed_model"] == "fallback-1"
    assert state["fallback_used"] is True
    assert state["prompt_tokens"] == 9
    assert state["completion_tokens"] == 14
    assert state["total_tokens"] == 23
    assert state["streamed_completion_chars"] == len("Hello world")


class _AsyncByteStream(httpx.AsyncByteStream):
    def __init__(self, iterator: AsyncIterator[bytes]) -> None:
        self._iterator = iterator

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._iterator:
            yield chunk


class _FailoverRouterStubTransport(httpx.AsyncBaseTransport):
    """Minimal transport stub modeling LiteLLM primary-to-fallback failover over real mock apps."""

    def __init__(
        self,
        primary_app: Any,
        fallback_app: Any,
        *,
        primary_timeout_seconds: float = 0.08,
    ) -> None:
        self._primary = httpx.ASGITransport(app=primary_app)
        self._fallback = httpx.ASGITransport(app=fallback_app)
        self._primary_timeout_seconds = primary_timeout_seconds

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        model_alias = payload["model"]
        primary_req = httpx.Request(
            method=request.method,
            url=request.url,
            headers=request.headers,
            content=request.content,
        )
        try:
            primary_resp = await asyncio.wait_for(
                self._primary.handle_async_request(primary_req),
                timeout=self._primary_timeout_seconds,
            )
            if primary_resp.status_code < 500:
                body = await primary_resp.aread()
                await primary_resp.aclose()
                headers = dict(primary_resp.headers)
                headers.update(
                    {
                        "x-litellm-attempted-fallbacks": "0",
                        "x-litellm-model-id": "primary-1",
                        "x-litellm-model-group": model_alias,
                    }
                )
                return httpx.Response(
                    status_code=primary_resp.status_code,
                    headers=headers,
                    content=body,
                )
            await primary_resp.aclose()
        except (TimeoutError, httpx.TimeoutException):
            pass

        # Fail over to fallback provider (strip fault-injection directive for clean fallback)
        fallback_headers = {
            k: v for k, v in request.headers.items() if k.lower() != "x-mock-behavior"
        }
        fallback_req = httpx.Request(
            method=request.method,
            url=request.url,
            headers=fallback_headers,
            content=request.content,
        )
        fallback_resp = await self._fallback.handle_async_request(fallback_req)
        body = await fallback_resp.aread()
        await fallback_resp.aclose()
        headers = dict(fallback_resp.headers)
        headers.update(
            {
                "x-litellm-attempted-fallbacks": "1",
                "x-litellm-model-id": "fallback-1",
                "x-litellm-model-group": f"{model_alias}-fallback",
            }
        )
        return httpx.Response(
            status_code=fallback_resp.status_code,
            headers=headers,
            content=body,
        )


async def test_primary_to_fallback_failover_with_real_mock_providers_on_fault_and_timeout() -> None:
    jwks, auth_headers = _test_auth_bundle()
    primary_app = create_mock_provider_app(
        settings=MockProviderSettings(
            provider_name="mock-llm-primary",
            mock_mode_enabled=True,
            timeout_delay_ms=250,
        )
    )
    fallback_app = create_mock_provider_app(
        settings=MockProviderSettings(
            provider_name="mock-llm-fallback",
            mock_mode_enabled=True,
        )
    )
    control_plane_app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://litellm-proxy:4000",
            model_router_api_key="master-secret-key",
            mock_mode_enabled=True,
            jwt_jwks=jwks,
        ),
        model_router_transport=_FailoverRouterStubTransport(primary_app, fallback_app),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
    )
    wrapped_app, captured_states = _wrap_capture_request_state(control_plane_app)

    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=primary_app),
            base_url="http://mock-llm-primary",
        ) as primary_admin,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=wrapped_app),
            base_url="http://control-plane",
        ) as client,
    ):
        # 1. Normal primary call
        primary_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Primary check"}],
            },
            headers=auth_headers,
        )
        assert primary_resp.status_code == 200
        assert "mock-llm-primary" in primary_resp.json()["choices"][0]["message"]["content"]
        assert primary_resp.headers["x-routed-model"] == "primary-1"
        assert primary_resp.headers["x-fallback-used"] == "false"
        assert captured_states[-1]["fallback_used"] is False

        # 2. Primary /admin/fault -> automatic failover for JSON and SSE
        fault_on = await primary_admin.post(
            "/admin/fault",
            json={"enabled": True, "mode": "fail_503"},
        )
        assert fault_on.status_code == 200

        fallback_json = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Failover JSON check"}],
            },
            headers=auth_headers,
        )
        assert fallback_json.status_code == 200
        assert "mock-llm-fallback" in fallback_json.json()["choices"][0]["message"]["content"]
        assert fallback_json.headers["x-routed-model"] == "fallback-1"
        assert fallback_json.headers["x-fallback-used"] == "true"
        assert captured_states[-1]["fallback_used"] is True
        assert captured_states[-1]["routed_model"] == "fallback-1"

        async with client.stream(
            "POST",
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Failover SSE check"}],
                "stream": True,
            },
            headers=auth_headers,
        ) as sse_resp:
            assert sse_resp.status_code == 200
            assert sse_resp.headers["x-routed-model"] == "fallback-1"
            assert sse_resp.headers["x-fallback-used"] == "true"
            data_lines = [
                line.removeprefix("data: ").strip()
                async for line in sse_resp.aiter_lines()
                if line.startswith("data: ")
            ]

        assert data_lines[-1] == "[DONE]"
        chunks = [json.loads(item) for item in data_lines[:-1]]
        usage_chunks = [c["usage"] for c in chunks if c.get("usage") is not None]
        assert len(usage_chunks) == 1
        assert captured_states[-1]["fallback_used"] is True
        assert captured_states[-1]["routed_model"] == "fallback-1"
        assert captured_states[-1]["prompt_tokens"] == usage_chunks[0]["prompt_tokens"]
        assert captured_states[-1]["completion_tokens"] == usage_chunks[0]["completion_tokens"]

        await primary_admin.post("/admin/fault", json={"enabled": False})

        # 3. Primary timeout -> automatic failover
        timeout_failover = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "Timeout failover check"}],
            },
            headers={**auth_headers, "X-Mock-Behavior": "timeout"},
        )
        assert timeout_failover.status_code == 200
        assert "mock-llm-fallback" in timeout_failover.json()["choices"][0]["message"]["content"]
        assert timeout_failover.headers["x-routed-model"] == "fallback-1"
        assert timeout_failover.headers["x-fallback-used"] == "true"
        assert captured_states[-1]["fallback_used"] is True


async def test_sse_disconnect_tracks_streamed_chars_and_closes_upstream_without_usage() -> None:
    upstream_closed = asyncio.Event()
    first_chunk_sent = asyncio.Event()
    release_or_cancel = asyncio.Event()

    class _TrackedStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield (
                b'data: {"id":"cmpl-disc","object":"chat.completion.chunk",'
                b'"created":1700000000,"model":"chat-default",'
                b'"choices":[{"index":0,"delta":{"content":"partial output"}}]}\n\n'
            )
            await release_or_cancel.wait()

        async def aclose(self) -> None:
            upstream_closed.set()

    class _DisconnectTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, _request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=200,
                headers={
                    "content-type": "text/event-stream",
                    "x-litellm-attempted-fallbacks": "0",
                    "x-litellm-model-id": "chat-default-primary",
                },
                stream=_TrackedStream(),
            )

    jwks, auth_headers = _test_auth_bundle()
    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://litellm-proxy:4000",
            jwt_jwks=jwks,
        ),
        model_router_transport=_DisconnectTransport(),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
    )
    wrapped_app, captured_states = _wrap_capture_request_state(app)

    scope, receive, disconnect_event = _build_asgi_chat_request(
        {
            "model": "chat-default",
            "messages": [{"role": "user", "content": "Disconnect mid-stream"}],
            "stream": True,
        },
        extra_headers=auth_headers,
    )

    async def send(message: dict[str, Any]) -> None:
        chunk = message.get("body", b"")
        if message["type"] == "http.response.body" and b"partial output" in chunk:
            first_chunk_sent.set()

    app_task = asyncio.create_task(wrapped_app(scope, receive, send))
    await asyncio.wait_for(first_chunk_sent.wait(), timeout=2.0)
    disconnect_event.set()
    await asyncio.wait_for(app_task, timeout=2.0)

    assert upstream_closed.is_set()
    state = captured_states[0]
    assert state["routed_model"] == "chat-default-primary"
    assert state["fallback_used"] is False
    assert state["prompt_tokens"] is None
    assert state["completion_tokens"] is None
    assert state["streamed_completion_chars"] == len("partial output")


async def test_caller_auth_not_leaked_when_router_key_unset_and_target_model_honored(
    tmp_path: Path,
) -> None:
    observed_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed_requests.append(request)
        return httpx.Response(
            status_code=200,
            headers={"content-type": "application/json"},
            json={
                "id": "chatcmpl-remap",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "chat-default",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

    policy_data = yaml.safe_load(POLICY_BUNDLE_PATH.read_text(encoding="utf-8"))
    policy_data["teams"]["platform-eng"]["allowed_model_aliases"].append("chat-legacy")
    policy_data["teams"]["platform-eng"]["model_alias_remapping"] = {"chat-legacy": "chat-default"}
    policy_copy = tmp_path / "policy-bundle.yaml"
    policy_copy.write_text(yaml.safe_dump(policy_data), encoding="utf-8")

    caller_api_key = "sk-gw-caller-secret"
    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=policy_copy,
            model_router_base_url="http://litellm-proxy:4000",
            model_router_api_key=None,
            api_keys={
                hash_api_key(caller_api_key): {
                    "actor_id": "caller-1",
                    "team": "platform-eng",
                    "role": "developer",
                }
            },
        ),
        model_router_transport=httpx.MockTransport(handler),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
    )
    wrapped_app, captured = _wrap_capture_request_state(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=wrapped_app),
        base_url="http://control-plane",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-legacy",
                "messages": [{"role": "user", "content": "Remapped"}],
            },
            headers={"Authorization": f"Bearer {caller_api_key}"},
        )

    assert resp.status_code == 200
    assert "authorization" not in observed_requests[0].headers
    assert json.loads(observed_requests[0].content)["model"] == "chat-default"
    assert resp.headers["x-routed-model"] == "chat-default"
    assert resp.headers["x-fallback-used"] == "false"
    assert captured[0]["routed_model"] == "chat-default"
    assert captured[0]["target_model"] == "chat-default"
