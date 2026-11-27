"""Offline HTTP-seam tests for Guarded MCP Runtime and Control Plane /mcp forwarding."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import fakeredis
import httpx
import jwt
import pytest
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client.parser import text_string_to_metric_families
from redis.exceptions import RedisError

from gateway_api.app import create_app as create_gateway_app
from gateway_api.config import ControlPlaneSettings
from mcp_runtime.app import create_app as create_mcp_app
from mcp_runtime.config import MCPRuntimeSettings
from platform_common import (
    INTERNAL_IDENTITY_AUDIENCE,
    INTERNAL_IDENTITY_HEADER,
    INTERNAL_IDENTITY_ISSUER,
    MIN_INTERNAL_IDENTITY_SECRET_BYTES,
    ActorContext,
    AuditEvent,
    InternalIdentityAssertion,
    InternalIdentityError,
    PolicyDefaults,
    authorize_mcp_tool,
    load_policy_bundle,
    sign_internal_identity_assertion,
    validate_internal_identity_secret,
    verify_internal_identity_assertion,
)
from scripts.generate_test_keys import (
    DEFAULT_HS256_SECRET,
    generate_rsa_keypair,
    generate_scoped_api_key,
    mint_hs256_jwt,
    mint_rs256_jwt,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_BUNDLE_PATH = REPO_ROOT / "policies" / "policy-bundle.yaml"
TEST_INTERNAL_SECRET = "internal-mcp-identity-signing-secret-32b"
MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def test_internal_identity_sign_verify_and_reject_invalid_assertions() -> None:
    assert INTERNAL_IDENTITY_HEADER == "x-internal-actor-assertion"
    assert INTERNAL_IDENTITY_ISSUER == "ai-gateway-control-plane"
    assert INTERNAL_IDENTITY_AUDIENCE == "ai-gateway-mcp-runtime"
    assert MIN_INTERNAL_IDENTITY_SECRET_BYTES == 32

    actor = ActorContext(
        actor_id="dev-alice",
        team="platform-eng",
        role="developer",
        auth_method="jwt",
    )
    now = int(time.time())
    assertion_jwt = sign_internal_identity_assertion(
        actor=actor,
        run_id="run-slice-1",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        secret=TEST_INTERNAL_SECRET,
        ttl_seconds=30,
        now=now,
    )
    verified = verify_internal_identity_assertion(assertion_jwt, secret=TEST_INTERNAL_SECRET)
    assert isinstance(verified, InternalIdentityAssertion)
    assert verified.actor_id == "dev-alice"
    assert verified.team == "platform-eng"
    assert verified.role == "developer"
    assert verified.run_id == "run-slice-1"
    assert verified.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert verified.iat == now
    assert verified.exp == now + 30
    assert verified.jti

    with pytest.raises(InternalIdentityError) as missing_exc:
        verify_internal_identity_assertion(None, secret=TEST_INTERNAL_SECRET)
    assert missing_exc.value.code == "missing_assertion"

    expired_assertion = sign_internal_identity_assertion(
        actor=actor,
        run_id="run-expired",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        secret=TEST_INTERNAL_SECRET,
        ttl_seconds=10,
        now=now - 60,
    )
    with pytest.raises(InternalIdentityError) as expired_exc:
        verify_internal_identity_assertion(expired_assertion, secret=TEST_INTERNAL_SECRET)
    assert expired_exc.value.code == "expired_assertion"

    with pytest.raises(InternalIdentityError) as wrong_secret_exc:
        verify_internal_identity_assertion(
            assertion_jwt,
            secret="wrong-internal-mcp-identity-secret-32b",
        )
    assert wrong_secret_exc.value.code == "invalid_assertion"

    alg_none_assertion = jwt.encode(
        {
            "iss": INTERNAL_IDENTITY_ISSUER,
            "aud": INTERNAL_IDENTITY_AUDIENCE,
            "sub": "dev-alice",
            "actor_id": "dev-alice",
            "team": "platform-eng",
            "role": "admin",
            "run_id": "run-alg-none",
            "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
            "iat": now,
            "exp": now + 30,
        },
        None,
        algorithm="none",
    )
    with pytest.raises(InternalIdentityError) as alg_none_exc:
        verify_internal_identity_assertion(alg_none_assertion, secret=TEST_INTERNAL_SECRET)
    assert alg_none_exc.value.code == "invalid_assertion"

    with pytest.raises(ValueError):
        sign_internal_identity_assertion(
            actor=actor,
            run_id="run-short",
            trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
            secret="too-short",
        )

    with pytest.raises(ValueError):
        verify_internal_identity_assertion(assertion_jwt, secret="too-short")


def test_validate_internal_identity_secret_and_authorize_mcp_tool() -> None:
    assert validate_internal_identity_secret(TEST_INTERNAL_SECRET) == TEST_INTERNAL_SECRET
    for bad_secret in (None, "", "too-short"):
        with pytest.raises(ValueError):
            validate_internal_identity_secret(bad_secret)

    policy = load_policy_bundle(POLICY_BUNDLE_PATH).bundle
    assert authorize_mcp_tool(
        policy,
        team="unknown-team",
        role="developer",
        tool_name="query_runbook",
    ) == (False, "team_not_allowed")
    assert authorize_mcp_tool(
        policy,
        team="product-eng",
        role="developer",
        tool_name="lookup_service_slo",
    ) == (False, "mcp_tool_not_allowed")
    assert authorize_mcp_tool(
        policy,
        team="product-eng",
        role="developer",
        tool_name="check_model_catalog",
        target_team="platform-eng",
    ) == (False, "mcp_cross_team_denied")
    assert authorize_mcp_tool(
        policy,
        team="platform-eng",
        role="admin",
        tool_name="check_model_catalog",
        target_team="product-eng",
    ) == (True, None)
    assert authorize_mcp_tool(
        policy,
        team="ops-eng",
        role="ops",
        tool_name="lookup_service_slo",
    ) == (True, None)


def test_audit_event_outcome_and_policy_defaults_mcp_fields_are_backward_compatible() -> None:
    defaults = PolicyDefaults()
    assert defaults.mcp_tool_timeout_seconds == 5.0
    assert defaults.mcp_max_tool_calls_per_run == 5
    assert defaults.mcp_run_ttl_seconds == 3600

    event = AuditEvent(
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        request_id="req-1",
        actor_id="dev-alice",
        team="platform-eng",
        role="developer",
        policy_version="v1+deadbeef",
        policy_action="allow",
        status_code=200,
    )
    assert event.outcome is None

    mcp_event = AuditEvent(
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        request_id="req-2",
        actor_id="dev-alice",
        team="platform-eng",
        role="developer",
        tool_name="query_runbook",
        run_id="run-1",
        policy_version="v1+deadbeef",
        policy_action="allow",
        status_code=200,
        outcome="allowed",
    )
    assert mcp_event.outcome == "allowed"


def _jsonrpc_call(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    rpc_id: int = 1,
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": method,
        "params": params or {},
    }


def _extract_tool_json(rpc_response: dict[str, Any]) -> dict[str, Any]:
    result = rpc_response["result"]
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


async def test_mcp_runtime_healthz_and_readyz_fail_closed_on_missing_secret_or_redis() -> None:
    events: list[AuditEvent] = []
    app_no_secret = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=None,
            require_redis=True,
        ),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        audit_sink=events,
    )
    app_no_redis = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
            require_redis=True,
        ),
        redis_client=None,
        audit_sink=events,
    )
    app_ready = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
            require_redis=True,
        ),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        audit_sink=events,
    )

    async with (
        app_no_secret.router.lifespan_context(app_no_secret),
        app_no_redis.router.lifespan_context(app_no_redis),
        app_ready.router.lifespan_context(app_ready),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_no_secret),
            base_url="http://mcp-runtime",
        ) as c_no_secret,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_no_redis),
            base_url="http://mcp-runtime",
        ) as c_no_redis,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_ready),
            base_url="http://mcp-runtime",
        ) as c_ready,
    ):
        assert (await c_no_secret.get("/healthz")).status_code == 200
        assert (await c_no_secret.get("/readyz")).status_code == 503
        assert (await c_no_redis.get("/readyz")).status_code == 503
        ready_resp = await c_ready.get("/readyz")
        assert ready_resp.status_code == 200
        assert ready_resp.json()["status"] == "ready"
        assert ready_resp.json()["policy_version"].startswith("v1+")
        assert events == []


async def test_mcp_runtime_direct_subseam_rejects_untrusted_assertions(
    caplog: pytest.LogCaptureFixture,
) -> None:
    events: list[AuditEvent] = []
    mcp_app = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
            require_redis=True,
        ),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        audit_sink=events,
    )

    actor = ActorContext(actor_id="ops-actor", team="ops-eng", role="ops", auth_method="jwt")
    now = int(time.time())
    valid_assertion = sign_internal_identity_assertion(
        actor=actor,
        run_id="run-direct-1",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        secret=TEST_INTERNAL_SECRET,
        ttl_seconds=30,
        now=now,
    )
    expired_assertion = sign_internal_identity_assertion(
        actor=actor,
        run_id="run-direct-expired",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        secret=TEST_INTERNAL_SECRET,
        ttl_seconds=5,
        now=now - 60,
    )
    wrong_secret_assertion = sign_internal_identity_assertion(
        actor=actor,
        run_id="run-direct-wrong-secret",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        secret="another-secret-that-does-not-match-32b",
        ttl_seconds=30,
        now=now,
    )
    alg_none_assertion = jwt.encode(
        {
            "iss": INTERNAL_IDENTITY_ISSUER,
            "aud": INTERNAL_IDENTITY_AUDIENCE,
            "sub": "ops-actor",
            "actor_id": "ops-actor",
            "team": "ops-eng",
            "role": "admin",
            "run_id": "run-direct-alg-none",
            "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
            "iat": now,
            "exp": now + 30,
        },
        None,
        algorithm="none",
    )

    header_b64, payload_b64, sig_b64 = valid_assertion.split(".")
    tampered_claims = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    tampered_claims["role"] = "admin"
    tampered_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(tampered_claims).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    tampered_assertion = f"{header_b64}.{tampered_payload_b64}.{sig_b64}"

    bad_assertions = [
        ("missing", None),
        ("expired", expired_assertion),
        ("tampered", tampered_assertion),
        ("wrong_secret", wrong_secret_assertion),
        ("alg_none", alg_none_assertion),
    ]

    with caplog.at_level(logging.INFO, logger="mcp_runtime.audit"):
        async with (
            mcp_app.router.lifespan_context(mcp_app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=mcp_app),
                base_url="http://mcp-runtime",
            ) as client,
        ):
            for _label, assertion_jwt in bad_assertions:
                headers = dict(MCP_HEADERS)
                if assertion_jwt is not None:
                    headers[INTERNAL_IDENTITY_HEADER] = assertion_jwt
                resp = await client.post(
                    "/mcp",
                    json=_jsonrpc_call("tools/list"),
                    headers=headers,
                )
                assert resp.status_code == 401
                body = resp.json()
                assert body["jsonrpc"] == "2.0"
                assert "error" in body

    assert len(events) == len(bad_assertions)
    for event in events:
        assert event.status_code == 401
        assert event.policy_action == "deny"
        assert event.outcome == "auth_denied"
        assert event.actor_id == "anonymous"
        assert TEST_INTERNAL_SECRET not in event.model_dump_json()
        assert valid_assertion not in event.model_dump_json()


async def test_mcp_runtime_direct_subseam_executes_tools_with_valid_assertion() -> None:
    events: list[AuditEvent] = []
    mcp_app = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
            require_redis=True,
        ),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        audit_sink=events,
    )
    actor = ActorContext(actor_id="ops-alice", team="ops-eng", role="ops", auth_method="jwt")
    assertion = sign_internal_identity_assertion(
        actor=actor,
        run_id="run-direct-ok",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        secret=TEST_INTERNAL_SECRET,
    )
    headers = {**MCP_HEADERS, INTERNAL_IDENTITY_HEADER: assertion}

    async with (
        mcp_app.router.lifespan_context(mcp_app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mcp_app),
            base_url="http://mcp-runtime",
        ) as client,
    ):
        list_resp = await client.post("/mcp", json=_jsonrpc_call("tools/list"), headers=headers)
        assert list_resp.status_code == 200
        tool_names = {t["name"] for t in list_resp.json()["result"]["tools"]}
        assert tool_names == {"check_model_catalog", "query_runbook", "lookup_service_slo"}

        runbook_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "query_runbook", "arguments": {"query": "failover"}},
                rpc_id=2,
            ),
            headers=headers,
        )
        assert runbook_resp.status_code == 200
        runbook_data = _extract_tool_json(runbook_resp.json())
        assert runbook_data["match_count"] >= 1

        catalog_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "check_model_catalog", "arguments": {"team": "ops-eng"}},
                rpc_id=3,
            ),
            headers=headers,
        )
        assert catalog_resp.status_code == 200
        catalog_data = _extract_tool_json(catalog_resp.json())
        assert catalog_data["team"] == "ops-eng"
        assert catalog_data["allowed_model_aliases"] == ["chat-default", "chat-fast"]

        slo_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "lookup_service_slo", "arguments": {"service_name": "gateway-api"}},
                rpc_id=4,
            ),
            headers=headers,
        )
        assert slo_resp.status_code == 200
        slo_data = _extract_tool_json(slo_resp.json())
        assert slo_data["service_name"] == "gateway-api"
        assert slo_data["found"] is True

    assert [e.outcome for e in events] == ["allowed", "allowed", "allowed", "allowed"]
    assert [e.tool_name for e in events] == [
        None,
        "query_runbook",
        "check_model_catalog",
        "lookup_service_slo",
    ]


class RecordingTransport(httpx.AsyncBaseTransport):
    """Wrap an ASGI transport to capture forwarded HTTP requests."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


def _build_gateway_with_mcp(
    *,
    mcp_app: Any | None = None,
    mcp_transport: httpx.AsyncBaseTransport | None = None,
    internal_secret: str | None = TEST_INTERNAL_SECRET,
    jwks: dict[str, Any] | None = None,
    api_keys: dict[str, Any] | None = None,
    gateway_events: list[AuditEvent] | None = None,
    gateway_timeout_seconds: float = 30.0,
    gateway_tracer_provider: Any | None = None,
) -> tuple[Any, RecordingTransport | None]:
    recorder: RecordingTransport | None = None
    resolved_transport = mcp_transport
    if resolved_transport is None and mcp_app is not None:
        recorder = RecordingTransport(httpx.ASGITransport(app=mcp_app))
        resolved_transport = recorder

    gateway_app = create_gateway_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://unused-model-router",
            mcp_runtime_base_url="http://mcp-runtime",
            mcp_runtime_timeout_seconds=gateway_timeout_seconds,
            internal_identity_secret=internal_secret,
            jwt_jwks=jwks,
            api_keys=api_keys,
        ),
        mcp_runtime_transport=resolved_transport,
        audit_sink=gateway_events,
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        tracer_provider=gateway_tracer_provider,
    )
    return gateway_app, recorder


async def test_control_plane_mcp_forwarding_rejects_unauthenticated_and_invalid_credentials() -> (
    None
):
    keypair = generate_rsa_keypair(seed="mcp-auth-test")
    mcp_events: list[AuditEvent] = []
    gateway_events: list[AuditEvent] = []
    mcp_app = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
        ),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        audit_sink=mcp_events,
    )
    gateway_app, recorder = _build_gateway_with_mcp(
        mcp_app=mcp_app,
        jwks=keypair.jwks,
        gateway_events=gateway_events,
    )
    assert recorder is not None

    async with (
        mcp_app.router.lifespan_context(mcp_app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway_app),
            base_url="http://control-plane",
        ) as client,
    ):
        missing_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "query_runbook", "arguments": {"query": "x"}},
            ),
            headers=MCP_HEADERS,
        )
        assert missing_resp.status_code == 401

        bad_jwt_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call("tools/list"),
            headers={**MCP_HEADERS, "Authorization": "Bearer invalid.jwt.token"},
        )
        assert bad_jwt_resp.status_code == 401

        bad_key_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call("tools/list"),
            headers={**MCP_HEADERS, "Authorization": "Bearer sk-gw-unknown-key"},
        )
        assert bad_key_resp.status_code == 401

    assert recorder.requests == []
    assert mcp_events == []
    assert len(gateway_events) == 3
    assert all(e.status_code == 401 and e.policy_action == "deny" for e in gateway_events)
    assert gateway_events[0].tool_name == "query_runbook"
    assert gateway_events[0].run_id is not None and gateway_events[0].run_id.startswith("run-")


async def test_control_plane_mcp_forwarding_fails_closed_when_internal_secret_unconfigured() -> (
    None
):
    keypair = generate_rsa_keypair(seed="mcp-secret-test")
    jwt_credential = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="ops-bob",
        team="ops-eng",
        role="ops",
    )

    for bad_secret in (None, "short-secret"):
        local_mcp_app = create_mcp_app(
            settings=MCPRuntimeSettings(
                policy_bundle_path=POLICY_BUNDLE_PATH,
                internal_identity_secret=TEST_INTERNAL_SECRET,
            ),
            redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        )
        gateway_events: list[AuditEvent] = []
        gateway_app, recorder = _build_gateway_with_mcp(
            mcp_app=local_mcp_app,
            internal_secret=bad_secret,
            jwks=keypair.jwks,
            gateway_events=gateway_events,
        )
        assert recorder is not None
        async with (
            local_mcp_app.router.lifespan_context(local_mcp_app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gateway_app),
                base_url="http://control-plane",
            ) as client,
        ):
            resp = await client.post(
                "/mcp",
                json=_jsonrpc_call("tools/list"),
                headers={**MCP_HEADERS, "Authorization": f"Bearer {jwt_credential}"},
            )
            assert resp.status_code == 503
        assert recorder.requests == []
        assert gateway_events[0].policy_action == "error"
        assert gateway_events[0].status_code == 503


async def test_control_plane_mcp_forwarding_strips_auth_mints_assertion_and_routes() -> None:
    keypair = generate_rsa_keypair(seed="mcp-e2e-test")
    ops_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="ops-carol",
        team="ops-eng",
        role="ops",
    )
    dev_api_key = generate_scoped_api_key(
        actor_id="prod-dev-dave",
        team="product-eng",
        role="developer",
        seed="mcp-e2e-test",
    )
    api_keys_store = {"api_keys": {dev_api_key.sha256: dev_api_key.to_store_entry()}}

    mcp_events: list[AuditEvent] = []
    gateway_events: list[AuditEvent] = []
    mcp_app = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
        ),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        audit_sink=mcp_events,
    )
    gateway_app, recorder = _build_gateway_with_mcp(
        mcp_app=mcp_app,
        jwks=keypair.jwks,
        api_keys=api_keys_store,
        gateway_events=gateway_events,
    )
    assert recorder is not None

    async with (
        mcp_app.router.lifespan_context(mcp_app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway_app),
            base_url="http://control-plane",
        ) as client,
    ):
        # 1. initialize + notifications/initialized + tools/list
        init_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0"},
                },
            ),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {ops_jwt}",
            },
        )
        assert init_resp.status_code == 200
        assert "serverInfo" in init_resp.json()["result"]

        notif_resp = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {ops_jwt}",
            },
        )
        assert notif_resp.status_code == 202

        list_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call("tools/list"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {ops_jwt}",
                INTERNAL_IDENTITY_HEADER: "spoofed-actor-assertion",
            },
        )
        assert list_resp.status_code == 200
        assert re.fullmatch(r"run-[0-9a-f]{16}", list_resp.headers["x-run-id"])
        assert list_resp.headers["x-policy-version"].startswith("v1+")
        assert re.fullmatch(r"[0-9a-f]{32}", list_resp.headers["x-trace-id"])
        tool_names = {t["name"] for t in list_resp.json()["result"]["tools"]}
        assert tool_names == {"check_model_catalog", "query_runbook", "lookup_service_slo"}

        slo_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "lookup_service_slo", "arguments": {"service_name": "litellm-proxy"}},
                rpc_id=2,
            ),
            headers={
                **MCP_HEADERS,
                "Authorization": f"Bearer {ops_jwt}",
                "X-Run-Id": "run-explicit-ops-1",
            },
        )
        assert slo_resp.status_code == 200
        assert slo_resp.headers["x-run-id"] == "run-explicit-ops-1"
        assert _extract_tool_json(slo_resp.json())["service_name"] == "litellm-proxy"

        catalog_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "check_model_catalog", "arguments": {"team": "product-eng"}},
                rpc_id=3,
            ),
            headers={
                **MCP_HEADERS,
                "Authorization": f"Bearer {dev_api_key.plaintext_key}",
                "X-Run-Id": "run-explicit-dev-1",
            },
        )
        assert catalog_resp.status_code == 200
        catalog_data = _extract_tool_json(catalog_resp.json())
        assert catalog_data["team"] == "product-eng"
        assert catalog_data["allowed_model_aliases"] == ["chat-default", "chat-fast"]

        del_resp = await client.delete(
            "/mcp",
            headers={"Authorization": f"Bearer {ops_jwt}"},
        )
        assert del_resp.status_code == 405

    assert len(recorder.requests) == 6
    for req in recorder.requests:
        assert "authorization" not in req.headers
        assertion_hdr = req.headers.get(INTERNAL_IDENTITY_HEADER)
        assert assertion_hdr is not None
        assert assertion_hdr != "spoofed-actor-assertion"
        assert "application/json" in req.headers.get("accept", "")
        assert "text/event-stream" in req.headers.get("accept", "")

    verified_list_req = verify_internal_identity_assertion(
        recorder.requests[2].headers[INTERNAL_IDENTITY_HEADER],
        secret=TEST_INTERNAL_SECRET,
    )
    assert verified_list_req.actor_id == "ops-carol"
    assert verified_list_req.team == "ops-eng"
    assert verified_list_req.role == "ops"
    assert verified_list_req.run_id == list_resp.headers["x-run-id"]

    verified_req_3 = verify_internal_identity_assertion(
        recorder.requests[4].headers[INTERNAL_IDENTITY_HEADER],
        secret=TEST_INTERNAL_SECRET,
    )
    assert verified_req_3.actor_id == "prod-dev-dave"
    assert verified_req_3.team == "product-eng"
    assert verified_req_3.role == "developer"
    assert verified_req_3.run_id == "run-explicit-dev-1"

    # Also verify GET /mcp SSE passthrough through the Control Plane
    class _SseGetTransport(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.requests: list[httpx.Request] = []

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=b"event: endpoint\ndata: /mcp\n\n",
            )

    sse_transport = _SseGetTransport()
    gw_sse, _ = _build_gateway_with_mcp(mcp_transport=sse_transport, jwks=keypair.jwks)
    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gw_sse),
            base_url="http://control-plane",
        ) as sse_client,
        sse_client.stream(
            "GET",
            "/mcp",
            headers={"Authorization": f"Bearer {ops_jwt}", "Accept": "text/event-stream"},
        ) as get_resp,
    ):
        assert get_resp.status_code == 200
        assert "text/event-stream" in get_resp.headers.get("content-type", "")
        sse_body = await get_resp.aread()
        assert b"event: endpoint" in sse_body

    assert len(sse_transport.requests) == 1
    assert sse_transport.requests[0].method == "GET"
    assert "authorization" not in sse_transport.requests[0].headers
    assert INTERNAL_IDENTITY_HEADER in sse_transport.requests[0].headers


async def test_control_plane_mcp_forwarding_returns_502_and_504_on_upstream_failures() -> None:
    keypair = generate_rsa_keypair(seed="mcp-errors-test")
    jwt_credential = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="ops-erin",
        team="ops-eng",
        role="ops",
    )

    class _UnreachableTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused", request=request)

    class _SlowTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0.25)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    gw_unreachable, _ = _build_gateway_with_mcp(
        mcp_transport=_UnreachableTransport(),
        jwks=keypair.jwks,
    )
    gw_timeout, _ = _build_gateway_with_mcp(
        mcp_transport=_SlowTransport(),
        jwks=keypair.jwks,
        gateway_timeout_seconds=0.05,
    )

    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gw_unreachable),
            base_url="http://control-plane",
        ) as c_unreach,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gw_timeout),
            base_url="http://control-plane",
        ) as c_timeout,
    ):
        resp_502 = await c_unreach.post(
            "/mcp",
            json=_jsonrpc_call("tools/list"),
            headers={**MCP_HEADERS, "Authorization": f"Bearer {jwt_credential}"},
        )
        assert resp_502.status_code == 502

        resp_504 = await c_timeout.post(
            "/mcp",
            json=_jsonrpc_call("tools/list"),
            headers={**MCP_HEADERS, "Authorization": f"Bearer {jwt_credential}"},
        )
        assert resp_504.status_code == 504


async def test_control_plane_mcp_rbac_developer_ops_admin_and_cross_team_denial() -> None:
    keypair = generate_rsa_keypair(seed="mcp-rbac-test")
    dev_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="prod-dev-1",
        team="product-eng",
        role="developer",
    )
    ops_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="ops-actor-1",
        team="ops-eng",
        role="ops",
    )
    admin_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="platform-admin-1",
        team="platform-eng",
        role="admin",
    )

    redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)
    mcp_events: list[AuditEvent] = []
    gateway_events: list[AuditEvent] = []
    mcp_app = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
        ),
        redis_client=redis_client,
        audit_sink=mcp_events,
    )
    gateway_app, _ = _build_gateway_with_mcp(
        mcp_app=mcp_app,
        jwks=keypair.jwks,
        gateway_events=gateway_events,
    )

    async with (
        mcp_app.router.lifespan_context(mcp_app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway_app),
            base_url="http://control-plane",
        ) as client,
    ):
        # 1. developer denied lookup_service_slo (403)
        dev_slo = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "lookup_service_slo", "arguments": {"service_name": "gateway-api"}},
                rpc_id=1,
            ),
            headers={**MCP_HEADERS, "Authorization": f"Bearer {dev_jwt}", "X-Run-Id": "run-dev"},
        )
        assert dev_slo.status_code == 403
        assert dev_slo.headers["x-policy-denial-reason"] == "mcp_tool_not_allowed"

        # 2. developer denied cross-Team check_model_catalog (403)
        dev_cross = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "check_model_catalog", "arguments": {"team": "platform-eng"}},
                rpc_id=2,
            ),
            headers={**MCP_HEADERS, "Authorization": f"Bearer {dev_jwt}", "X-Run-Id": "run-dev"},
        )
        assert dev_cross.status_code == 403
        assert dev_cross.headers["x-policy-denial-reason"] == "mcp_cross_team_denied"

        # 3. developer allowed query_runbook and own-Team check_model_catalog;
        #    prior 403 denials must NOT have consumed loop cap!
        dev_runbook = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "query_runbook", "arguments": {"query": "redis"}},
                rpc_id=3,
            ),
            headers={**MCP_HEADERS, "Authorization": f"Bearer {dev_jwt}", "X-Run-Id": "run-dev"},
        )
        assert dev_runbook.status_code == 200
        assert dev_runbook.headers["x-mcp-run-calls"] == "1"

        dev_own = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "check_model_catalog", "arguments": {"team": "product-eng"}},
                rpc_id=4,
            ),
            headers={**MCP_HEADERS, "Authorization": f"Bearer {dev_jwt}", "X-Run-Id": "run-dev"},
        )
        assert dev_own.status_code == 200
        assert _extract_tool_json(dev_own.json())["team"] == "product-eng"
        assert dev_own.headers["x-mcp-run-calls"] == "2"

        # 4. ops allowed lookup_service_slo, denied cross-Team check_model_catalog
        ops_slo = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "lookup_service_slo", "arguments": {"service_name": "redis"}},
                rpc_id=5,
            ),
            headers={**MCP_HEADERS, "Authorization": f"Bearer {ops_jwt}", "X-Run-Id": "run-ops"},
        )
        assert ops_slo.status_code == 200
        assert _extract_tool_json(ops_slo.json())["availability_target"] == 0.9995

        ops_cross = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "check_model_catalog", "arguments": {"team": "platform-eng"}},
                rpc_id=6,
            ),
            headers={**MCP_HEADERS, "Authorization": f"Bearer {ops_jwt}", "X-Run-Id": "run-ops"},
        )
        assert ops_cross.status_code == 403
        assert ops_cross.headers["x-policy-denial-reason"] == "mcp_cross_team_denied"

        # 5. admin allowed cross-Team check_model_catalog
        admin_cross = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "check_model_catalog", "arguments": {"team": "product-eng"}},
                rpc_id=7,
            ),
            headers={
                **MCP_HEADERS,
                "Authorization": f"Bearer {admin_jwt}",
                "X-Run-Id": "run-admin",
            },
        )
        assert admin_cross.status_code == 200
        assert _extract_tool_json(admin_cross.json())["team"] == "product-eng"

        # 6. unknown tool rejected by allowlist (403)
        unknown_tool = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "delete_everything", "arguments": {}},
                rpc_id=8,
            ),
            headers={
                **MCP_HEADERS,
                "Authorization": f"Bearer {admin_jwt}",
                "X-Run-Id": "run-admin",
            },
        )
        assert unknown_tool.status_code == 403
        assert unknown_tool.headers["x-policy-denial-reason"] == "mcp_tool_not_allowed"

    assert [e.outcome for e in mcp_events] == [
        "rbac_denied",
        "rbac_denied",
        "allowed",
        "allowed",
        "allowed",
        "rbac_denied",
        "allowed",
        "rbac_denied",
    ]
    assert [e.policy_action for e in gateway_events] == [
        "deny",
        "deny",
        "allow",
        "allow",
        "allow",
        "deny",
        "allow",
        "deny",
    ]


async def test_control_plane_mcp_per_call_execution_timeout_returns_504() -> None:
    keypair = generate_rsa_keypair(seed="mcp-timeout-test")
    jwt_credential = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="ops-timeout",
        team="ops-eng",
        role="ops",
    )
    mcp_events: list[AuditEvent] = []
    gateway_events: list[AuditEvent] = []
    mcp_app = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
            tool_timeout_seconds=0.05,
        ),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        audit_sink=mcp_events,
        tool_delay_seconds=0.25,
    )
    gateway_app, _ = _build_gateway_with_mcp(
        mcp_app=mcp_app,
        jwks=keypair.jwks,
        gateway_events=gateway_events,
    )

    async with (
        mcp_app.router.lifespan_context(mcp_app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway_app),
            base_url="http://control-plane",
        ) as client,
    ):
        resp = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "query_runbook", "arguments": {"query": "timeout"}},
                rpc_id=10,
            ),
            headers={
                **MCP_HEADERS,
                "Authorization": f"Bearer {jwt_credential}",
                "X-Run-Id": "run-to-1",
            },
        )
        assert resp.status_code == 504
        assert resp.headers["x-policy-denial-reason"] == "mcp_tool_timeout"
        assert resp.json()["error"]["data"]["reason"] == "mcp_tool_timeout"

    assert len(mcp_events) == 1
    assert mcp_events[0].outcome == "timed_out"
    assert mcp_events[0].policy_action == "error"
    assert mcp_events[0].status_code == 504
    assert mcp_events[0].tool_name == "query_runbook"
    assert mcp_events[0].run_id == "run-to-1"
    assert gateway_events[0].status_code == 504
    assert gateway_events[0].policy_action == "error"


async def test_mcp_run_loop_cap_enforced_across_two_runtime_replicas_sharing_redis() -> None:
    keypair = generate_rsa_keypair(seed="mcp-loop-cap-test")
    jwt_credential = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="ops-loop",
        team="ops-eng",
        role="ops",
    )

    shared_server = fakeredis.FakeServer()
    redis_a = fakeredis.FakeAsyncRedis(server=shared_server, decode_responses=True)
    redis_b = fakeredis.FakeAsyncRedis(server=shared_server, decode_responses=True)

    mcp_events_a: list[AuditEvent] = []
    mcp_events_b: list[AuditEvent] = []
    mcp_app_a = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
            max_tool_calls_per_run=3,
        ),
        redis_client=redis_a,
        audit_sink=mcp_events_a,
    )
    mcp_app_b = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
            max_tool_calls_per_run=3,
        ),
        redis_client=redis_b,
        audit_sink=mcp_events_b,
    )

    class _RoundRobinTransport(httpx.AsyncBaseTransport):
        def __init__(
            self,
            t_a: httpx.AsyncBaseTransport,
            t_b: httpx.AsyncBaseTransport,
        ) -> None:
            self._transports = (t_a, t_b)
            self._idx = 0

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            target = self._transports[self._idx % 2]
            self._idx += 1
            return await target.handle_async_request(request)

    gateway_app, _ = _build_gateway_with_mcp(
        mcp_transport=_RoundRobinTransport(
            httpx.ASGITransport(app=mcp_app_a),
            httpx.ASGITransport(app=mcp_app_b),
        ),
        jwks=keypair.jwks,
    )

    async with (
        mcp_app_a.router.lifespan_context(mcp_app_a),
        mcp_app_b.router.lifespan_context(mcp_app_b),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway_app),
            base_url="http://control-plane",
        ) as client,
    ):
        # tools/list does NOT count against the per-Run tool-call loop cap
        list_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call("tools/list", rpc_id=1),
            headers={
                **MCP_HEADERS,
                "Authorization": f"Bearer {jwt_credential}",
                "X-Run-Id": "run-cap-1",
            },
        )
        assert list_resp.status_code == 200

        for idx in range(1, 4):
            call_resp = await client.post(
                "/mcp",
                json=_jsonrpc_call(
                    "tools/call",
                    {"name": "query_runbook", "arguments": {"query": "loop"}},
                    rpc_id=idx + 1,
                ),
                headers={
                    **MCP_HEADERS,
                    "Authorization": f"Bearer {jwt_credential}",
                    "X-Run-Id": "run-cap-1",
                },
            )
            assert call_resp.status_code == 200
            assert call_resp.headers["x-mcp-run-calls"] == str(idx)
            assert call_resp.headers["x-mcp-run-limit"] == "3"

        capped_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "query_runbook", "arguments": {"query": "loop"}},
                rpc_id=5,
            ),
            headers={
                **MCP_HEADERS,
                "Authorization": f"Bearer {jwt_credential}",
                "X-Run-Id": "run-cap-1",
            },
        )
        assert capped_resp.status_code == 429
        assert capped_resp.headers["x-policy-denial-reason"] == "mcp_run_loop_cap_exceeded"
        assert capped_resp.headers["x-mcp-run-calls"] == "3"
        assert capped_resp.headers["x-mcp-run-limit"] == "3"

        other_run_resp = await client.post(
            "/mcp",
            json=_jsonrpc_call(
                "tools/call",
                {"name": "query_runbook", "arguments": {"query": "loop"}},
                rpc_id=6,
            ),
            headers={
                **MCP_HEADERS,
                "Authorization": f"Bearer {jwt_credential}",
                "X-Run-Id": "run-cap-2",
            },
        )
        assert other_run_resp.status_code == 200
        assert other_run_resp.headers["x-mcp-run-calls"] == "1"

    assert await redis_a.get("mcp:run:ops-eng:run-cap-1:calls") == "3"
    assert await redis_a.ttl("mcp:run:ops-eng:run-cap-1:calls") > 0
    all_outcomes = [e.outcome for e in (mcp_events_a + mcp_events_b)]
    assert "loop_capped" in all_outcomes


async def test_mcp_runtime_fails_closed_with_503_when_redis_unavailable_or_errors() -> None:
    keypair = generate_rsa_keypair(seed="mcp-redis-down")
    jwt_credential = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="ops-redis",
        team="ops-eng",
        role="ops",
    )

    class _FailingRedis:
        async def ping(self) -> bool:
            raise RedisError("Redis connection lost")

        def register_script(self, _source: str) -> Any:
            async def _fail(*_args: Any, **_kwargs: Any) -> Any:
                raise RedisError("Redis connection lost")

            return _fail

    for redis_stub in (None, _FailingRedis()):
        mcp_events: list[AuditEvent] = []
        mcp_app = create_mcp_app(
            settings=MCPRuntimeSettings(
                policy_bundle_path=POLICY_BUNDLE_PATH,
                internal_identity_secret=TEST_INTERNAL_SECRET,
                require_redis=True,
            ),
            redis_client=redis_stub,
            audit_sink=mcp_events,
        )
        gateway_app, _ = _build_gateway_with_mcp(mcp_app=mcp_app, jwks=keypair.jwks)

        async with (
            mcp_app.router.lifespan_context(mcp_app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gateway_app),
                base_url="http://control-plane",
            ) as client,
        ):
            resp = await client.post(
                "/mcp",
                json=_jsonrpc_call(
                    "tools/call",
                    {"name": "query_runbook", "arguments": {"query": "redis"}},
                ),
                headers={**MCP_HEADERS, "Authorization": f"Bearer {jwt_credential}"},
            )
            assert resp.status_code == 503
            assert resp.headers["x-policy-denial-reason"] == "redis_unavailable"

        assert len(mcp_events) == 1
        assert mcp_events[0].outcome == "redis_unavailable"
        assert mcp_events[0].policy_action == "error"
        assert mcp_events[0].status_code == 503


async def test_mcp_audit_privacy_otel_trace_correlation_and_prometheus_metrics(
    caplog: pytest.LogCaptureFixture,
) -> None:
    hs256_dev_jwt = mint_hs256_jwt(
        secret=DEFAULT_HS256_SECRET,
        actor_id="hs256-dev",
        team="product-eng",
        role="developer",
    )

    gw_exporter = InMemorySpanExporter()
    gw_tracer_provider = TracerProvider(resource=Resource.create({"service.name": "gateway-api"}))
    gw_tracer_provider.add_span_processor(SimpleSpanProcessor(gw_exporter))

    mcp_exporter = InMemorySpanExporter()
    mcp_tracer_provider = TracerProvider(resource=Resource.create({"service.name": "mcp-runtime"}))
    mcp_tracer_provider.add_span_processor(SimpleSpanProcessor(mcp_exporter))

    mcp_events: list[AuditEvent] = []
    gateway_events: list[AuditEvent] = []
    mcp_app = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
            max_tool_calls_per_run=1,
        ),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        audit_sink=mcp_events,
        tracer_provider=mcp_tracer_provider,
    )
    gateway_app = create_gateway_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://unused-model-router",
            mcp_runtime_base_url="http://mcp-runtime",
            internal_identity_secret=TEST_INTERNAL_SECRET,
            jwt_hs256_enabled=True,
            jwt_hs256_secret=DEFAULT_HS256_SECRET,
        ),
        mcp_runtime_transport=httpx.ASGITransport(app=mcp_app),
        audit_sink=gateway_events,
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        tracer_provider=gw_tracer_provider,
    )

    secret_arg_marker = "CONFIDENTIAL_TOOL_ARGUMENT_MARKER_999"
    pii_email_arg = "sensitive.actor@corp.example.com"
    incoming_trace_id = "0af7651916cd43dd8448eb211c80319c"
    incoming_parent_span_id = "b7ad6b7169203331"
    incoming_traceparent = f"00-{incoming_trace_id}-{incoming_parent_span_id}-01"

    caplog.clear()
    with caplog.at_level(logging.INFO):
        async with (
            mcp_app.router.lifespan_context(mcp_app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gateway_app),
                base_url="http://control-plane",
            ) as client,
        ):
            # 1. Allowed call with explicit traceparent and sensitive argument text
            ok_resp = await client.post(
                "/mcp",
                json=_jsonrpc_call(
                    "tools/call",
                    {
                        "name": "query_runbook",
                        "arguments": {"query": f"failover {secret_arg_marker} {pii_email_arg}"},
                    },
                    rpc_id=1,
                ),
                headers={
                    **MCP_HEADERS,
                    "Authorization": f"Bearer {hs256_dev_jwt}",
                    "X-Run-Id": "run-trace-1",
                    "traceparent": incoming_traceparent,
                },
            )
            assert ok_resp.status_code == 200
            assert ok_resp.headers["x-trace-id"] == incoming_trace_id

            # 2. Loop-capped 429 on same Run without incoming traceparent (minted root trace_id)
            capped_resp = await client.post(
                "/mcp",
                json=_jsonrpc_call(
                    "tools/call",
                    {"name": "query_runbook", "arguments": {"query": secret_arg_marker}},
                    rpc_id=2,
                ),
                headers={
                    **MCP_HEADERS,
                    "Authorization": f"Bearer {hs256_dev_jwt}",
                    "X-Run-Id": "run-trace-1",
                },
            )
            assert capped_resp.status_code == 429

            # 3. RBAC 403 on lookup_service_slo
            denied_resp = await client.post(
                "/mcp",
                json=_jsonrpc_call(
                    "tools/call",
                    {"name": "lookup_service_slo", "arguments": {"service_name": "gateway-api"}},
                    rpc_id=3,
                ),
                headers={
                    **MCP_HEADERS,
                    "Authorization": f"Bearer {hs256_dev_jwt}",
                    "X-Run-Id": "run-trace-2",
                },
            )
            assert denied_resp.status_code == 403

            metrics_resp = await client.get("/metrics")
            assert metrics_resp.status_code == 200

    gw_spans = gw_exporter.get_finished_spans()
    mcp_spans = mcp_exporter.get_finished_spans()
    assert len(gw_spans) == 3
    assert len(mcp_spans) == 3
    assert len(gateway_events) == 3
    assert len(mcp_events) == 3

    for idx in range(3):
        gw_span = gw_spans[idx]
        mcp_span = mcp_spans[idx]
        gw_ev = gateway_events[idx]
        mcp_ev = mcp_events[idx]

        gw_trace = f"{gw_span.context.trace_id:032x}"
        mcp_trace = f"{mcp_span.context.trace_id:032x}"
        assert gw_trace == mcp_trace == gw_ev.trace_id == mcp_ev.trace_id
        assert mcp_span.parent is not None
        assert f"{mcp_span.parent.span_id:016x}" == f"{gw_span.context.span_id:016x}"
        assert dict(gw_span.attributes or {}).get("gateway.tool_name") == mcp_ev.tool_name
        assert dict(gw_span.attributes or {}).get("gateway.run_id") == mcp_ev.run_id

    assert gateway_events[0].trace_id == incoming_trace_id
    assert [e.outcome for e in mcp_events] == ["allowed", "loop_capped", "rbac_denied"]

    # Privacy checks across AuditEvents, structured logs, spans, and /metrics
    audit_log_lines = [
        rec.getMessage()
        for rec in caplog.records
        if rec.name in ("gateway_api.audit", "mcp_runtime.audit")
    ]
    assert len(audit_log_lines) == 6
    serialized_spans = json.dumps(
        [{"name": s.name, "attrs": dict(s.attributes or {})} for s in (gw_spans + mcp_spans)]
    )
    forbidden = [
        secret_arg_marker,
        pii_email_arg,
        hs256_dev_jwt,
        TEST_INTERNAL_SECRET,
        DEFAULT_HS256_SECRET,
    ]
    surfaces = (
        [e.model_dump_json() for e in (gateway_events + mcp_events)]
        + audit_log_lines
        + [serialized_spans, metrics_resp.text]
    )
    for surface in surfaces:
        for secret in forbidden:
            assert secret not in surface

    # Prometheus /metrics accuracy for /mcp and policy denials
    samples: dict[str, list[tuple[dict[str, str], float]]] = {}
    for family in text_string_to_metric_families(metrics_resp.text):
        for sample in family.samples:
            samples.setdefault(sample.name, []).append((dict(sample.labels), float(sample.value)))

    def _sample(name: str, **labels: str) -> float | None:
        for lbls, val in samples.get(name, []):
            if all(lbls.get(k) == v for k, v in labels.items()):
                return val
        return None

    assert (
        _sample(
            "gateway_requests_total",
            route="/mcp",
            team="product-eng",
            model_alias="unknown",
            status="200",
        )
        == 1.0
    )
    assert (
        _sample(
            "gateway_policy_denials_total",
            team="product-eng",
            reason="mcp_run_loop_cap_exceeded",
        )
        == 1.0
    )
    assert (
        _sample(
            "gateway_policy_denials_total",
            team="product-eng",
            reason="mcp_tool_not_allowed",
        )
        == 1.0
    )
