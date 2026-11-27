"""End-to-end tests for GovernedClient against Control Plane, MCP Runtime, and Mock Provider."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import fakeredis
import httpx
import pytest
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from gateway_api.app import create_app as create_gateway_app
from gateway_api.config import ControlPlaneSettings
from gateway_sdk import AgentLoopResult, AgentLoopStep, GatewayClientError, GovernedClient
from mcp_runtime.app import create_app as create_mcp_app
from mcp_runtime.config import MCPRuntimeSettings
from mock_llm.app import create_app as create_mock_provider_app
from mock_llm.config import MockProviderSettings
from platform_common import AuditEvent
from scripts.generate_test_keys import generate_rsa_keypair, mint_rs256_jwt

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_BUNDLE_PATH = REPO_ROOT / "policies" / "policy-bundle.yaml"
TEST_INTERNAL_SECRET = "internal-mcp-identity-signing-secret-32b"
_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-01$")


def _build_full_stack(
    *,
    max_tool_calls_per_run: int = 5,
):
    keypair = generate_rsa_keypair(seed="gateway-sdk-test")
    ops_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="sdk-ops-user",
        team="ops-eng",
        role="ops",
    )
    dev_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="sdk-dev-user",
        team="product-eng",
        role="developer",
    )

    gw_exporter = InMemorySpanExporter()
    gw_tracer_provider = TracerProvider(resource=Resource.create({"service.name": "gateway-api"}))
    gw_tracer_provider.add_span_processor(SimpleSpanProcessor(gw_exporter))

    mcp_exporter = InMemorySpanExporter()
    mcp_tracer_provider = TracerProvider(resource=Resource.create({"service.name": "mcp-runtime"}))
    mcp_tracer_provider.add_span_processor(SimpleSpanProcessor(mcp_exporter))

    gateway_events: list[AuditEvent] = []
    mcp_events: list[AuditEvent] = []

    mock_app = create_mock_provider_app(
        MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    mcp_app = create_mcp_app(
        settings=MCPRuntimeSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            internal_identity_secret=TEST_INTERNAL_SECRET,
            max_tool_calls_per_run=max_tool_calls_per_run,
        ),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        audit_sink=mcp_events,
        tracer_provider=mcp_tracer_provider,
    )
    gateway_app = create_gateway_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-llm-primary",
            model_router_api_key="sk-litellm-test",
            mcp_runtime_base_url="http://mcp-runtime",
            internal_identity_secret=TEST_INTERNAL_SECRET,
            jwt_jwks=keypair.jwks,
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
        mcp_runtime_transport=httpx.ASGITransport(app=mcp_app),
        audit_sink=gateway_events,
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
        tracer_provider=gw_tracer_provider,
    )

    return {
        "gateway_app": gateway_app,
        "mcp_app": mcp_app,
        "ops_jwt": ops_jwt,
        "dev_jwt": dev_jwt,
        "gateway_events": gateway_events,
        "mcp_events": mcp_events,
        "gw_exporter": gw_exporter,
        "mcp_exporter": mcp_exporter,
    }


class _TransientFaultTransport(httpx.AsyncBaseTransport):
    """Inject deterministic 5xx or TransportError failures before delegating to real ASGI app."""

    def __init__(self, inner: httpx.AsyncBaseTransport, outcomes: list[int | Exception]) -> None:
        self._inner = inner
        self._outcomes = list(outcomes)
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._outcomes:
            outcome = self._outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            if outcome >= 500:
                return httpx.Response(
                    status_code=outcome,
                    json={
                        "error": {
                            "message": f"Upstream error {outcome}",
                            "type": "server_error",
                            "code": f"http_{outcome}",
                        }
                    },
                )
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


async def test_governed_client_json_completion_propagates_traceparent_and_run_id() -> None:
    stack = _build_full_stack()
    explicit_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    explicit_traceparent = f"00-{explicit_trace_id}-00f067aa0ba902b7-01"

    async with (
        stack["mcp_app"].router.lifespan_context(stack["mcp_app"]),
        GovernedClient(
            base_url="http://control-plane",
            api_key=stack["ops_jwt"],
            transport=httpx.ASGITransport(app=stack["gateway_app"]),
        ) as client,
    ):
        assert _TRACEPARENT_RE.fullmatch(client.traceparent)
        assert client.run_id

        default_resp = await client.chat_completions(
            "chat-default",
            [{"role": "user", "content": "Hello governed SDK"}],
        )
        assert "mock-llm-primary" in default_resp["choices"][0]["message"]["content"]
        assert default_resp["usage"]["total_tokens"] > 0

        explicit_resp = await client.chat_completions(
            "chat-fast",
            [{"role": "user", "content": "Trace override check"}],
            max_tokens=32,
            temperature=0.2,
            run_id="run-sdk-explicit-1",
            traceparent=explicit_traceparent,
            extra_headers={"x-custom-sdk": "true"},
        )
        assert "mock-llm-primary" in explicit_resp["choices"][0]["message"]["content"]

    events = stack["gateway_events"]
    assert len(events) == 2
    default_trace_id = _TRACEPARENT_RE.fullmatch(client.traceparent).group(1)  # type: ignore[union-attr]
    assert events[0].trace_id == default_trace_id
    assert events[1].trace_id == explicit_trace_id

    gw_spans = stack["gw_exporter"].get_finished_spans()
    assert len(gw_spans) == 2
    assert f"{gw_spans[0].context.trace_id:032x}" == default_trace_id
    assert f"{gw_spans[1].context.trace_id:032x}" == explicit_trace_id


async def test_governed_client_retries_5xx_and_transport_errors_but_never_retries_4xx() -> None:
    stack = _build_full_stack()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    fault_transport = _TransientFaultTransport(
        httpx.ASGITransport(app=stack["gateway_app"]),
        outcomes=[
            503,
            httpx.ConnectError("temporary reset"),
        ],
    )

    async with (
        stack["mcp_app"].router.lifespan_context(stack["mcp_app"]),
        GovernedClient(
            base_url="http://control-plane",
            api_key=stack["dev_jwt"],
            transport=fault_transport,
            sleep_fn=fake_sleep,
            max_retries=3,
            backoff_base_seconds=0.1,
        ) as client,
    ):
        resp = await client.chat_completions(
            "chat-default",
            [{"role": "user", "content": "Retry until success"}],
        )
        assert "mock-llm-primary" in resp["choices"][0]["message"]["content"]
        assert len(fault_transport.requests) == 3
        assert sleeps == pytest.approx([0.1, 0.2])

        # 403 RBAC denial must fail immediately with 0 retries and structured GatewayClientError
        before_requests = len(fault_transport.requests)
        with pytest.raises(GatewayClientError) as denied_exc:
            await client.chat_completions(
                "chat-premium",
                [{"role": "user", "content": "Restricted alias"}],
            )
        assert len(fault_transport.requests) == before_requests + 1
        assert sleeps == pytest.approx([0.1, 0.2])
        assert denied_exc.value.status_code == 403
        assert denied_exc.value.code == "model_not_allowed"
        assert denied_exc.value.reason == "model_not_allowed"
        assert denied_exc.value.headers["x-policy-denial-reason"] == "model_not_allowed"
        assert isinstance(denied_exc.value.payload, dict)

    # Exhausted 5xx retries raise GatewayClientError
    exhausted_sleeps: list[float] = []

    async def fake_exhausted_sleep(seconds: float) -> None:
        exhausted_sleeps.append(seconds)

    always_502 = _TransientFaultTransport(
        httpx.ASGITransport(app=stack["gateway_app"]),
        outcomes=[502, 502, 502],
    )
    async with GovernedClient(
        base_url="http://control-plane",
        api_key=stack["ops_jwt"],
        transport=always_502,
        sleep_fn=fake_exhausted_sleep,
        max_retries=2,
        backoff_base_seconds=0.05,
    ) as fail_client:
        with pytest.raises(GatewayClientError) as exc_info:
            await fail_client.chat_completions(
                "chat-default",
                [{"role": "user", "content": "Exhaust retries"}],
            )
        assert exc_info.value.status_code == 502
        assert len(always_502.requests) == 3
        assert exhausted_sleeps == pytest.approx([0.05, 0.1])


async def test_governed_client_sse_streaming_and_pre_stream_5xx_retry() -> None:
    stack = _build_full_stack()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    fault_transport = _TransientFaultTransport(
        httpx.ASGITransport(app=stack["gateway_app"]),
        outcomes=[503],
    )

    async with (
        stack["mcp_app"].router.lifespan_context(stack["mcp_app"]),
        GovernedClient(
            base_url="http://control-plane",
            api_key=stack["dev_jwt"],
            transport=fault_transport,
            sleep_fn=fake_sleep,
            max_retries=2,
            backoff_base_seconds=0.1,
        ) as client,
    ):
        chunks: list[dict[str, Any]] = []
        stream = await client.chat_completions(
            "chat-default",
            [{"role": "user", "content": "Stream governed completion"}],
            stream=True,
        )
        async for chunk in stream:
            chunks.append(chunk)

        assert sleeps == pytest.approx([0.1])
        assert len(fault_transport.requests) == 2
        text = "".join(
            choice.get("delta", {}).get("content", "")
            for chunk in chunks
            for choice in chunk.get("choices", [])
        )
        assert "mock-llm-primary" in text
        usage_chunks = [c["usage"] for c in chunks if c.get("usage") is not None]
        assert len(usage_chunks) == 1
        assert usage_chunks[0]["total_tokens"] > 0

        # 403 on streaming must fail immediately without retries
        before = len(fault_transport.requests)
        with pytest.raises(GatewayClientError) as exc_info:
            await client.chat_completions(
                "chat-premium",
                [{"role": "user", "content": "Forbidden stream"}],
                stream=True,
            )
        assert exc_info.value.status_code == 403
        assert exc_info.value.code == "model_not_allowed"
        assert len(fault_transport.requests) == before + 1
        assert sleeps == pytest.approx([0.1])


async def test_governed_client_call_mcp_tool_retries_5xx_and_raises_on_rbac_403() -> None:
    stack = _build_full_stack()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    ops_transport = _TransientFaultTransport(
        httpx.ASGITransport(app=stack["gateway_app"]),
        outcomes=[503],
    )
    trace_id = "0af7651916cd43dd8448eb211c80319c"
    traceparent = f"00-{trace_id}-b7ad6b7169203331-01"

    async with (
        stack["mcp_app"].router.lifespan_context(stack["mcp_app"]),
        GovernedClient(
            base_url="http://control-plane",
            api_key=stack["ops_jwt"],
            transport=ops_transport,
            sleep_fn=fake_sleep,
            max_retries=2,
            backoff_base_seconds=0.1,
            run_id="run-sdk-mcp-1",
            traceparent=traceparent,
        ) as ops_client,
        GovernedClient(
            base_url="http://control-plane",
            api_key=stack["dev_jwt"],
            transport=httpx.ASGITransport(app=stack["gateway_app"]),
            run_id="run-sdk-mcp-dev",
        ) as dev_client,
    ):
        slo = await ops_client.call_mcp_tool(
            "lookup_service_slo",
            {"service_name": "gateway-api"},
        )
        assert slo["found"] is True
        assert slo["service_name"] == "gateway-api"
        assert sleeps == pytest.approx([0.1])
        assert len(ops_transport.requests) == 2
        assert "text/event-stream" in ops_transport.requests[0].headers["accept"]

        with pytest.raises(GatewayClientError) as denied_exc:
            await dev_client.call_mcp_tool(
                "lookup_service_slo",
                {"service_name": "gateway-api"},
            )
        assert denied_exc.value.status_code == 403
        assert denied_exc.value.reason == "mcp_tool_not_allowed"

    assert len(stack["mcp_events"]) == 2
    assert stack["mcp_events"][0].trace_id == trace_id
    assert stack["mcp_events"][0].run_id == "run-sdk-mcp-1"
    assert stack["mcp_events"][1].outcome == "rbac_denied"
    gw_spans = stack["gw_exporter"].get_finished_spans()
    mcp_spans = stack["mcp_exporter"].get_finished_spans()
    assert f"{gw_spans[0].context.trace_id:032x}" == trace_id
    assert f"{mcp_spans[0].context.trace_id:032x}" == trace_id


async def test_governed_client_run_agent_loop_completes_and_stops_on_server_run_cap() -> None:
    # 1. Clean completion after 1 tool call + 1 final completion
    stack_ok = _build_full_stack(max_tool_calls_per_run=5)
    planned_calls = 0

    def plan_once(_completion: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
        nonlocal planned_calls
        planned_calls += 1
        if planned_calls == 1:
            return ("query_runbook", {"query": "failover"})
        return None

    async with (
        stack_ok["mcp_app"].router.lifespan_context(stack_ok["mcp_app"]),
        GovernedClient(
            base_url="http://control-plane",
            api_key=stack_ok["ops_jwt"],
            transport=httpx.ASGITransport(app=stack_ok["gateway_app"]),
        ) as client,
    ):
        result = await client.run_agent_loop(
            "chat-default",
            [{"role": "user", "content": "Diagnose failover"}],
            plan_once,
            max_steps=5,
            run_id="run-agent-ok",
        )

    assert isinstance(result, AgentLoopResult)
    assert result.stopped_reason == "completed"
    assert result.run_id == "run-agent-ok"
    assert _TRACEPARENT_RE.fullmatch(result.traceparent)
    assert result.final_content and "mock-llm-primary" in result.final_content
    assert len(result.steps) == 2
    assert all(isinstance(step, AgentLoopStep) for step in result.steps)
    assert result.steps[0].tool_name == "query_runbook"
    assert result.steps[0].tool_result is not None
    assert result.steps[0].tool_result["match_count"] >= 1
    assert result.steps[1].tool_name is None

    expected_trace_id = _TRACEPARENT_RE.fullmatch(result.traceparent).group(1)  # type: ignore[union-attr]
    assert all(ev.trace_id == expected_trace_id for ev in stack_ok["gateway_events"])
    assert all(ev.trace_id == expected_trace_id for ev in stack_ok["mcp_events"])
    assert all(ev.run_id == "run-agent-ok" for ev in stack_ok["mcp_events"])

    # 2. Run hitting server-side Run loop cap (429) stops cleanly with server_run_cap_exceeded
    stack_cap = _build_full_stack(max_tool_calls_per_run=2)

    async def always_call_tool(_completion: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        return ("query_runbook", {"query": "loop"})

    async with (
        stack_cap["mcp_app"].router.lifespan_context(stack_cap["mcp_app"]),
        GovernedClient(
            base_url="http://control-plane",
            api_key=stack_cap["ops_jwt"],
            transport=httpx.ASGITransport(app=stack_cap["gateway_app"]),
        ) as cap_client,
    ):
        capped_result = await cap_client.run_agent_loop(
            "chat-default",
            [{"role": "user", "content": "Keep calling tools"}],
            always_call_tool,
            max_steps=10,
            run_id="run-agent-capped",
        )

    assert capped_result.stopped_reason == "server_run_cap_exceeded"
    assert capped_result.run_id == "run-agent-capped"
    assert sum(1 for step in capped_result.steps if step.tool_result is not None) == 2
    assert capped_result.steps[-1].tool_name == "query_runbook"
    assert capped_result.steps[-1].tool_result is None
    assert [ev.outcome for ev in stack_cap["mcp_events"]] == ["allowed", "allowed", "loop_capped"]


async def test_governed_client_run_agent_loop_max_steps_and_dict_planner() -> None:
    stack = _build_full_stack(max_tool_calls_per_run=5)

    def dict_planner(_completion: dict[str, Any]) -> dict[str, Any]:
        return {"name": "check_model_catalog", "arguments": {"team": "product-eng"}}

    async with (
        stack["mcp_app"].router.lifespan_context(stack["mcp_app"]),
        GovernedClient(
            base_url="http://control-plane",
            api_key=stack["dev_jwt"],
            transport=httpx.ASGITransport(app=stack["gateway_app"]),
        ) as client,
    ):
        result = await client.run_agent_loop(
            "chat-default",
            [{"role": "user", "content": "Check catalog"}],
            dict_planner,
            max_steps=2,
            run_id="run-max-steps",
        )

    assert result.stopped_reason == "max_steps_reached"
    assert len(result.steps) == 2
    assert all(
        step.tool_result and step.tool_result["team"] == "product-eng" for step in result.steps
    )
