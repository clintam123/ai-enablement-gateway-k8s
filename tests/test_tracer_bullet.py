import hashlib
import json
import re
import time
from pathlib import Path

import httpx
import pytest

from gateway_api.app import create_app
from gateway_api.config import ControlPlaneSettings
from mock_llm.app import create_app as create_mock_provider_app
from mock_llm.config import MockProviderSettings

POLICY_BUNDLE_PATH = Path(__file__).resolve().parent.parent / "policies" / "policy-bundle.yaml"


async def test_healthz_and_readyz_expose_deterministic_policy_version() -> None:
    expected_digest = hashlib.sha256(POLICY_BUNDLE_PATH.read_bytes()).hexdigest()[:8]
    expected_version = f"v1+{expected_digest}"

    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://control-plane",
    ) as client:
        health_resp = await client.get("/healthz")
        assert health_resp.status_code == 200
        assert health_resp.json() == {"status": "ok"}

        ready_resp = await client.get("/readyz")
        assert ready_resp.status_code == 200
        ready_body = ready_resp.json()
        assert ready_body["status"] == "ready"
        assert re.fullmatch(r"v1\+[0-9a-f]{8}", ready_body["policy_version"])
        assert ready_body["policy_version"] == expected_version


async def test_policy_version_changes_when_policy_bundle_content_changes(tmp_path: Path) -> None:
    bundle_copy = tmp_path / "policy-bundle.yaml"
    original_bytes = POLICY_BUNDLE_PATH.read_bytes()
    mutated_bytes = original_bytes + b"\n# rollout-marker\n"
    bundle_copy.write_bytes(mutated_bytes)

    expected_mutated_version = f"v1+{hashlib.sha256(mutated_bytes).hexdigest()[:8]}"
    app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=bundle_copy,
            model_router_base_url="http://mock-provider",
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://control-plane",
    ) as client:
        ready_resp = await client.get("/readyz")
        assert ready_resp.status_code == 200
        assert ready_resp.json()["policy_version"] == expected_mutated_version


def test_control_plane_fails_fast_on_missing_policy_bundle(tmp_path: Path) -> None:
    missing_path = tmp_path / "does-not-exist.yaml"
    with pytest.raises(FileNotFoundError):
        create_app(
            settings=ControlPlaneSettings(
                policy_bundle_path=missing_path,
                model_router_base_url="http://mock-provider",
            )
        )


async def test_json_chat_completion_flows_through_control_plane_to_mock_provider() -> None:
    expected_version = f"v1+{hashlib.sha256(POLICY_BUNDLE_PATH.read_bytes()).hexdigest()[:8]}"
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    control_plane_app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
    )

    payload = {
        "model": "chat-default",
        "messages": [
            {"role": "system", "content": "You are a helpful platform assistant."},
            {"role": "user", "content": "Summarize our Kubernetes deployment topology."},
        ],
        "stream": False,
    }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=control_plane_app),
        base_url="http://control-plane",
    ) as client:
        resp_one = await client.post("/v1/chat/completions", json=payload)
        resp_two = await client.post("/v1/chat/completions", json=payload)

    assert resp_one.status_code == 200
    assert resp_one.headers["x-policy-version"] == expected_version

    body_one = resp_one.json()
    body_two = resp_two.json()

    assert body_one["object"] == "chat.completion"
    assert body_one["model"] == "chat-default"
    assert body_one["choices"][0]["message"]["role"] == "assistant"
    assert "mock-llm-primary" in body_one["choices"][0]["message"]["content"]
    assert body_one["choices"][0]["finish_reason"] == "stop"

    usage = body_one["usage"]
    assert usage["prompt_tokens"] > 0
    assert usage["completion_tokens"] > 0
    assert usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"]

    # Deterministic content and LLM Token usage across identical requests
    assert (
        body_one["choices"][0]["message"]["content"]
        == (body_two["choices"][0]["message"]["content"])
    )
    assert body_one["usage"] == body_two["usage"]


async def test_json_chat_completion_respects_max_tokens_cap() -> None:
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    control_plane_app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
    )

    payload = {
        "model": "chat-fast",
        "messages": [{"role": "user", "content": "Respond concisely with capped tokens."}],
        "max_tokens": 3,
    }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=control_plane_app),
        base_url="http://control-plane",
    ) as client:
        resp = await client.post("/v1/chat/completions", json=payload)

    assert resp.status_code == 200
    body = resp.json()
    assert 1 <= body["usage"]["completion_tokens"] <= 3
    assert body["usage"]["total_tokens"] == (
        body["usage"]["prompt_tokens"] + body["usage"]["completion_tokens"]
    )


async def test_sse_streaming_chat_completion_flows_through_control_plane() -> None:
    expected_version = f"v1+{hashlib.sha256(POLICY_BUNDLE_PATH.read_bytes()).hexdigest()[:8]}"
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    control_plane_app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
    )

    messages = [{"role": "user", "content": "Stream a deterministic platform status update."}]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=control_plane_app),
        base_url="http://control-plane",
    ) as client:
        json_resp = await client.post(
            "/v1/chat/completions",
            json={"model": "chat-default", "messages": messages, "stream": False},
        )
        assert json_resp.status_code == 200
        expected_content = json_resp.json()["choices"][0]["message"]["content"]
        expected_usage = json_resp.json()["usage"]

        async with client.stream(
            "POST",
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": messages,
                "stream": True,
                "stream_options": {"include_usage": True},
            },
        ) as sse_resp:
            assert sse_resp.status_code == 200
            assert sse_resp.headers["content-type"].startswith("text/event-stream")
            assert sse_resp.headers["x-policy-version"] == expected_version

            data_lines = [
                line.removeprefix("data: ").strip()
                async for line in sse_resp.aiter_lines()
                if line.startswith("data: ")
            ]

    assert data_lines[-1] == "[DONE]"
    chunks = [json.loads(item) for item in data_lines[:-1]]
    assert len(chunks) >= 3
    assert all(chunk["object"] == "chat.completion.chunk" for chunk in chunks)
    assert all(chunk["model"] == "chat-default" for chunk in chunks)

    streamed_content = "".join(
        choice["delta"].get("content", "") for chunk in chunks for choice in chunk["choices"]
    )
    assert streamed_content == expected_content

    finish_reasons = [
        choice["finish_reason"]
        for chunk in chunks
        for choice in chunk["choices"]
        if choice.get("finish_reason") is not None
    ]
    assert finish_reasons == ["stop"]

    usage_chunks = [chunk["usage"] for chunk in chunks if chunk.get("usage") is not None]
    assert len(usage_chunks) == 1
    assert usage_chunks[0] == expected_usage


async def test_mock_behavior_fail_503_propagates_for_json_and_sse() -> None:
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    control_plane_app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
            mock_mode_enabled=True,
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=control_plane_app),
        base_url="http://control-plane",
    ) as client:
        json_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Trigger 503"}],
                "stream": False,
            },
            headers={"X-Mock-Behavior": "fail_503"},
        )
        assert json_resp.status_code == 503
        assert json_resp.json()["error"]["code"] == "mock_fault_503"

        sse_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Trigger streaming 503"}],
                "stream": True,
            },
            headers={"X-Mock-Behavior": "fail_503"},
        )
        assert sse_resp.status_code == 503
        assert sse_resp.json()["error"]["code"] == "mock_fault_503"


async def test_mock_behavior_latency_and_timeout_directives() -> None:
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(
            provider_name="mock-llm-primary",
            mock_mode_enabled=True,
            timeout_delay_ms=250,
        )
    )
    control_plane_app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
            model_router_timeout_seconds=0.1,
            mock_mode_enabled=True,
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=control_plane_app),
        base_url="http://control-plane",
    ) as client:
        started = time.monotonic()
        latency_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "Add deterministic latency"}],
            },
            headers={"X-Mock-Behavior": "latency_ms=40"},
        )
        elapsed_ms = (time.monotonic() - started) * 1000
        assert latency_resp.status_code == 200
        assert elapsed_ms >= 35

        timeout_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-fast",
                "messages": [{"role": "user", "content": "Trigger provider timeout"}],
            },
            headers={"X-Mock-Behavior": "timeout"},
        )
        assert timeout_resp.status_code == 504
        assert timeout_resp.json()["error"]["code"] == "provider_timeout"


async def test_mock_behavior_header_ignored_when_mock_mode_disabled() -> None:
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    control_plane_app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
            mock_mode_enabled=False,
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=control_plane_app),
        base_url="http://control-plane",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Header must be ignored"}],
            },
            headers={"X-Mock-Behavior": "fail_503"},
        )
        assert resp.status_code == 200


async def test_admin_fault_toggle_induces_and_recovers_sustained_503_window() -> None:
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    control_plane_app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=POLICY_BUNDLE_PATH,
            model_router_base_url="http://mock-provider",
        ),
        model_router_transport=httpx.ASGITransport(app=mock_app),
    )

    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mock_app),
            base_url="http://mock-provider",
        ) as provider_admin,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=control_plane_app),
            base_url="http://control-plane",
        ) as gateway_client,
    ):
        fault_on = await provider_admin.post(
            "/admin/fault",
            json={"enabled": True, "mode": "fail_503"},
        )
        assert fault_on.status_code == 200
        assert fault_on.json()["enabled"] is True

        failed_resp = await gateway_client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Request during outage"}],
            },
        )
        assert failed_resp.status_code == 503

        fault_off = await provider_admin.post(
            "/admin/fault",
            json={"enabled": False},
        )
        assert fault_off.status_code == 200
        assert fault_off.json()["enabled"] is False

        recovered_resp = await gateway_client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Request after recovery"}],
            },
        )
        assert recovered_resp.status_code == 200
