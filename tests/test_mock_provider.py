import asyncio

import httpx

from mock_llm.app import create_app
from mock_llm.config import MockProviderSettings


async def test_mock_provider_healthz_identifies_provider_name() -> None:
    app = create_app(
        settings=MockProviderSettings(provider_name="mock-llm-fallback", mock_mode_enabled=True)
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://mock-provider",
    ) as client:
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "provider": "mock-llm-fallback"}


async def test_mock_provider_ignores_x_mock_behavior_when_mock_mode_disabled() -> None:
    app = create_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=False)
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://mock-provider",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Should succeed"}],
            },
            headers={"X-Mock-Behavior": "fail_503"},
        )
        assert resp.status_code == 200


async def test_mock_provider_admin_fault_window_auto_expires() -> None:
    app = create_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://mock-provider",
    ) as client:
        enable_resp = await client.post(
            "/admin/fault",
            json={"enabled": True, "mode": "fail_503", "duration_seconds": 0.05},
        )
        assert enable_resp.status_code == 200

        during_fault = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "During timed fault"}],
            },
        )
        assert during_fault.status_code == 503

        await asyncio.sleep(0.07)

        after_expiry = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "After fault expiry"}],
            },
        )
        assert after_expiry.status_code == 200
