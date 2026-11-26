"""Configuration settings for the deterministic Mock Provider service."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class MockProviderSettings(BaseSettings):
    """Environment-driven settings for the Mock Provider."""

    model_config = SettingsConfigDict(env_prefix="MOCK_LLM_", extra="ignore")

    provider_name: str = "mock-llm-primary"
    mock_mode_enabled: bool = True
    base_latency_ms: int = 0
    timeout_delay_ms: int = 5000
