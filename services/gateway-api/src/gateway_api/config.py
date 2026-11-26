"""Configuration settings for the Control Plane service."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class ControlPlaneSettings(BaseSettings):
    """Environment-driven settings for the Control Plane."""

    model_config = SettingsConfigDict(env_prefix="GATEWAY_", extra="ignore")

    policy_bundle_path: Path = Path("policies/policy-bundle.yaml")
    model_router_base_url: str = "http://localhost:8001"
    model_router_api_key: str | None = None
    model_router_timeout_seconds: float = 30.0
    mock_mode_enabled: bool = True
