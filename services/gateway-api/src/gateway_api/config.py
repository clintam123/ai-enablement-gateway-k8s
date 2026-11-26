"""Configuration settings for the Control Plane service."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict


class ControlPlaneSettings(BaseSettings):
    """Environment-driven settings for the Control Plane."""

    model_config = SettingsConfigDict(env_prefix="GATEWAY_", extra="ignore")

    policy_bundle_path: Path = Path("policies/policy-bundle.yaml")
    model_router_base_url: str = "http://localhost:8001"
    model_router_api_key: str | None = None
    model_router_timeout_seconds: float = 30.0
    mock_mode_enabled: bool = True

    # Credential authentication settings
    api_keys_path: Path | None = None
    api_keys_json: str | None = None
    api_keys: dict[str, dict[str, Any]] | None = None

    jwt_issuer: str = "https://auth.ai-gateway.local"
    jwt_audience: str = "ai-enablement-gateway"
    jwt_jwks_url: str | None = None
    jwt_jwks_json: str | None = None
    jwt_jwks: dict[str, Any] | None = None
    jwt_jwks_cache_ttl_seconds: int = 300
    jwt_leeway_seconds: int = 0

    jwt_hs256_enabled: bool = False
    jwt_hs256_secret: str | None = None

    # Redis Budget Quota & RPM settings
    redis_url: str | None = None
    redis_socket_timeout_seconds: float = 1.0
    require_redis: bool = True

    # OpenTelemetry tracing settings
    otel_service_name: str = "gateway-api"
    otel_exporter_otlp_endpoint: str | None = None
