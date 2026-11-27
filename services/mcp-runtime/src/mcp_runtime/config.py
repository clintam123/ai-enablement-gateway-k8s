"""Configuration settings for the Guarded MCP Runtime service."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class MCPRuntimeSettings(BaseSettings):
    """Environment-driven settings for the Guarded MCP Runtime."""

    model_config = SettingsConfigDict(env_prefix="MCP_RUNTIME_", extra="ignore")

    policy_bundle_path: Path = Path("policies/policy-bundle.yaml")
    internal_identity_secret: str | None = None
    internal_identity_leeway_seconds: int = 0

    redis_url: str | None = None
    redis_socket_timeout_seconds: float = 1.0
    require_redis: bool = True

    tool_timeout_seconds: float | None = None
    max_tool_calls_per_run: int | None = None
    run_ttl_seconds: int | None = None
    tool_delay_seconds: float = 0.0

    otel_service_name: str = "mcp-runtime"
    otel_exporter_otlp_endpoint: str | None = None
