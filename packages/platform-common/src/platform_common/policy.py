"""Versioned Policy Bundle schema and atomic file loader."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class PolicyDefaults(BaseModel):
    """Default governance parameters when Team or Model Alias overrides are omitted."""

    model_config = ConfigDict(frozen=True)

    default_max_tokens_ceiling: int = Field(default=512, ge=1)
    requests_per_minute: int = Field(default=60, ge=1)
    daily_budget_usd: float = Field(default=10.0, ge=0.0)
    mcp_tool_timeout_seconds: float = Field(default=5.0, gt=0.0)
    mcp_max_tool_calls_per_run: int = Field(default=5, ge=1)
    mcp_run_ttl_seconds: int = Field(default=3600, ge=1)


class ModelAliasPolicy(BaseModel):
    """Pricing and reservation ceiling for a logical Model Alias."""

    model_config = ConfigDict(frozen=True)

    prompt_usd_per_1k_tokens: float = Field(ge=0.0)
    completion_usd_per_1k_tokens: float = Field(ge=0.0)
    max_tokens_ceiling: int | None = Field(default=None, ge=1)


class TeamPolicy(BaseModel):
    """Per-Team Model Alias RBAC, Budget Quotas, RPM, and MCP Tool allowlists."""

    model_config = ConfigDict(frozen=True)

    allowed_model_aliases: tuple[str, ...] = Field(default_factory=tuple)
    model_alias_remapping: dict[str, str] = Field(default_factory=dict)
    requests_per_minute: int = Field(ge=1)
    daily_budget_usd: float = Field(ge=0.0)
    mcp_tool_allowlist: dict[str, tuple[str, ...]] = Field(default_factory=dict)


class SafetyRule(BaseModel):
    """Pre-call PII redaction or prompt-denial safety rule."""

    model_config = ConfigDict(frozen=True)

    id: str
    pattern: str
    action: Literal["redact", "deny"]
    entity_type: str | None = None
    replacement: str | None = None
    description: str = ""


class PolicyBundle(BaseModel):
    """Immutable governance Policy Bundle loaded atomically by the Control Plane."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = "v1"
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    models: dict[str, ModelAliasPolicy] = Field(default_factory=dict)
    teams: dict[str, TeamPolicy] = Field(default_factory=dict)
    safety_rules: tuple[SafetyRule, ...] = Field(default_factory=tuple)


class LoadedPolicyBundle(BaseModel):
    """Validated Policy Bundle paired with its deterministic policy_version fingerprint."""

    model_config = ConfigDict(frozen=True)

    bundle: PolicyBundle
    policy_version: str
    sha256: str
    source_path: Path


def load_policy_bundle(path: str | Path) -> LoadedPolicyBundle:
    """Atomically read, validate, and fingerprint a YAML Policy Bundle from disk."""
    bundle_path = Path(path)
    raw_bytes = bundle_path.read_bytes()
    sha256_hex = hashlib.sha256(raw_bytes).hexdigest()

    parsed = yaml.safe_load(raw_bytes)
    if not isinstance(parsed, dict):
        raise ValueError(f"Policy Bundle at {bundle_path} must be a YAML mapping")

    bundle = PolicyBundle.model_validate(parsed)
    policy_version = f"{bundle.schema_version}+{sha256_hex[:8]}"

    return LoadedPolicyBundle(
        bundle=bundle,
        policy_version=policy_version,
        sha256=sha256_hex,
        source_path=bundle_path,
    )


def authorize_mcp_tool(
    policy: PolicyBundle,
    *,
    team: str,
    role: str,
    tool_name: str,
    target_team: str | None = None,
) -> tuple[bool, str | None]:
    """Authorize Role- and Team-scoped MCP Tool access and cross-Team queries."""
    team_policy = policy.teams.get(team)
    if team_policy is None:
        return False, "team_not_allowed"
    allowed_tools = team_policy.mcp_tool_allowlist.get(role, ())
    if tool_name not in allowed_tools:
        return False, "mcp_tool_not_allowed"
    if (
        tool_name == "check_model_catalog"
        and role != "admin"
        and target_team is not None
        and target_team.strip() != team
    ):
        return False, "mcp_cross_team_denied"
    return True, None
