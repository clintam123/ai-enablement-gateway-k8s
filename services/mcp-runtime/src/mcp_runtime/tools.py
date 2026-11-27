"""Stateless FastMCP server and deterministic read-only operational MCP Tools."""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

from platform_common import InternalIdentityAssertion, LoadedPolicyBundle

ACTOR_ASSERTION_CTX: ContextVar[InternalIdentityAssertion | None] = ContextVar(
    "mcp_runtime_actor_assertion",
    default=None,
)

_RUNBOOKS: tuple[dict[str, Any], ...] = (
    {
        "id": "rb-router-failover",
        "title": "Model Router Primary-to-Fallback Failover",
        "severity": "sev2",
        "tags": ["failover", "litellm", "router", "503", "provider"],
        "summary": (
            "Verify LiteLLM fallback routing headers and upstream mock/provider health "
            "when primary Provider latency or 503 rate spikes."
        ),
        "steps": [
            "Check gateway_upstream_failovers_total and x-litellm-attempted-fallbacks.",
            "Inspect litellm-proxy /health/readiness and mock-llm-primary /healthz.",
            "Verify Policy Bundle model_alias_remapping and cooldown_time settings.",
        ],
    },
    {
        "id": "rb-redis-quota-failclosed",
        "title": "Redis Budget Quota & MCP Loop Cap Fail-Closed Recovery",
        "severity": "sev1",
        "tags": ["redis", "quota", "503", "loop", "budget"],
        "summary": (
            "Control Plane and MCP Runtime fail closed with 503 when Redis is unreachable "
            "or timing out on Lua reservation/loop-cap scripts."
        ),
        "steps": [
            "Check /readyz on gateway-api and mcp-runtime for redis_unavailable errors.",
            "Verify Redis pod readiness, memory headroom, and NetworkPolicy port 6379.",
            "Confirm Lua script execution latency stays below redis_socket_timeout_seconds.",
        ],
    },
    {
        "id": "rb-mcp-loop-cap",
        "title": "Agent Run Loop Cap Circuit Breaker Triage",
        "severity": "sev3",
        "tags": ["mcp", "loop", "429", "run_id", "timeout"],
        "summary": (
            "Diagnose 429 mcp_run_loop_cap_exceeded or 504 mcp_tool_timeout responses "
            "for a runaway agent Run."
        ),
        "steps": [
            "Inspect x-run-id, x-mcp-run-calls, and x-mcp-run-limit headers.",
            "Query Jaeger trace by trace_id to locate repeated tools/call spans.",
            "Confirm caller starts a fresh X-Run-Id for a new bounded Run.",
        ],
    },
)

_SERVICE_SLOS: dict[str, dict[str, Any]] = {
    "gateway-api": {
        "service_name": "gateway-api",
        "availability_target": 0.999,
        "p95_latency_ms_target": 120.0,
        "overhead_p95_ms_target": 25.0,
        "error_budget_remaining_pct": 99.4,
        "status": "healthy",
    },
    "litellm-proxy": {
        "service_name": "litellm-proxy",
        "availability_target": 0.999,
        "p95_latency_ms_target": 350.0,
        "overhead_p95_ms_target": 40.0,
        "error_budget_remaining_pct": 98.9,
        "status": "healthy",
    },
    "mcp-runtime": {
        "service_name": "mcp-runtime",
        "availability_target": 0.999,
        "p95_latency_ms_target": 200.0,
        "overhead_p95_ms_target": 30.0,
        "error_budget_remaining_pct": 99.7,
        "status": "healthy",
    },
    "redis": {
        "service_name": "redis",
        "availability_target": 0.9995,
        "p95_latency_ms_target": 10.0,
        "overhead_p95_ms_target": 5.0,
        "error_budget_remaining_pct": 99.9,
        "status": "healthy",
    },
}


def build_mcp_server(
    *,
    loaded_policy: LoadedPolicyBundle,
    tool_delay_seconds: float = 0.0,
) -> tuple[FastMCP, Starlette]:
    """Create the stateless Streamable HTTP FastMCP instance and ASGI sub-app."""
    mcp = FastMCP(
        "ai-enablement-mcp-runtime",
        stateless_http=True,
        json_response=True,
        streamable_http_path="/mcp",
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    async def _maybe_delay() -> None:
        if tool_delay_seconds > 0.0:
            await asyncio.sleep(tool_delay_seconds)

    @mcp.tool()
    async def check_model_catalog(team: str) -> dict[str, Any]:
        """Return allowed Model Aliases, rate limits, and Budget Quotas for a Team."""
        await _maybe_delay()
        normalized_team = team.strip()
        assertion = ACTOR_ASSERTION_CTX.get()
        if (
            assertion is not None
            and assertion.role != "admin"
            and normalized_team != assertion.team
        ):
            raise PermissionError(
                f"Role '{assertion.role}' may not query catalog for Team '{normalized_team}'"
            )

        team_policy = loaded_policy.bundle.teams.get(normalized_team)
        if team_policy is None:
            return {
                "team": normalized_team,
                "found": False,
                "policy_version": loaded_policy.policy_version,
                "allowed_model_aliases": [],
                "models": {},
            }

        return {
            "team": normalized_team,
            "found": True,
            "policy_version": loaded_policy.policy_version,
            "allowed_model_aliases": list(team_policy.allowed_model_aliases),
            "requests_per_minute": team_policy.requests_per_minute,
            "daily_budget_usd": team_policy.daily_budget_usd,
            "models": {
                alias: {
                    "prompt_usd_per_1k_tokens": loaded_policy.bundle.models[
                        alias
                    ].prompt_usd_per_1k_tokens,
                    "completion_usd_per_1k_tokens": loaded_policy.bundle.models[
                        alias
                    ].completion_usd_per_1k_tokens,
                    "max_tokens_ceiling": loaded_policy.bundle.models[alias].max_tokens_ceiling,
                }
                for alias in team_policy.allowed_model_aliases
                if alias in loaded_policy.bundle.models
            },
        }

    @mcp.tool()
    async def query_runbook(query: str) -> dict[str, Any]:
        """Search deterministic operational runbooks by keyword."""
        await _maybe_delay()
        tokens = [tok for tok in query.lower().split() if tok]
        matches: list[dict[str, Any]] = []
        for entry in _RUNBOOKS:
            haystack = " ".join(
                [
                    entry["id"],
                    entry["title"],
                    entry["summary"],
                    " ".join(entry["tags"]),
                    " ".join(entry["steps"]),
                ]
            ).lower()
            if not tokens or any(tok in haystack for tok in tokens):
                matches.append(entry)
        return {
            "match_count": len(matches),
            "runbooks": matches,
        }

    @mcp.tool()
    async def lookup_service_slo(service_name: str) -> dict[str, Any]:
        """Return deterministic SLO targets and error budget status for a platform service."""
        await _maybe_delay()
        normalized = service_name.strip().lower()
        slo = _SERVICE_SLOS.get(normalized)
        if slo is None:
            return {
                "service_name": service_name.strip(),
                "found": False,
            }
        return {
            "found": True,
            **slo,
        }

    mcp_asgi_app = mcp.streamable_http_app()
    return mcp, mcp_asgi_app
