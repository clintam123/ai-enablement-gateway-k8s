---
status: accepted
---

# Hybrid Control Plane with Stateless LiteLLM Data Plane

Split the platform into a custom FastAPI governance front door (`gateway-api`) and a stateless LiteLLM Proxy model router (`litellm-proxy`, YAML-only with no Postgres database). LiteLLM Proxy's built-in JWT authentication requires a paid Enterprise license (`LITELLM_LICENSE`), and storing policies in LiteLLM's mutable database conflicts with GitOps-versioned, offline-testable YAML policy bundles. Keeping LiteLLM stateless lets us reuse its 100+ provider adapters, retries, fallback chains, `always_include_stream_usage: true`, and response headers (`x-litellm-attempted-fallbacks`, `x-litellm-model-id`, `x-litellm-model-group`) while keeping all governance, quotas, and audit logging in `gateway-api`.

## Considered Options

- **Standalone LiteLLM Proxy (with Postgres + Redis):** Fewer hops, but JWT auth is gated behind an Enterprise license and policies move out of versioned YAML into database state.
- **Pure Custom FastAPI Gateway (no LiteLLM):** Single hop and lowest latency, but requires hand-rolling and maintaining provider adapters, streaming normalization, and failover logic for OpenAI, Gemini, and vLLM.

## Consequences

- `gateway-api` is the sole system of record for authentication, authorization, guardrails, Redis-backed quotas, and audit logs, adding one internal HTTP hop (~3–8ms).
- `litellm-proxy` is the only workload holding upstream provider API keys and allowed external egress via `NetworkPolicy`, minimizing credential blast radius.
- `gateway-api` depends on LiteLLM's response headers (`x-litellm-attempted-fallbacks`, `x-litellm-model-id`, `x-litellm-model-group`) and `always_include_stream_usage: true` to populate accurate audit records for both JSON and SSE streaming calls.
