---
status: accepted
---

# Gateway-Mediated MCP with Signed Internal Identity and Server-Side Loop Cap

Route all MCP Streamable HTTP traffic (`/mcp`) through `gateway-api` rather than exposing `mcp-runtime` on its own Ingress. After authenticating the caller, `gateway-api` mints a short-lived signed internal identity token (`actor_id`, `team`, `role`, `run_id`, `trace_id`) that `mcp-runtime` cryptographically verifies before enforcing tool-level RBAC, per-call timeouts, and a Redis-backed per-`run_id` max tool-call circuit breaker.

## Considered Options

- **Direct Ingress to `mcp-runtime`:** Avoids proxying MCP through `gateway-api`, but expands external ingress surface and duplicates JWT/API-key auth logic across two services.
- **Trusted plain `X-*` headers + client-side loop cap:** Simpler, but plain headers violate zero-trust defense-in-depth if `NetworkPolicy` is ever misconfigured, and an SDK-side loop cap is easily bypassed by raw HTTP clients.

## Consequences

- `mcp-runtime` runs in stateless Streamable HTTP mode with zero external ingress and rejects unsigned or tampered requests even from inside the cluster.
- Runaway agent loops are stopped server-side in Redis across multiple `mcp-runtime` replicas.
