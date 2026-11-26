---
status: accepted
---

# Atomic Reserve-Then-Reconcile Quotas and Fail-Closed Redis

Enforce per-team token and USD budget quotas in Redis using atomic Lua scripts that reserve `prompt_tokens + max_tokens` (or a policy default ceiling when `max_tokens` is omitted) before forwarding to `litellm-proxy`, then reconcile actual usage and refund unused reservation when the response or SSE stream completes. If Redis is unreachable, `gateway-api` fails closed with HTTP `503`.

## Considered Options

- **Check-before, deduct-after:** Simpler implementation, but concurrent request bursts and long-running SSE streams can overshoot team budgets before deductions land.
- **Fail-open on Redis outage:** Maximizes availability during Redis downtime, but silently disables rate limits and spending caps—unacceptable for a governance-first gateway.

## Consequences

- Multi-replica `gateway-api` deployments under HPA share strictly consistent quota state without race conditions.
- Stream completion and client disconnect paths must reliably trigger reconciliation so reserved budget is not leaked.
- Redis becomes a critical-path availability dependency and requires clear readiness checks and alerting.
