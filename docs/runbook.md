# AI Enablement Gateway — Operational Runbook

Concise 1-page incident triage and recovery guide for the **Control Plane** (`gateway-api`), **Model Router** (`litellm-proxy`), **Guarded MCP Runtime** (`mcp-runtime`), Redis **Budget Quota** store, and observability stack.

## 1. Quick Cluster & Endpoint Checks

```bash
# Workload, HPA, and NetworkPolicy status
kubectl get pods,hpa,networkpolicy -n ai-gateway
kubectl get pods -n observability

# Control Plane readiness and active Policy Bundle fingerprint
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz

# Port-forward Prometheus, Grafana, and Jaeger UIs
kubectl port-forward -n observability svc/prometheus 9090:9090
kubectl port-forward -n observability svc/grafana 3000:3000
kubectl port-forward -n observability svc/jaeger 16686:16686
```

- **External `/metrics` boundary:** `GET http://localhost:8080/metrics` must return `404`; scrape internal metrics only via `kubectl port-forward -n ai-gateway svc/ai-gateway-gateway-api 8000:8000` (`GET /metrics`).
- **Jaeger trace lookup:** Query `curl -fsS http://127.0.0.1:16686/api/v3/traces/<trace_id>` or match `trace_id` from structured JSON **Audit Events** in `kubectl logs -n ai-gateway deploy/ai-gateway-gateway-api`.

## 2. Prometheus SLO Alert Triage

All 4 SLO rules live in [`deploy/observability/prometheus/slo-alerts.yml`](../deploy/observability/prometheus/slo-alerts.yml) (`ai-enablement-gateway-slo` group).

| Alert | Severity | Threshold (`for`) | Triage Steps |
| :--- | :--- | :--- | :--- |
| `GatewayHighP95Overhead` | `warning` | `gateway_overhead_duration_seconds_bucket` p95 `> 0.05s` (`50ms`, `2m`) | 1. Inspect `kubectl top pods -n ai-gateway` and `kubectl get hpa ai-gateway-gateway-api -n ai-gateway` to verify HPA scaled past 1 replica.<br>2. Check Redis Lua round-trip latency and Pod CPU throttling (`resources.limits.cpu: 500m`).<br>3. Inspect slow `gateway.chat` / `gateway.mcp` spans in Jaeger (`16686`) to separate Redis/JWKS latency from **Control Plane** regex guardrails. |
| `GatewayHigh5xxErrorRate` | `critical` | `5xx` ratio of `gateway_requests_total` `> 5%` (`2m`) | 1. Query `/readyz` on `gateway-api` and `mcp-runtime` (`503 redis_unavailable` indicates fail-closed Redis outage per ADR-0003).<br>2. Check `kubectl logs -n ai-gateway deploy/ai-gateway-redis` and `deploy/ai-gateway-litellm-proxy` (`502` / `504` indicates **Model Router** unreachable or timed out).<br>3. Verify `NetworkPolicy` allows `gateway-api` -> `ai-gateway-redis:6379`, `ai-gateway-litellm-proxy:4000`, and `ai-gateway-mcp-runtime:8002`. |
| `GatewayHighUpstreamFailoverRate` | `warning` | `gateway_upstream_failovers_total / chat requests > 5%` (`2m`) | 1. Inspect `x-fallback-used`, `x-routed-model`, and `gateway_upstream_failovers_total` by `team`, `requested_model`, and `routed_model`.<br>2. Check primary **Provider** (`mock-llm-primary` `/healthz` or external **Provider** status) and `litellm-proxy` logs (`allowed_fails: 3`, `cooldown_time: 30`).<br>3. Follow Section 3 below to clear injected fault windows and confirm recovery. |
| `GatewayTeamBudgetQuotaExhaustion` | `warning` | `increase(gateway_policy_denials_total{reason="budget_quota_exceeded"}[5m]) > 0` (`1m`) | 1. Identify affected **Team** (`$labels.team`) and inspect `X-Budget-Limit-USD`, `X-Budget-Remaining-USD`, and `Audit Events`.<br>2. Inspect Jaeger traces and `X-Run-Id` headers to rule out a runaway agent **Run** (`429 mcp_run_loop_cap_exceeded` stops loops at 5 calls).<br>3. If legitimate demand increased, raise the **Team**'s `daily_budget_usd` via a GitOps **Policy Bundle** rollout. |

## 3. Failover Check & `/admin/fault` Reset

When primary-to-fallback failover triggers against the local deterministic **Mock Provider**:

```bash
# 1. Confirm current routing header (X-Fallback-Used: true means fallback active)
curl -i -sS -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <CREDENTIAL>" \
  -d '{"model":"chat-default","messages":[{"role":"user","content":"Failover probe"}]}'

# 2. Port-forward mock-llm-primary and clear fault injection
kubectl port-forward -n ai-gateway svc/mock-llm-primary 8000:8000 &
PF_PID=$!
curl -fsS -X POST http://127.0.0.1:8000/admin/fault \
  -H "Content-Type: application/json" \
  -d '{"enabled":false}'
kill "$PF_PID"

# 3. Wait ~30s (LiteLLM router_settings.cooldown_time) and verify X-Fallback-Used: false
```

## 4. Immutable Policy Bundle, Helm & Terraform Rollback

**Policy Bundle** (`policies/policy-bundle.yaml`) and **Model Router** (`services/litellm-proxy/config.yaml`) ConfigMaps are mounted read-only with `immutable: true` and content-hash names plus Pod template `checksum/*` annotations:

```bash
# Remove any temporary Helm Policy Bundle override (returns to chart canonical bundle)
helm upgrade ai-gateway deploy/helm/ai-enablement-platform \
  --namespace ai-gateway --reuse-values --set configMaps.policyBundleOverride=""
kubectl rollout status deployment/ai-gateway-gateway-api -n ai-gateway --timeout=120s
kubectl rollout status deployment/ai-gateway-mcp-runtime -n ai-gateway --timeout=120s

# Or roll back to the previous known-good Helm revision
helm history ai-gateway -n ai-gateway
helm rollback ai-gateway <REVISION> -n ai-gateway
```

For GitOps rollbacks, revert the offending commit on `policies/policy-bundle.yaml` and sync the chart copy (`deploy/helm/ai-enablement-platform/files/policy-bundle.yaml`), verify `uv run python scripts/validate_aliases.py`, and re-apply Terraform (`make up` for local Kind or `make gcp-up` for GKE Autopilot). To tear down ephemeral clusters completely: `make down` (local Kind) or `make gcp-down` (GCP GKE Autopilot).
