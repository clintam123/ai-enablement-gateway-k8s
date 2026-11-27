# Live `k6` Load Benchmark Report

All metrics below were measured verbatim from an end-to-end [`make bench`](../Makefile) run against a live local Kind cluster (`Calico` CNI, `metrics-server`, `Traefik` Ingress at `http://localhost:8080`, `Redis 7.4.2`, `LiteLLM Proxy 1.84.0`, `Prometheus v3.2.1`, `Grafana 11.5.2`, and `Jaeger 2.23.0`). Raw machine-readable output is preserved in [`benchmarks/results/latest-summary.json`](../benchmarks/results/latest-summary.json).

## Environment & Methodology

- **Run timestamp (UTC):** `2026-11-27T03:15:53.977734+00:00`
- **Load generator:** `k6 v2.4.0 (commit/devel, go1.27.4, darwin/arm64)` via [`benchmarks/k6/gateway_benchmark.js`](../benchmarks/k6/gateway_benchmark.js) and [`scripts/run_benchmarks.py`](../scripts/run_benchmarks.py)
- **Target endpoint:** `http://localhost:8080` (Traefik Ingress -> `ai-gateway-gateway-api` **Control Plane**)
- **Autoscaling baseline:** `gateway-api` Deployment with `100m` CPU request, HPA target `50%` utilization (`50m`), `minReplicas: 1`, `maxReplicas: 4`, `scaleUp.stabilizationWindowSeconds: 15`
- **Control Plane overhead measurement:** Exact histogram bucket delta computed from `gateway_overhead_duration_seconds_bucket{route="/v1/chat/completions"}` before and after steady-state `normal_json` and `sse_stream` phases, cross-checked against Prometheus PromQL `histogram_quantile(...)` across all `4` HPA-scaled targets
- **HPA isolation safeguard:** Only during `hpa_sustained`, [`scripts/run_benchmarks.py`](../scripts/run_benchmarks.py) applied a temporary Helm `configMaps.policyBundleOverride` raising `platform-eng` `requests_per_minute` and `daily_budget_usd` (keeping `product-eng` strict at `60` RPM / `$10.0` **Budget Quota**) and restored the canonical **Policy Bundle** (`configMaps.policyBundleOverride=""`) in a `finally` block

## Summary Results

| Scenario | Requests | Success Rate | Throughput (RPS) | End-to-End p50 (ms) | End-to-End p95 (ms) | Key Governance / Scaling Outcome |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| `normal_json` | `61` | `100.00%` (`1.0`) | `5.074` | `19.147` | `28.672` | **Control Plane** overhead `3.219` ms p50 / `4.934` ms p95 (`X-Fallback-Used: false`) |
| `sse_stream` | `30` | `100.00%` (`1.0`) | `3.000` | `23.198` | `32.121` | Zero-buffer `text/event-stream`, usage chunk + `[DONE]`, `3.452` ms p50 / `6.250` ms p95 overhead |
| `failover` | `13` | `100.00%` (`1.0`) | `1.316` | `4782.615` | `5431.677` | `/admin/fault` `fail_503` -> `X-Fallback-Used: true` (`mock-llm-fallback`) -> recovered `mock-llm-primary` |
| `quota_exhaustion` | `90` | `60` (`200`) / `30` (`429`) | — | — | — | `product-eng` `60` RPM enforced atomically: `0` over-window leaks, `1.0` (`100%`) `429` header validity & block accuracy |
| `hpa_sustained` | `32103` | `99.69%` (`0.996916`) | `356.696` | `44.974` | `69.004` | CPU peaked at `488%` (`100m` request); HPA scaled `1` -> `3` -> `4` Ready replicas (`policy_restored: true`) |

## Control Plane Governance Overhead Breakdown

Across `91` steady-state `/v1/chat/completions` requests (`61` JSON + `30` SSE) executing RS256 JWT verification, **Team** **Model Alias** RBAC, regex PII/safety guardrails, Redis Lua reserve-then-reconcile **Budget Quota** checks, OpenTelemetry spans, and structured **Audit Event** emission:

- **Combined steady-state overhead (`gateway_overhead_duration_seconds_bucket` delta):** `p50 = 3.299 ms`, `p95 = 4.977 ms`, `mean = 3.246 ms`
- **Normal JSON (`61` samples):** `min = 7.783 ms`, `avg = 19.195 ms`, `p50 = 19.147 ms`, `p90 = 24.205 ms`, `p95 = 28.672 ms`, `max = 53.594 ms` (`overhead p50 = 3.219 ms`, `p95 = 4.934 ms`, `mean = 3.228 ms`)
- **SSE Streaming (`30` samples):** `min = 12.252 ms`, `avg = 23.920 ms`, `p50 = 23.198 ms`, `p90 = 29.979 ms`, `p95 = 32.121 ms`, `max = 53.933 ms` (`overhead p50 = 3.452 ms`, `p95 = 6.250 ms`, `mean = 3.283 ms`)
- **Cluster-wide Prometheus PromQL snapshot (after HPA scale-out, `4` targets UP):** `p50 = 2.024 ms`, `p95 = 13.736 ms` — comfortably below the `50 ms` `GatewayHighP95Overhead` SLO alert threshold.

## Failover, Quota Accuracy & HPA Scale-Out Observations

1. **Why failover p50/p95 measured `4782.615 ms` / `5431.677 ms`:** `services/litellm-proxy/config.yaml` configures `num_retries: 2` before invoking `fallbacks` (`chat-default -> chat-default-fallback`), adding retry backoff against `mock-llm-primary` before failing over to `mock-llm-fallback`. Once `/admin/fault` was reset to `{"enabled": false}`, the **Model Router** cleared its `cooldown_time: 30` window and returned cleanly to `mock-llm-primary` (`X-Fallback-Used: false`).
2. **Atomic Redis `429` boundary accuracy:** Starting on a fresh UTC minute, `90` concurrent requests from `product-eng` (`requests_per_minute: 60`) produced exactly `60` HTTP `200` completions and `30` HTTP `429` denials (`quota_429_rate = 0.333333`, `over_limit_leaks = 0`, `block_accuracy = 1.0`), with `100%` of `429` responses carrying `Retry-After`, `X-RateLimit-Limit-Requests`, `X-RateLimit-Remaining-Requests`, `X-Budget-Limit-USD`, and `X-Policy-Denial-Reason`.
3. **HPA scale-out timeline (`1 -> 3 -> 4` Ready replicas):** Under `24` concurrent VUs (`32103` total requests at `356.696` RPS) running RS256 verification and regex PII scrubbing, `metrics-server` recorded CPU rising from `19%` to `439%`, then `488%`. HPA scaled `ai-gateway-gateway-api` from `1` to `3` Ready pods within ~`35s` and `4` Ready pods by ~`50s`, dropping per-pod CPU utilization to `242%` and `220%`. Approximately `0.31%` of burst requests (`success_rate = 0.996916`, `max = 30003.131 ms`) hit the `30s` HTTP timeout while single-pod **Control Plane** and single-worker `litellm-proxy` absorbed the initial `488%` CPU spike prior to scale-out.

## Reproducing Locally

```bash
make dev-creds
make up ENABLE_OBSERVABILITY=true
uv run python scripts/smoke_test.py --check-observability
make bench
make down
```
