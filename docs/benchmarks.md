# Live `k6` Load Benchmark Report

All metrics below were measured verbatim from an end-to-end [`make bench`](../Makefile) run against a live local Kind cluster (`Calico` CNI, `metrics-server`, `Traefik` Ingress at `http://localhost:8080`, `Redis 7.4.2`, `LiteLLM Proxy 1.84.0`, `Prometheus v3.2.1`, `Grafana 11.5.2`, and `Jaeger 2.23.0`). Raw machine-readable output is preserved in [`benchmarks/results/latest-summary.json`](../benchmarks/results/latest-summary.json).

## Environment & Methodology

- **Run timestamp (UTC):** `2026-11-27T08:33:05.210690+00:00`
- **Load generator:** `k6 v2.4.0 (commit/devel, go1.27.4, darwin/arm64)` via [`benchmarks/k6/gateway_benchmark.js`](../benchmarks/k6/gateway_benchmark.js) and [`scripts/run_benchmarks.py`](../scripts/run_benchmarks.py)
- **Target endpoint:** `http://localhost:8080` (Traefik Ingress -> `ai-gateway-gateway-api` **Control Plane**)
- **Autoscaling baseline:** `gateway-api` Deployment with `100m` CPU request, HPA target `50%` utilization (`50m`), `minReplicas: 1`, `maxReplicas: 4`, `scaleUp.stabilizationWindowSeconds: 15`
- **Control Plane overhead measurement:** Exact histogram bucket delta computed from `gateway_overhead_duration_seconds_bucket{route="/v1/chat/completions"}` before and after steady-state `normal_json` and `sse_stream` phases, cross-checked against Prometheus PromQL `histogram_quantile(...)` across all `4` HPA-scaled targets
- **Isolation safeguard:** Only during Phase 5 (`budget_quota_exhaustion` & `hpa_sustained`), [`scripts/run_benchmarks.py`](../scripts/run_benchmarks.py) applied a temporary Helm `configMaps.policyBundleOverride` raising `platform-eng` `requests_per_minute` and `daily_budget_usd` plus scoping `ops-eng` to a `$0.005` incremental `chat-premium` **Budget Quota** window (keeping `product-eng` strict at `60` RPM / `$10.0` **Budget Quota**) and restored the canonical **Policy Bundle** (`configMaps.policyBundleOverride=""`) in a `finally` block

## Summary Results

| Scenario | Requests | Success Rate | Throughput (RPS) | End-to-End p50 (ms) | End-to-End p95 (ms) | Key Governance / Scaling Outcome |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| `normal_json` | `60` | `100.00%` (`1.0`) | `4.999` | `20.477` | `24.628` | **Control Plane** overhead `3.293` ms p50 / `4.939` ms p95 (`X-Fallback-Used: false`) |
| `sse_stream` | `30` | `100.00%` (`1.0`) | `3.000` | `25.369` | `34.599` | Zero-buffer `text/event-stream`, usage chunk + `[DONE]`, `3.571` ms p50 / `8.750` ms p95 overhead |
| `failover` | `13` | `100.00%` (`1.0`) | `1.396` | `4743.036` | `5339.048` | `/admin/fault` `fail_503` -> `X-Fallback-Used: true` (`mock-llm-fallback`) -> recovered `mock-llm-primary` |
| `quota_exhaustion` (`rpm_limit_exceeded`) | `90` | `60` (`200`) / `30` (`429`) | — | — | — | `product-eng` `60` RPM enforced atomically: `0` over-window leaks, `1.0` (`100%`) `429` header validity & block accuracy |
| `budget_quota_exhaustion` (`budget_quota_exceeded`) | `30` | `4` (`200`) / `26` (`429`) | — | — | — | `ops-eng` daily USD **Budget Quota** (`$0.009595` limit, `$0.007715` final spend): `0.0` USD leaks, `26` Prometheus denials, `1.0` accuracy |
| `hpa_sustained` | `30595` | `99.997%` (`0.999967`) | `339.934` | `47.887` | `95.958` | CPU peaked at `489%` (`100m` request); HPA scaled `1` -> `3` -> `4` Ready replicas (`policy_restored: true`) |

## Control Plane Governance Overhead Breakdown

Across `90` steady-state `/v1/chat/completions` requests (`60` JSON + `30` SSE) executing RS256 JWT verification, **Team** **Model Alias** RBAC, regex PII/safety guardrails, Redis Lua reserve-then-reconcile **Budget Quota** checks, OpenTelemetry spans, and structured **Audit Event** emission:

- **Combined steady-state overhead (`gateway_overhead_duration_seconds_bucket` delta):** `p50 = 3.387 ms`, `p95 = 5.625 ms`, `mean = 3.428 ms`
- **Normal JSON (`60` samples):** `min = 6.754 ms`, `avg = 18.931 ms`, `p50 = 20.477 ms`, `p90 = 24.269 ms`, `p95 = 24.628 ms`, `max = 47.958 ms` (`overhead p50 = 3.293 ms`, `p95 = 4.939 ms`, `mean = 3.255 ms`)
- **SSE Streaming (`30` samples):** `min = 12.326 ms`, `avg = 26.353 ms`, `p50 = 25.369 ms`, `p90 = 29.511 ms`, `p95 = 34.599 ms`, `max = 92.667 ms` (`overhead p50 = 3.571 ms`, `p95 = 8.750 ms`, `mean = 3.774 ms`)
- **Cluster-wide Prometheus PromQL snapshot (after HPA scale-out, `4` targets UP):** `p50 = 2.181 ms`, `p95 = 18.936 ms` — comfortably below the `50 ms` `GatewayHighP95Overhead` SLO alert threshold.

## Failover, Quota Accuracy & HPA Scale-Out Observations

1. **Why failover p50/p95 measured `4743.036 ms` / `5339.048 ms`:** `services/litellm-proxy/config.yaml` configures `num_retries: 2` before invoking `fallbacks` (`chat-default -> chat-default-fallback`), adding retry backoff against `mock-llm-primary` before failing over to `mock-llm-fallback`. Once `/admin/fault` was reset to `{"enabled": false}`, the **Model Router** cleared its `cooldown_time: 30` window and returned cleanly to `mock-llm-primary` (`X-Fallback-Used: false`).
2. **Atomic Redis `429` boundary accuracy (RPM + daily USD Budget Quota):**
   - **RPM limit (`rpm_limit_exceeded`):** Starting on a fresh UTC minute, `90` concurrent requests from `product-eng` (`requests_per_minute: 60`) produced exactly `60` HTTP `200` completions and `30` HTTP `429` denials (`quota_429_rate = 0.333333`, `over_limit_leaks = 0`, `block_accuracy = 1.0`).
   - **Daily USD Budget Quota (`budget_quota_exceeded`):** Under a `$0.005` incremental `ops-eng` daily budget window (`spend_before_usd = 0.004595`, `daily_budget_limit_usd = 0.009595`, `chat-premium`), `30` requests produced `4` HTTP `200` completions (`spend_after_usd = 0.007715`) and `26` HTTP `429` denials (`budget_429_rate = 0.866667`, `over_budget_leaks_usd = 0.0`, `block_accuracy = 1.0`, `gateway_policy_denials_total` delta `= 26.0`). `100%` of `429` responses in both phases carried `Retry-After`, `X-RateLimit-Limit-Requests`, `X-RateLimit-Remaining-Requests`, `X-Budget-Limit-USD`, `X-Budget-Remaining-USD`, and `X-Policy-Denial-Reason`.
3. **HPA scale-out timeline (`1 -> 3 -> 4` Ready replicas):** Under `24` concurrent VUs (`30595` total requests at `339.934` RPS) running RS256 verification and regex PII scrubbing, `metrics-server` recorded CPU rising to `421%`, then peaking at `489%`. HPA scaled `ai-gateway-gateway-api` from `1` to `3` Ready pods within ~`30s` and `4` Ready pods by ~`46s`, dropping per-pod CPU utilization to `250%` and `229%` (`success_rate = 0.999967`, `max = 564.176 ms`).

## Reproducing Locally

```bash
make dev-creds
make up ENABLE_OBSERVABILITY=true
uv run python scripts/smoke_test.py --check-observability
make bench
make down
```
