"""Reproducible k6 + live Kind benchmark orchestrator for AI Enablement Gateway."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml

try:
    from scripts.smoke_test import (
        DEFAULT_BASE_URL,
        DEFAULT_CREDENTIALS_PATH,
        DEFAULT_NAMESPACE,
        DEFAULT_OBSERVABILITY_NAMESPACE,
        PortForwardFactory,
        _default_kubectl_runner,
        _default_port_forward,
        _fresh_rs256_jwt,
        _load_credentials,
    )
except ModuleNotFoundError:  # Invoked directly as `python scripts/run_benchmarks.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from scripts.smoke_test import (
        DEFAULT_BASE_URL,
        DEFAULT_CREDENTIALS_PATH,
        DEFAULT_NAMESPACE,
        DEFAULT_OBSERVABILITY_NAMESPACE,
        PortForwardFactory,
        _default_kubectl_runner,
        _default_port_forward,
        _fresh_rs256_jwt,
        _load_credentials,
    )

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_K6_SCRIPT_PATH = REPO_ROOT / "benchmarks" / "k6" / "gateway_benchmark.js"
DEFAULT_OUTPUT_PATH = REPO_ROOT / "benchmarks" / "results" / "latest-summary.json"
DEFAULT_POLICY_BUNDLE_PATH = REPO_ROOT / "policies" / "policy-bundle.yaml"
DEFAULT_CHART_DIR = REPO_ROOT / "deploy" / "helm" / "ai-enablement-platform"
DEFAULT_RELEASE_NAME = "ai-gateway"

_METRIC_LINE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|[+-]?Inf|NaN)$"
)
_LABEL_PAIR_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')

KubectlRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
HelmRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
K6Runner = Callable[..., subprocess.CompletedProcess[str]]


def _default_helm_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _parse_labels(raw_labels: str | None) -> dict[str, str]:
    if not raw_labels:
        return {}
    return {match.group(1): match.group(2) for match in _LABEL_PAIR_RE.finditer(raw_labels)}


def parse_overhead_histogram_samples(
    metrics_text: str,
    *,
    route: str = "/v1/chat/completions",
) -> tuple[dict[str, float], float, float]:
    """Parse gateway_overhead_duration_seconds bucket, sum, and count for one route."""
    buckets: dict[str, float] = {}
    total_sum = 0.0
    total_count = 0.0

    for raw_line in metrics_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _METRIC_LINE_RE.match(line)
        if match is None:
            continue
        metric_name, raw_labels, raw_value = match.groups()
        labels = _parse_labels(raw_labels)
        if labels.get("route") != route:
            continue
        value = float(raw_value)
        if metric_name == "gateway_overhead_duration_seconds_bucket":
            le = labels.get("le")
            if le is not None:
                buckets[le] = buckets.get(le, 0.0) + value
        elif metric_name == "gateway_overhead_duration_seconds_sum":
            total_sum += value
        elif metric_name == "gateway_overhead_duration_seconds_count":
            total_count += value

    return buckets, total_sum, total_count


def compute_histogram_quantile_ms(bucket_counts: dict[str, float], quantile: float) -> float:
    """Compute Prometheus-style linear-interpolated histogram quantile in milliseconds."""
    if not 0.0 <= quantile <= 1.0:
        raise ValueError(f"quantile must be in [0, 1], got {quantile}")
    if not bucket_counts:
        return 0.0

    finite_buckets: list[tuple[float, float]] = []
    inf_count: float | None = None
    for le_key, count in bucket_counts.items():
        if le_key == "+Inf":
            inf_count = count
            continue
        finite_buckets.append((float(le_key), count))

    finite_buckets.sort(key=lambda pair: pair[0])
    fallback_total = finite_buckets[-1][1] if finite_buckets else 0.0
    total = inf_count if inf_count is not None else fallback_total
    if total <= 0.0 or not finite_buckets:
        return 0.0

    rank = quantile * total
    prev_bound = 0.0
    prev_count = 0.0
    for bound, cumulative_count in finite_buckets:
        if cumulative_count >= rank:
            bucket_span = cumulative_count - prev_count
            if bucket_span <= 0.0:
                return round(bound * 1000.0, 3)
            fraction = (rank - prev_count) / bucket_span
            return round((prev_bound + fraction * (bound - prev_bound)) * 1000.0, 3)
        prev_bound = bound
        prev_count = cumulative_count

    return round(finite_buckets[-1][0] * 1000.0, 3)


def compute_overhead_delta_summary(
    before_text: str,
    after_text: str,
    *,
    route: str = "/v1/chat/completions",
) -> dict[str, Any]:
    """Compute exact Control Plane overhead p50/p95/mean ms from /metrics histogram delta."""
    before_buckets, before_sum, before_count = parse_overhead_histogram_samples(
        before_text, route=route
    )
    after_buckets, after_sum, after_count = parse_overhead_histogram_samples(
        after_text, route=route
    )

    delta_buckets: dict[str, float] = {}
    for le_key in set(before_buckets) | set(after_buckets):
        delta_buckets[le_key] = max(
            0.0, after_buckets.get(le_key, 0.0) - before_buckets.get(le_key, 0.0)
        )

    delta_count = max(0.0, after_count - before_count)
    delta_sum = max(0.0, after_sum - before_sum)
    mean_ms = round((delta_sum / delta_count) * 1000.0, 3) if delta_count > 0 else 0.0

    return {
        "sample_count": round(delta_count),
        "p50_ms": compute_histogram_quantile_ms(delta_buckets, 0.50),
        "p95_ms": compute_histogram_quantile_ms(delta_buckets, 0.95),
        "mean_ms": mean_ms,
        "_delta_buckets": delta_buckets,
        "_delta_sum_seconds": delta_sum,
    }


def merge_overhead_deltas(deltas: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge multiple phase overhead bucket deltas into a single exact summary."""
    combined_buckets: dict[str, float] = {}
    total_count = 0
    total_sum_seconds = 0.0

    for item in deltas:
        total_count += int(item.get("sample_count", 0))
        total_sum_seconds += float(item.get("_delta_sum_seconds", 0.0))
        for le_key, val in (item.get("_delta_buckets") or {}).items():
            combined_buckets[le_key] = combined_buckets.get(le_key, 0.0) + float(val)

    mean_ms = round((total_sum_seconds / total_count) * 1000.0, 3) if total_count > 0 else 0.0
    return {
        "sample_count": total_count,
        "p50_ms": compute_histogram_quantile_ms(combined_buckets, 0.50),
        "p95_ms": compute_histogram_quantile_ms(combined_buckets, 0.95),
        "mean_ms": mean_ms,
    }


def parse_policy_denials_sample(
    metrics_text: str,
    *,
    team: str,
    reason: str,
) -> float:
    """Extract gateway_policy_denials_total sample value for one Team and denial reason."""
    total = 0.0
    for raw_line in metrics_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _METRIC_LINE_RE.match(line)
        if match is None:
            continue
        metric_name, raw_labels, raw_value = match.groups()
        if metric_name != "gateway_policy_denials_total":
            continue
        labels = _parse_labels(raw_labels)
        if labels.get("team") == team and labels.get("reason") == reason:
            total += float(raw_value)
    return total


def build_hpa_benchmark_policy_override(
    policy_path: Path = DEFAULT_POLICY_BUNDLE_PATH,
    *,
    platform_rpm: int = 100_000,
    platform_daily_budget_usd: float = 10_000.0,
    ops_rpm: int | None = None,
    ops_daily_budget_usd: float | None = None,
    ops_allow_chat_premium: bool = False,
) -> str:
    """Create temporary Policy Bundle YAML for HPA and optional Budget Quota testing."""
    parsed = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict) or not isinstance(parsed.get("teams"), dict):
        raise ValueError(f"Malformed Policy Bundle at {policy_path}")
    teams = parsed["teams"]
    if "platform-eng" not in teams:
        raise ValueError("Policy Bundle missing 'platform-eng' Team")
    teams["platform-eng"]["requests_per_minute"] = platform_rpm
    teams["platform-eng"]["daily_budget_usd"] = platform_daily_budget_usd
    if ops_rpm is not None or ops_daily_budget_usd is not None or ops_allow_chat_premium:
        if "ops-eng" not in teams:
            raise ValueError("Policy Bundle missing 'ops-eng' Team")
        if ops_rpm is not None:
            teams["ops-eng"]["requests_per_minute"] = ops_rpm
        if ops_daily_budget_usd is not None:
            teams["ops-eng"]["daily_budget_usd"] = ops_daily_budget_usd
        if ops_allow_chat_premium:
            aliases = list(teams["ops-eng"].get("allowed_model_aliases") or [])
            if "chat-premium" not in aliases:
                aliases.append("chat-premium")
            teams["ops-eng"]["allowed_model_aliases"] = aliases
    return yaml.safe_dump(parsed, sort_keys=False)


def _make_client(
    base_url: str,
    *,
    http_transport: httpx.AsyncBaseTransport | None,
    timeout_seconds: float = 15.0,
) -> httpx.Client:
    kwargs: dict[str, Any] = {
        "base_url": base_url.rstrip("/"),
        "timeout": httpx.Timeout(timeout_seconds),
    }
    if http_transport is not None and isinstance(http_transport, httpx.BaseTransport):
        kwargs["transport"] = http_transport
    return httpx.Client(**kwargs)


def _metric_values(summary_doc: dict[str, Any], metric_name: str) -> dict[str, Any]:
    raw = (summary_doc.get("metrics") or {}).get(metric_name) or {}
    if isinstance(raw.get("values"), dict):
        return raw["values"]
    return raw


def _extract_trend_stats(summary_doc: dict[str, Any], metric_name: str) -> dict[str, float]:
    vals = _metric_values(summary_doc, metric_name)
    return {
        "min": round(float(vals.get("min", 0.0)), 3),
        "avg": round(float(vals.get("avg", 0.0)), 3),
        "p50": round(float(vals.get("med", vals.get("p(50)", 0.0))), 3),
        "p90": round(float(vals.get("p(90)", 0.0)), 3),
        "p95": round(float(vals.get("p(95)", 0.0)), 3),
        "max": round(float(vals.get("max", 0.0)), 3),
    }


def _extract_rate_stats(summary_doc: dict[str, Any], metric_name: str) -> dict[str, Any]:
    vals = _metric_values(summary_doc, metric_name)
    passes = int(vals.get("passes", 0))
    fails = int(vals.get("fails", 0))
    if "value" in vals:
        rate_val = float(vals["value"])
    elif passes + fails > 0:
        rate_val = passes / (passes + fails)
    else:
        rate_val = 0.0
    return {
        "value": round(rate_val, 6),
        "passes": passes,
        "fails": fails,
    }


def _extract_counter_count(summary_doc: dict[str, Any], metric_name: str) -> int:
    vals = _metric_values(summary_doc, metric_name)
    return int(vals.get("count", 0))


def _default_k6_runner(
    *,
    scenario: str,
    summary_export_path: Path,
    env: dict[str, str],
    on_poll: Callable[[], None] | None = None,
    poll_interval_seconds: float = 5.0,
    k6_script_path: Path = DEFAULT_K6_SCRIPT_PATH,
) -> subprocess.CompletedProcess[str]:
    k6_bin = shutil.which("k6")
    cmd_env = {**os.environ, **env}
    if k6_bin is not None:
        cmd = [
            k6_bin,
            "run",
            "--summary-export",
            str(summary_export_path),
            str(k6_script_path),
        ]
    else:
        # Docker fallback when local k6 CLI is unavailable.
        summary_dir = str(summary_export_path.parent)
        summary_name = summary_export_path.name
        script_dir = str(k6_script_path.parent)
        script_name = k6_script_path.name
        docker_env_args: list[str] = []
        for key, value in env.items():
            if key == "BASE_URL" and "localhost" in value:
                value = value.replace("localhost", "host.docker.internal")
            elif key == "BASE_URL" and "127.0.0.1" in value:
                value = value.replace("127.0.0.1", "host.docker.internal")
            docker_env_args.extend(["-e", f"{key}={value}"])
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network=host",
            *docker_env_args,
            "-v",
            f"{script_dir}:/scripts:ro",
            "-v",
            f"{summary_dir}:/out",
            "grafana/k6:latest",
            "run",
            "--summary-export",
            f"/out/{summary_name}",
            f"/scripts/{script_name}",
        ]

    if on_poll is None:
        return subprocess.run(cmd, env=cmd_env, capture_output=True, text=True, check=False)

    proc = subprocess.Popen(
        cmd,
        env=cmd_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        while proc.poll() is None:
            on_poll()
            time.sleep(poll_interval_seconds)
        on_poll()
        stdout, stderr = proc.communicate(timeout=10)
    except BaseException:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout=stdout, stderr=stderr)


def _scrape_gateway_metrics(
    *,
    namespace: str,
    port_forward_factory: PortForwardFactory,
    http_transport: Any | None,
) -> str:
    with (
        port_forward_factory("svc/ai-gateway-gateway-api", 8000, namespace) as local_port,
        _make_client(
            f"http://127.0.0.1:{local_port}",
            http_transport=http_transport,
            timeout_seconds=10.0,
        ) as client,
    ):
        resp = client.get("/metrics")
        if resp.status_code != 200:
            raise RuntimeError(f"Failed scraping /metrics from gateway-api: {resp.status_code}")
        return resp.text


def _wait_for_gateway_ready(
    base_url: str,
    *,
    http_transport: Any | None,
    timeout_seconds: float = 60.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_err = "not polled"
    with _make_client(base_url, http_transport=http_transport, timeout_seconds=5.0) as client:
        while time.monotonic() < deadline:
            try:
                resp = client.get("/readyz")
                if resp.status_code == 200:
                    return
                last_err = f"HTTP {resp.status_code}"
            except httpx.HTTPError as exc:
                last_err = repr(exc)
            time.sleep(1.5)
    raise RuntimeError(f"Gateway did not become ready at {base_url}/readyz: {last_err}")


def _wait_for_primary_recovery(
    base_url: str,
    *,
    platform_jwt: str,
    http_transport: Any | None,
    timeout_seconds: float = 60.0,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    with _make_client(base_url, http_transport=http_transport, timeout_seconds=10.0) as client:
        while time.monotonic() < deadline:
            resp = client.post(
                "/v1/chat/completions",
                headers={"Authorization": f"Bearer {platform_jwt}"},
                json={
                    "model": "chat-default",
                    "max_tokens": 16,
                    "messages": [{"role": "user", "content": "Primary recovery probe"}],
                },
            )
            if resp.status_code == 200 and resp.headers.get("x-fallback-used") == "false":
                content = resp.json()["choices"][0]["message"]["content"]
                if "mock-llm-primary" in content:
                    return True
            time.sleep(3.0)
    raise RuntimeError(f"Primary Provider did not recover within {timeout_seconds}s")


def _sample_hpa_and_pods(
    *,
    namespace: str,
    kubectl_runner: KubectlRunner,
) -> dict[str, Any]:
    hpa_proc = kubectl_runner(
        ["get", "hpa", "ai-gateway-gateway-api", "-n", namespace, "-o", "json"]
    )
    pods_proc = kubectl_runner(
        [
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            "app.kubernetes.io/component=gateway-api",
            "-o",
            "json",
        ]
    )

    current_replicas = 1
    desired_replicas = 1
    cpu_util: int | None = None
    if hpa_proc.returncode == 0 and hpa_proc.stdout.strip():
        hpa_doc = json.loads(hpa_proc.stdout)
        status_doc = hpa_doc.get("status") or {}
        current_replicas = int(status_doc.get("currentReplicas") or 0)
        desired_replicas = int(status_doc.get("desiredReplicas") or 0)
        for metric in status_doc.get("currentMetrics") or []:
            if metric.get("type") == "Resource":
                res = metric.get("resource") or {}
                if res.get("name") == "cpu":
                    raw_util = (res.get("current") or {}).get("averageUtilization")
                    if isinstance(raw_util, int):
                        cpu_util = raw_util

    ready_pods = 0
    total_pods = 0
    if pods_proc.returncode == 0 and pods_proc.stdout.strip():
        pods_doc = json.loads(pods_proc.stdout)
        items = pods_doc.get("items") or []
        total_pods = len(items)
        for pod in items:
            if pod.get("metadata", {}).get("deletionTimestamp"):
                continue
            conditions = pod.get("status", {}).get("conditions") or []
            if any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions):
                ready_pods += 1

    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "current_replicas": current_replicas,
        "desired_replicas": desired_replicas,
        "ready_replicas": ready_pods,
        "total_pods": total_pods,
        "cpu_utilization_pct": cpu_util,
    }


def _collect_prometheus_snapshot(
    *,
    observability_namespace: str,
    port_forward_factory: PortForwardFactory,
    http_transport: Any | None,
) -> dict[str, Any]:
    try:
        with (
            port_forward_factory("svc/prometheus", 9090, observability_namespace) as local_port,
            _make_client(
                f"http://127.0.0.1:{local_port}",
                http_transport=http_transport,
                timeout_seconds=10.0,
            ) as prom,
        ):
            p50_resp = prom.get(
                "/api/v1/query",
                params={
                    "query": (
                        "histogram_quantile(0.50, sum by (le) "
                        '(rate(gateway_overhead_duration_seconds_bucket{route="/v1/chat/completions"}[5m])))'
                    )
                },
            )
            p95_resp = prom.get(
                "/api/v1/query",
                params={
                    "query": (
                        "histogram_quantile(0.95, sum by (le) "
                        '(rate(gateway_overhead_duration_seconds_bucket{route="/v1/chat/completions"}[5m])))'
                    )
                },
            )
            targets_resp = prom.get("/api/v1/targets")

            def _parse_scalar(resp: httpx.Response) -> float | None:
                if resp.status_code != 200:
                    return None
                results = (resp.json().get("data") or {}).get("result") or []
                if not results:
                    return None
                raw = results[0]["value"][1]
                val = float(raw)
                if val != val:  # NaN
                    return None
                return round(val * 1000.0, 3)

            up_targets = 0
            if targets_resp.status_code == 200:
                active = (targets_resp.json().get("data") or {}).get("activeTargets") or []
                up_targets = sum(
                    1
                    for t in active
                    if (t.get("labels") or {}).get("job") == "ai-gateway-control-plane"
                    and t.get("health") == "up"
                )

            return {
                "available": True,
                "p50_ms": _parse_scalar(p50_resp),
                "p95_ms": _parse_scalar(p95_resp),
                "gateway_targets_up": up_targets,
            }
    except Exception as exc:  # noqa: BLE001 - optional observability snapshot
        return {"available": False, "reason": str(exc)}


def _run_k6_phase(
    *,
    scenario: str,
    base_url: str,
    platform_jwt: str,
    ops_api_key: str,
    product_api_key: str,
    work_dir: Path,
    k6_runner: K6Runner,
    on_poll: Callable[[], None] | None = None,
) -> dict[str, Any]:
    summary_file = work_dir / f"k6-{scenario}.json"
    env = {
        "BASE_URL": base_url.rstrip("/"),
        "SCENARIO": scenario,
        "PLATFORM_CREDENTIAL": platform_jwt,
        "OPS_CREDENTIAL": ops_api_key,
        "PRODUCT_CREDENTIAL": product_api_key,
    }
    proc = k6_runner(
        scenario=scenario,
        summary_export_path=summary_file,
        env=env,
        on_poll=on_poll,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"k6 scenario '{scenario}' failed (rc={proc.returncode}):\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    if not summary_file.is_file():
        raise RuntimeError(f"k6 scenario '{scenario}' did not write {summary_file}")
    return json.loads(summary_file.read_text(encoding="utf-8"))


def _helm_upgrade(
    *,
    helm_runner: HelmRunner,
    release_name: str,
    chart_dir: Path,
    namespace: str,
    extra_args: list[str],
) -> None:
    cmd = [
        "upgrade",
        release_name,
        str(chart_dir),
        "--namespace",
        namespace,
        "--reuse-values",
        *extra_args,
    ]
    proc = helm_runner(cmd)
    if proc.returncode != 0:
        raise RuntimeError(
            f"helm {' '.join(cmd)} failed (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
        )


def _wait_for_rollout(
    *,
    kubectl_runner: KubectlRunner,
    namespace: str,
    deployment: str,
) -> None:
    proc = kubectl_runner(
        ["rollout", "status", f"deployment/{deployment}", "-n", namespace, "--timeout=120s"]
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"kubectl rollout status deployment/{deployment} failed: {proc.stdout}\n{proc.stderr}"
        )


def _read_team_budget_micros(
    *,
    namespace: str,
    team: str,
    kubectl_runner: KubectlRunner,
    release_name: str = DEFAULT_RELEASE_NAME,
) -> int:
    utc_date = datetime.now(UTC).strftime("%Y-%m-%d")
    proc = kubectl_runner(
        [
            "exec",
            "-n",
            namespace,
            f"deploy/{release_name}-redis",
            "--",
            "redis-cli",
            "GET",
            f"budget:{team}:{utc_date}",
        ]
    )
    if proc.returncode != 0:
        return 0
    raw = proc.stdout.strip()
    if not raw or raw == "(nil)":
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _detect_k6_version() -> str:
    k6_bin = shutil.which("k6")
    if k6_bin is not None:
        proc = subprocess.run([k6_bin, "version"], capture_output=True, text=True, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip().splitlines()[0]
    return "grafana/k6:latest"


def run_benchmarks(
    *,
    base_url: str = DEFAULT_BASE_URL,
    credentials_path: Path = DEFAULT_CREDENTIALS_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    namespace: str = DEFAULT_NAMESPACE,
    observability_namespace: str = DEFAULT_OBSERVABILITY_NAMESPACE,
    policy_bundle_path: Path = DEFAULT_POLICY_BUNDLE_PATH,
    chart_dir: Path = DEFAULT_CHART_DIR,
    release_name: str = DEFAULT_RELEASE_NAME,
    avoid_minute_rollover: bool = True,
    http_transport: Any | None = None,
    port_forward_factory: PortForwardFactory = _default_port_forward,
    kubectl_runner: KubectlRunner = _default_kubectl_runner,
    helm_runner: HelmRunner = _default_helm_runner,
    k6_runner: K6Runner = _default_k6_runner,
) -> dict[str, Any]:
    """Execute all 5 k6 load benchmark scenarios against the live cluster and write JSON."""
    bundle = _load_credentials(credentials_path)
    platform_jwt = _fresh_rs256_jwt(bundle, "platform-eng")
    ops_api_key = str(bundle["teams"]["ops-eng"]["api_key"])
    product_api_key = str(bundle["teams"]["product-eng"]["api_key"])

    canonical_policy = yaml.safe_load(policy_bundle_path.read_text(encoding="utf-8"))
    product_rpm_limit = int(canonical_policy["teams"]["product-eng"]["requests_per_minute"])

    _wait_for_gateway_ready(base_url, http_transport=http_transport, timeout_seconds=45.0)

    with tempfile.TemporaryDirectory(prefix="ai-gateway-bench-") as tmp_dir_str:
        work_dir = Path(tmp_dir_str)

        # Phase 1: Normal JSON traffic + exact Control Plane overhead delta
        print("[1/5] Running normal_json benchmark...")
        before_json_metrics = _scrape_gateway_metrics(
            namespace=namespace,
            port_forward_factory=port_forward_factory,
            http_transport=http_transport,
        )
        json_summary = _run_k6_phase(
            scenario="normal_json",
            base_url=base_url,
            platform_jwt=platform_jwt,
            ops_api_key=ops_api_key,
            product_api_key=product_api_key,
            work_dir=work_dir,
            k6_runner=k6_runner,
        )
        after_json_metrics = _scrape_gateway_metrics(
            namespace=namespace,
            port_forward_factory=port_forward_factory,
            http_transport=http_transport,
        )
        json_overhead = compute_overhead_delta_summary(before_json_metrics, after_json_metrics)

        # Phase 2: SSE streaming traffic + exact Control Plane overhead delta
        print("[2/5] Running sse_stream benchmark...")
        before_sse_metrics = _scrape_gateway_metrics(
            namespace=namespace,
            port_forward_factory=port_forward_factory,
            http_transport=http_transport,
        )
        sse_summary = _run_k6_phase(
            scenario="sse_stream",
            base_url=base_url,
            platform_jwt=platform_jwt,
            ops_api_key=ops_api_key,
            product_api_key=product_api_key,
            work_dir=work_dir,
            k6_runner=k6_runner,
        )
        after_sse_metrics = _scrape_gateway_metrics(
            namespace=namespace,
            port_forward_factory=port_forward_factory,
            http_transport=http_transport,
        )
        sse_overhead = compute_overhead_delta_summary(before_sse_metrics, after_sse_metrics)
        combined_overhead = merge_overhead_deltas([json_overhead, sse_overhead])

        # Phase 3: Fault-injected primary-to-fallback failover
        print("[3/5] Running failover benchmark via /admin/fault...")
        with (
            port_forward_factory("svc/mock-llm-primary", 8000, namespace) as admin_port,
            _make_client(
                f"http://127.0.0.1:{admin_port}",
                http_transport=http_transport,
                timeout_seconds=10.0,
            ) as admin_client,
        ):
            fault_on = admin_client.post("/admin/fault", json={"enabled": True, "mode": "fail_503"})
            if fault_on.status_code != 200:
                raise RuntimeError(f"Failed enabling /admin/fault: {fault_on.status_code}")
            try:
                failover_summary = _run_k6_phase(
                    scenario="failover",
                    base_url=base_url,
                    platform_jwt=platform_jwt,
                    ops_api_key=ops_api_key,
                    product_api_key=product_api_key,
                    work_dir=work_dir,
                    k6_runner=k6_runner,
                )
            finally:
                fault_off = admin_client.post("/admin/fault", json={"enabled": False})
                if fault_off.status_code != 200:
                    raise RuntimeError(f"Failed disabling /admin/fault: {fault_off.status_code}")
        primary_recovered = _wait_for_primary_recovery(
            base_url,
            platform_jwt=platform_jwt,
            http_transport=http_transport,
            timeout_seconds=60.0,
        )

        # Phase 4: Team Budget Quota / RPM 429 exhaustion (fresh UTC minute for product-eng)
        if avoid_minute_rollover:
            now = datetime.now(UTC)
            sleep_secs = 60 - now.second + 1.0
            print(
                f"[4/5] Waiting {sleep_secs:.1f}s for fresh UTC minute before quota_exhaustion..."
            )
            time.sleep(sleep_secs)
        else:
            print("[4/5] Running quota_exhaustion benchmark...")

        quota_summary = _run_k6_phase(
            scenario="quota_exhaustion",
            base_url=base_url,
            platform_jwt=platform_jwt,
            ops_api_key=ops_api_key,
            product_api_key=product_api_key,
            work_dir=work_dir,
            k6_runner=k6_runner,
        )

        # Phase 5: Budget Quota 429 + HPA sustained scale-out under temporary policy override
        print(
            "[5/5] Applying temporary benchmark Policy Bundle override for "
            "budget_quota_exhaustion & hpa_sustained..."
        )
        budget_window_usd = 0.005
        ops_spend_before_micros = _read_team_budget_micros(
            namespace=namespace,
            team="ops-eng",
            kubectl_runner=kubectl_runner,
            release_name=release_name,
        )
        ops_budget_limit_usd = round((ops_spend_before_micros / 1_000_000) + budget_window_usd, 6)
        override_yaml = build_hpa_benchmark_policy_override(
            policy_bundle_path,
            ops_rpm=600,
            ops_daily_budget_usd=ops_budget_limit_usd,
            ops_allow_chat_premium=True,
        )
        override_path = work_dir / "policy-bundle-hpa-bench.yaml"
        override_path.write_text(override_yaml, encoding="utf-8")

        hpa_samples: list[dict[str, Any]] = []
        policy_restored = False
        prometheus_snapshot: dict[str, Any] = {"available": False}

        def _poll_hpa() -> None:
            sample = _sample_hpa_and_pods(namespace=namespace, kubectl_runner=kubectl_runner)
            hpa_samples.append(sample)

        _helm_upgrade(
            helm_runner=helm_runner,
            release_name=release_name,
            chart_dir=chart_dir,
            namespace=namespace,
            extra_args=["--set-file", f"configMaps.policyBundleOverride={override_path}"],
        )
        try:
            _wait_for_rollout(
                kubectl_runner=kubectl_runner,
                namespace=namespace,
                deployment=f"{release_name}-gateway-api",
            )
            _wait_for_rollout(
                kubectl_runner=kubectl_runner,
                namespace=namespace,
                deployment=f"{release_name}-mcp-runtime",
            )
            _wait_for_gateway_ready(base_url, http_transport=http_transport, timeout_seconds=60.0)

            print("[4b/5] Running budget_quota_exhaustion benchmark (ops-eng daily_budget_usd)...")
            before_budget_metrics = _scrape_gateway_metrics(
                namespace=namespace,
                port_forward_factory=port_forward_factory,
                http_transport=http_transport,
            )
            budget_summary = _run_k6_phase(
                scenario="budget_quota_exhaustion",
                base_url=base_url,
                platform_jwt=platform_jwt,
                ops_api_key=ops_api_key,
                product_api_key=product_api_key,
                work_dir=work_dir,
                k6_runner=k6_runner,
            )
            after_budget_metrics = _scrape_gateway_metrics(
                namespace=namespace,
                port_forward_factory=port_forward_factory,
                http_transport=http_transport,
            )
            ops_spend_after_micros = _read_team_budget_micros(
                namespace=namespace,
                team="ops-eng",
                kubectl_runner=kubectl_runner,
                release_name=release_name,
            )

            _poll_hpa()

            hpa_summary = _run_k6_phase(
                scenario="hpa_sustained",
                base_url=base_url,
                platform_jwt=platform_jwt,
                ops_api_key=ops_api_key,
                product_api_key=product_api_key,
                work_dir=work_dir,
                k6_runner=k6_runner,
                on_poll=_poll_hpa,
            )

            # Give newly created replicas up to 20s to report Ready if desiredReplicas >= 2
            if hpa_samples and hpa_samples[-1]["desired_replicas"] >= 2:
                extra_deadline = time.monotonic() + 20.0
                while (
                    max(s["ready_replicas"] for s in hpa_samples) < 2
                    and time.monotonic() < extra_deadline
                ):
                    time.sleep(2.5)
                    _poll_hpa()

            prometheus_snapshot = _collect_prometheus_snapshot(
                observability_namespace=observability_namespace,
                port_forward_factory=port_forward_factory,
                http_transport=http_transport,
            )
        finally:
            print("Restoring canonical Policy Bundle via Helm...")
            _helm_upgrade(
                helm_runner=helm_runner,
                release_name=release_name,
                chart_dir=chart_dir,
                namespace=namespace,
                extra_args=["--set", "configMaps.policyBundleOverride="],
            )
            _wait_for_rollout(
                kubectl_runner=kubectl_runner,
                namespace=namespace,
                deployment=f"{release_name}-gateway-api",
            )
            _wait_for_rollout(
                kubectl_runner=kubectl_runner,
                namespace=namespace,
                deployment=f"{release_name}-mcp-runtime",
            )
            policy_restored = True

    allowed_200 = _extract_counter_count(quota_summary, "quota_allowed_200_total")
    blocked_429 = _extract_counter_count(quota_summary, "quota_blocked_429_total")
    quota_total_reqs = _extract_counter_count(quota_summary, "http_reqs") or (
        allowed_200 + blocked_429
    )
    quota_rate_info = _extract_rate_stats(quota_summary, "quota_429_rate")
    headers_valid_info = _extract_rate_stats(quota_summary, "quota_429_headers_valid_rate")
    expected_blocked = max(0, quota_total_reqs - product_rpm_limit)
    over_limit_leaks = max(0, allowed_200 - product_rpm_limit)
    block_accuracy = round(
        max(0.0, 1.0 - (over_limit_leaks / max(1, expected_blocked)))
        if blocked_429 > 0 and headers_valid_info["value"] == 1.0
        else 0.0,
        6,
    )

    budget_allowed_200 = _extract_counter_count(budget_summary, "budget_allowed_200_total")
    budget_blocked_429 = _extract_counter_count(budget_summary, "budget_blocked_429_total")
    budget_total_reqs = _extract_counter_count(budget_summary, "http_reqs") or (
        budget_allowed_200 + budget_blocked_429
    )
    budget_rate_info = _extract_rate_stats(budget_summary, "budget_429_rate")
    budget_headers_valid_info = _extract_rate_stats(budget_summary, "budget_429_headers_valid_rate")
    spend_before_usd = round(ops_spend_before_micros / 1_000_000, 6)
    spend_after_usd = round(ops_spend_after_micros / 1_000_000, 6)
    over_budget_leaks_usd = round(max(0.0, spend_after_usd - ops_budget_limit_usd), 6)
    budget_denials_metric_delta = round(
        max(
            0.0,
            parse_policy_denials_sample(
                after_budget_metrics, team="ops-eng", reason="budget_quota_exceeded"
            )
            - parse_policy_denials_sample(
                before_budget_metrics, team="ops-eng", reason="budget_quota_exceeded"
            ),
        ),
        3,
    )
    budget_block_accuracy = (
        1.0
        if budget_allowed_200 > 0
        and budget_blocked_429 > 0
        and over_budget_leaks_usd == 0.0
        and budget_headers_valid_info["value"] == 1.0
        else 0.0
    )

    observed_replicas = [max(s["current_replicas"], s["ready_replicas"]) for s in hpa_samples] or [
        1
    ]
    observed_ready = [s["ready_replicas"] for s in hpa_samples] or [1]
    cpu_samples = [
        s["cpu_utilization_pct"] for s in hpa_samples if s["cpu_utilization_pct"] is not None
    ]

    result: dict[str, Any] = {
        "schema_version": "v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "base_url": base_url.rstrip("/"),
        "k6_version": _detect_k6_version(),
        "cluster_context": {
            "namespace": namespace,
            "observability_namespace": observability_namespace,
            "gateway_cpu_request": "100m",
            "hpa_target_cpu_utilization_pct": 50,
            "hpa_min_replicas": 1,
            "hpa_max_replicas": 4,
        },
        "control_plane_overhead_ms": {
            "source": "gateway_overhead_duration_seconds_bucket delta (normal_json + sse_stream)",
            **combined_overhead,
            "prometheus_promql": prometheus_snapshot,
        },
        "scenarios": {
            "normal_json": {
                "requests": _extract_counter_count(json_summary, "http_reqs"),
                "success_rate": _extract_rate_stats(json_summary, "json_success_rate")["value"],
                "throughput_rps": round(
                    float(_metric_values(json_summary, "http_reqs").get("rate", 0.0)), 3
                ),
                "latency_ms": _extract_trend_stats(json_summary, "json_latency_ms"),
                "overhead_ms": {k: v for k, v in json_overhead.items() if not k.startswith("_")},
            },
            "sse_stream": {
                "requests": _extract_counter_count(sse_summary, "http_reqs"),
                "success_rate": _extract_rate_stats(sse_summary, "sse_success_rate")["value"],
                "throughput_rps": round(
                    float(_metric_values(sse_summary, "http_reqs").get("rate", 0.0)), 3
                ),
                "latency_ms": _extract_trend_stats(sse_summary, "sse_latency_ms"),
                "overhead_ms": {k: v for k, v in sse_overhead.items() if not k.startswith("_")},
            },
            "failover": {
                "requests": _extract_counter_count(failover_summary, "http_reqs"),
                "success_rate": _extract_rate_stats(failover_summary, "failover_success_rate")[
                    "value"
                ],
                "throughput_rps": round(
                    float(_metric_values(failover_summary, "http_reqs").get("rate", 0.0)), 3
                ),
                "latency_ms": _extract_trend_stats(failover_summary, "failover_latency_ms"),
                "primary_recovered": primary_recovered,
            },
            "quota_exhaustion": {
                "requests": quota_total_reqs,
                "team": "product-eng",
                "rpm_limit": product_rpm_limit,
                "denial_reason": "rpm_limit_exceeded",
                "allowed_200": allowed_200,
                "blocked_429": blocked_429,
                "over_limit_leaks": over_limit_leaks,
                "quota_429_rate": quota_rate_info["value"],
                "headers_valid_rate": headers_valid_info["value"],
                "block_accuracy": block_accuracy,
                "budget_quota_exceeded": {
                    "requests": budget_total_reqs,
                    "team": "ops-eng",
                    "model_alias": "chat-premium",
                    "denial_reason": "budget_quota_exceeded",
                    "budget_window_usd": budget_window_usd,
                    "daily_budget_limit_usd": ops_budget_limit_usd,
                    "spend_before_usd": spend_before_usd,
                    "spend_after_usd": spend_after_usd,
                    "over_budget_leaks_usd": over_budget_leaks_usd,
                    "allowed_200": budget_allowed_200,
                    "blocked_429": budget_blocked_429,
                    "budget_429_rate": budget_rate_info["value"],
                    "headers_valid_rate": budget_headers_valid_info["value"],
                    "block_accuracy": budget_block_accuracy,
                    "policy_denials_metric_delta": budget_denials_metric_delta,
                },
            },
            "hpa_sustained": {
                "requests": _extract_counter_count(hpa_summary, "http_reqs"),
                "success_rate": _extract_rate_stats(hpa_summary, "hpa_success_rate")["value"],
                "throughput_rps": round(
                    float(_metric_values(hpa_summary, "http_reqs").get("rate", 0.0)), 3
                ),
                "latency_ms": _extract_trend_stats(hpa_summary, "hpa_latency_ms"),
                "observed_min_replicas": min(observed_replicas),
                "observed_max_replicas": max(observed_replicas),
                "observed_max_ready_replicas": max(observed_ready),
                "peak_cpu_utilization_pct": max(cpu_samples) if cpu_samples else None,
                "policy_restored": policy_restored,
                "samples": hpa_samples,
            },
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run reproducible k6 load benchmarks against live Kind AI Enablement Gateway."
    )
    parser.add_argument("--base-url", default=os.getenv("BENCH_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument(
        "--credentials",
        type=Path,
        default=Path(os.getenv("BENCH_CREDENTIALS_PATH", str(DEFAULT_CREDENTIALS_PATH))),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(os.getenv("BENCH_OUTPUT_PATH", str(DEFAULT_OUTPUT_PATH))),
    )
    parser.add_argument("--namespace", default=os.getenv("BENCH_NAMESPACE", DEFAULT_NAMESPACE))
    parser.add_argument(
        "--observability-namespace",
        default=os.getenv("BENCH_OBSERVABILITY_NAMESPACE", DEFAULT_OBSERVABILITY_NAMESPACE),
    )
    parser.add_argument(
        "--no-minute-wait",
        action="store_true",
        help="Skip waiting for a fresh UTC minute before quota_exhaustion.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for running the live k6 benchmark suite."""
    args = _parse_args(argv)
    summary = run_benchmarks(
        base_url=args.base_url,
        credentials_path=args.credentials,
        output_path=args.output,
        namespace=args.namespace,
        observability_namespace=args.observability_namespace,
        avoid_minute_rollover=not args.no_minute_wait,
    )
    print(f"Benchmark summary written to {args.output}")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
