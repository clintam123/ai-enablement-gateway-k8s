"""Tests for k6 load benchmarks, benchmark runner, interactive demo script, and docs."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from scripts.generate_test_keys import write_local_credential_bundle

REPO_ROOT = Path(__file__).resolve().parent.parent
K6_SCRIPT_PATH = REPO_ROOT / "benchmarks" / "k6" / "gateway_benchmark.js"
MAKEFILE_PATH = REPO_ROOT / "Makefile"
POLICY_BUNDLE_PATH = REPO_ROOT / "policies" / "policy-bundle.yaml"


def test_k6_benchmark_script_scenarios_and_makefile_target() -> None:
    assert K6_SCRIPT_PATH.is_file(), f"Missing {K6_SCRIPT_PATH}"
    js_text = K6_SCRIPT_PATH.read_text(encoding="utf-8")

    for required_import in ("k6/http", "k6/metrics", "from 'k6'"):
        assert required_import in js_text
    for metric_type in ("Trend", "Rate", "Counter"):
        assert metric_type in js_text
    for metric_name in (
        "json_latency_ms",
        "json_success_rate",
        "sse_latency_ms",
        "sse_success_rate",
        "failover_success_rate",
        "quota_429_rate",
    ):
        assert metric_name in js_text
    for scenario in (
        "normal_json",
        "sse_stream",
        "failover",
        "quota_exhaustion",
        "hpa_sustained",
    ):
        assert scenario in js_text
    for header_or_marker in (
        "[DONE]",
        '"usage"',
        "x-fallback-used",
        "mock-llm-fallback",
        "retry-after",
        "x-ratelimit-limit-requests",
        "x-ratelimit-remaining-requests",
        "x-budget-limit-usd",
        "x-policy-denial-reason",
    ):
        assert header_or_marker.lower() in js_text.lower()

    k6_bin = shutil.which("k6")
    assert k6_bin is not None, "k6 binary must be installed to inspect benchmark script"
    for scenario in (
        "normal_json",
        "sse_stream",
        "failover",
        "quota_exhaustion",
        "hpa_sustained",
        "all",
    ):
        proc = subprocess.run(
            [k6_bin, "inspect", "-e", f"SCENARIO={scenario}", str(K6_SCRIPT_PATH)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, (
            f"k6 inspect failed for SCENARIO={scenario}:\n{proc.stdout}\n{proc.stderr}"
        )

    makefile_text = MAKEFILE_PATH.read_text(encoding="utf-8")
    assert "bench:" in makefile_text
    assert "scripts/run_benchmarks.py" in makefile_text


def test_overhead_histogram_delta_quantile_calculation() -> None:
    from scripts.run_benchmarks import compute_overhead_delta_summary

    route = 'route="/v1/chat/completions"'
    before_metrics = "\n".join(
        [
            f'gateway_overhead_duration_seconds_bucket{{{route},le="0.001"}} 2.0',
            f'gateway_overhead_duration_seconds_bucket{{{route},le="0.0025"}} 4.0',
            f'gateway_overhead_duration_seconds_bucket{{{route},le="0.005"}} 4.0',
            f'gateway_overhead_duration_seconds_bucket{{{route},le="0.01"}} 4.0',
            f'gateway_overhead_duration_seconds_bucket{{{route},le="+Inf"}} 4.0',
            f"gateway_overhead_duration_seconds_sum{{{route}}} 0.008",
            f"gateway_overhead_duration_seconds_count{{{route}}} 4.0",
        ]
    )
    after_metrics = "\n".join(
        [
            f'gateway_overhead_duration_seconds_bucket{{{route},le="0.001"}} 2.0',
            f'gateway_overhead_duration_seconds_bucket{{{route},le="0.0025"}} 4.0',
            f'gateway_overhead_duration_seconds_bucket{{{route},le="0.005"}} 54.0',
            f'gateway_overhead_duration_seconds_bucket{{{route},le="0.01"}} 104.0',
            f'gateway_overhead_duration_seconds_bucket{{{route},le="+Inf"}} 104.0',
            f"gateway_overhead_duration_seconds_sum{{{route}}} 0.608",
            f"gateway_overhead_duration_seconds_count{{{route}}} 104.0",
        ]
    )
    summary = compute_overhead_delta_summary(before_metrics, after_metrics)
    assert summary["sample_count"] == 100
    assert summary["p50_ms"] == pytest.approx(5.0, rel=1e-3)
    assert summary["p95_ms"] == pytest.approx(9.5, rel=1e-3)
    assert summary["mean_ms"] == pytest.approx(6.0, rel=1e-3)


def test_hpa_benchmark_policy_override_preserves_product_eng_limits() -> None:
    from scripts.run_benchmarks import build_hpa_benchmark_policy_override

    canonical = yaml.safe_load(POLICY_BUNDLE_PATH.read_text(encoding="utf-8"))
    override_yaml = build_hpa_benchmark_policy_override(POLICY_BUNDLE_PATH)
    overridden = yaml.safe_load(override_yaml)

    assert overridden["teams"]["platform-eng"]["requests_per_minute"] >= 50000
    assert overridden["teams"]["platform-eng"]["daily_budget_usd"] >= 5000.0
    assert overridden["teams"]["product-eng"] == canonical["teams"]["product-eng"]
    assert overridden["teams"]["ops-eng"] == canonical["teams"]["ops-eng"]
    assert overridden["safety_rules"] == canonical["safety_rules"]


def test_run_benchmarks_orchestration_restores_fault_and_policy_override_on_failure(
    tmp_path: Path,
) -> None:
    from scripts.run_benchmarks import run_benchmarks

    bundle_info = write_local_credential_bundle(tmp_path / ".local")
    creds_path = Path(bundle_info["credentials_path"])
    output_path = tmp_path / "latest-summary.json"

    fault_calls: list[dict[str, Any]] = []
    helm_calls: list[list[str]] = []
    k6_scenarios_seen: list[str] = []
    metrics_scrapes = 0

    def gateway_and_obs_handler(request: httpx.Request) -> httpx.Response:
        nonlocal metrics_scrapes
        if request.url.path == "/admin/fault":
            payload = json.loads(request.content.decode("utf-8"))
            fault_calls.append(payload)
            return httpx.Response(200, json={"enabled": payload["enabled"]})
        if request.url.path == "/v1/chat/completions":
            return httpx.Response(
                200,
                headers={"x-fallback-used": "false"},
                json={
                    "choices": [{"message": {"content": "[mock-llm-primary:chat-default] ok"}}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                },
            )
        if request.url.path == "/readyz":
            return httpx.Response(200, json={"status": "ready", "policy_version": "v1+override"})
        if request.url.path == "/metrics":
            metrics_scrapes += 1
            count = 0 if metrics_scrapes in (1, 3) else 40
            val = count * 0.004
            route = 'route="/v1/chat/completions"'
            text = "\n".join(
                [
                    f'gateway_overhead_duration_seconds_bucket{{{route},le="0.0025"}} {count // 2}',
                    f'gateway_overhead_duration_seconds_bucket{{{route},le="0.005"}} {count}',
                    f'gateway_overhead_duration_seconds_bucket{{{route},le="+Inf"}} {count}',
                    f"gateway_overhead_duration_seconds_sum{{{route}}} {val}",
                    f"gateway_overhead_duration_seconds_count{{{route}}} {count}",
                ]
            )
            return httpx.Response(200, text=text)
        if request.url.path == "/api/v1/query":
            return httpx.Response(
                200,
                json={"status": "success", "data": {"result": [{"value": [1700000000, "0.0042"]}]}},
            )
        if request.url.path == "/api/v1/targets":
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "activeTargets": [
                            {"labels": {"job": "ai-gateway-control-plane"}, "health": "up"}
                        ]
                    },
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(gateway_and_obs_handler)

    @contextmanager
    def fake_port_forward(service_name: str, remote_port: int, namespace: str):
        port_map = {
            ("svc/mock-llm-primary", 8000): 18001,
            ("svc/ai-gateway-gateway-api", 8000): 18002,
            ("svc/prometheus", 9090): 19090,
        }
        yield port_map[(service_name, remote_port)]

    def fake_kubectl(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["get", "hpa"]:
            return subprocess.CompletedProcess(
                ["kubectl", *args],
                0,
                stdout=json.dumps(
                    {
                        "status": {
                            "currentReplicas": 2,
                            "desiredReplicas": 2,
                            "currentMetrics": [
                                {
                                    "type": "Resource",
                                    "resource": {
                                        "name": "cpu",
                                        "current": {"averageUtilization": 82},
                                    },
                                }
                            ],
                        }
                    }
                ),
                stderr="",
            )
        if args[:2] == ["get", "pods"]:
            return subprocess.CompletedProcess(
                ["kubectl", *args],
                0,
                stdout=json.dumps(
                    {
                        "items": [
                            {"status": {"conditions": [{"type": "Ready", "status": "True"}]}},
                            {"status": {"conditions": [{"type": "Ready", "status": "True"}]}},
                        ]
                    }
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(["kubectl", *args], 0, stdout="", stderr="")

    def fake_helm(args: list[str]) -> subprocess.CompletedProcess[str]:
        helm_calls.append(args)
        return subprocess.CompletedProcess(["helm", *args], 0, stdout="ok", stderr="")

    def fake_k6(
        *,
        scenario: str,
        summary_export_path: Path,
        env: dict[str, str],
        on_poll: Any,
    ) -> subprocess.CompletedProcess[str]:
        k6_scenarios_seen.append(scenario)
        assert env["SCENARIO"] == scenario
        if on_poll is not None:
            on_poll()
        payloads = {
            "normal_json": {
                "metrics": {
                    "json_latency_ms": {
                        "min": 10.0,
                        "avg": 18.0,
                        "med": 17.0,
                        "p(90)": 24.0,
                        "p(95)": 28.0,
                        "max": 35.0,
                    },
                    "json_success_rate": {"value": 1.0, "passes": 60, "fails": 0},
                    "http_reqs": {"count": 60, "rate": 5.0},
                }
            },
            "sse_stream": {
                "metrics": {
                    "sse_latency_ms": {
                        "min": 12.0,
                        "avg": 20.0,
                        "med": 19.0,
                        "p(90)": 26.0,
                        "p(95)": 30.0,
                        "max": 38.0,
                    },
                    "sse_success_rate": {"value": 1.0, "passes": 30, "fails": 0},
                    "http_reqs": {"count": 30, "rate": 3.0},
                }
            },
            "failover": {
                "metrics": {
                    "failover_latency_ms": {
                        "min": 15.0,
                        "avg": 25.0,
                        "med": 24.0,
                        "p(90)": 35.0,
                        "p(95)": 40.0,
                        "max": 50.0,
                    },
                    "failover_success_rate": {"value": 1.0, "passes": 20, "fails": 0},
                    "http_reqs": {"count": 20, "rate": 4.0},
                }
            },
            "quota_exhaustion": {
                "metrics": {
                    "quota_429_rate": {"value": 30 / 90, "passes": 30, "fails": 60},
                    "quota_429_headers_valid_rate": {"value": 1.0, "passes": 30, "fails": 0},
                    "quota_allowed_200_total": {"count": 60},
                    "quota_blocked_429_total": {"count": 30},
                    "http_reqs": {"count": 90, "rate": 45.0},
                }
            },
            "hpa_sustained": {
                "metrics": {
                    "hpa_latency_ms": {
                        "min": 12.0,
                        "avg": 30.0,
                        "med": 26.0,
                        "p(90)": 55.0,
                        "p(95)": 70.0,
                        "max": 120.0,
                    },
                    "hpa_success_rate": {"value": 1.0, "passes": 500, "fails": 0},
                    "http_reqs": {"count": 500, "rate": 25.0},
                }
            },
        }
        summary_export_path.write_text(json.dumps(payloads[scenario]), encoding="utf-8")
        return subprocess.CompletedProcess(["k6"], 0, stdout="k6 v2.4.0", stderr="")

    summary = run_benchmarks(
        base_url="http://localhost:8080",
        credentials_path=creds_path,
        output_path=output_path,
        avoid_minute_rollover=False,
        http_transport=transport,
        port_forward_factory=fake_port_forward,
        kubectl_runner=fake_kubectl,
        helm_runner=fake_helm,
        k6_runner=fake_k6,
    )

    assert k6_scenarios_seen == [
        "normal_json",
        "sse_stream",
        "failover",
        "quota_exhaustion",
        "hpa_sustained",
    ]
    assert fault_calls == [
        {"enabled": True, "mode": "fail_503"},
        {"enabled": False},
    ]
    assert len(helm_calls) == 2
    assert any(arg.startswith("configMaps.policyBundleOverride=") for arg in helm_calls[0])
    assert "configMaps.policyBundleOverride=" in helm_calls[1]
    assert summary["scenarios"]["hpa_sustained"]["observed_max_replicas"] == 2
    assert summary["scenarios"]["hpa_sustained"]["observed_max_ready_replicas"] == 2
    assert summary["scenarios"]["quota_exhaustion"]["block_accuracy"] == 1.0
    assert output_path.is_file()

    # Now verify finally: restores canonical Policy Bundle even if hpa_sustained k6 fails
    helm_calls.clear()

    def failing_hpa_k6(
        *,
        scenario: str,
        summary_export_path: Path,
        env: dict[str, str],
        on_poll: Any,
    ) -> subprocess.CompletedProcess[str]:
        if scenario == "hpa_sustained":
            return subprocess.CompletedProcess(["k6"], 1, stdout="", stderr="simulated k6 failure")
        return fake_k6(
            scenario=scenario,
            summary_export_path=summary_export_path,
            env=env,
            on_poll=on_poll,
        )

    with pytest.raises(RuntimeError, match="hpa_sustained"):
        run_benchmarks(
            base_url="http://localhost:8080",
            credentials_path=creds_path,
            output_path=output_path,
            avoid_minute_rollover=False,
            http_transport=transport,
            port_forward_factory=fake_port_forward,
            kubectl_runner=fake_kubectl,
            helm_runner=fake_helm,
            k6_runner=failing_hpa_k6,
        )
    assert len(helm_calls) == 2
    assert "configMaps.policyBundleOverride=" in helm_calls[1]


def test_demo_script_is_executable_passes_bash_syntax_and_covers_walkthrough() -> None:
    demo_path = REPO_ROOT / "scripts" / "demo.sh"
    assert demo_path.is_file(), f"Missing {demo_path}"
    assert os.access(demo_path, os.X_OK), f"{demo_path} must be executable (chmod +x)"

    syntax_proc = subprocess.run(
        ["bash", "-n", str(demo_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert syntax_proc.returncode == 0, f"bash -n failed:\n{syntax_proc.stderr}"

    demo_text = demo_path.read_text(encoding="utf-8")
    for expected in (
        "set -euo pipefail",
        "--auto",
        "--base-url",
        "--credentials",
        "/healthz",
        "/readyz",
        "policy_version",
        "chat-premium",
        "prompt_denied",
        "stream",
        "/admin/fault",
        "x-fallback-used",
        "x-ratelimit-limit-requests",
        "/mcp",
        "lookup_service_slo",
        "check_model_catalog",
        "mcp_run_loop_cap_exceeded",
        "/metrics",
        "prometheus",
        "grafana",
        "jaeger",
    ):
        assert expected.lower() in demo_text.lower(), f"Missing {expected!r} in scripts/demo.sh"


def assert_glossary_compliance(doc_text: str, *, doc_name: str) -> None:
    # Strip fenced code blocks and inline code so literal K8s/PromQL/YAML identifiers
    # (e.g., GatewayHighUpstreamFailoverRate, prometheus upstream labels) are not misflagged.
    prose_only = re.sub(r"```[\s\S]*?```", " ", doc_text)
    prose_only = re.sub(r"`[^`\n]+`", " ", prose_only)
    forbidden_patterns = (
        r"\btenants?\b",
        r"\borgs?\b",
        r"\bauth tokens?\b",
        r"\bagent servers?\b",
        r"\btool prox(?:y|ies)\b",
        r"\baccess logs?\b",
        r"\btrace logs?\b",
        r"\bmodel servers?\b",
        r"\bconfig sets?\b",
        r"\brule files?\b",
        r"\bpermission groups?\b",
        r"\bvendors?\b",
    )
    for pattern in forbidden_patterns:
        match = re.search(pattern, prose_only, flags=re.IGNORECASE)
        assert match is None, (
            f"Forbidden GLOSSARY.md synonym {match.group(0)!r} found in {doc_name}"
        )


def test_runbook_covers_all_slo_alerts_triage_and_rollback() -> None:
    runbook_path = REPO_ROOT / "docs" / "runbook.md"
    assert runbook_path.is_file(), f"Missing {runbook_path}"
    text = runbook_path.read_text(encoding="utf-8")
    assert_glossary_compliance(text, doc_name="docs/runbook.md")

    for required in (
        "GatewayHighP95Overhead",
        "GatewayHigh5xxErrorRate",
        "GatewayHighUpstreamFailoverRate",
        "GatewayTeamBudgetQuotaExhaustion",
        "/admin/fault",
        "X-Fallback-Used",
        "helm rollback",
        "policyBundleOverride",
        "kubectl port-forward",
        "16686",
        "9090",
        "Control Plane",
        "Model Router",
        "Policy Bundle",
        "Budget Quota",
        "Provider",
    ):
        assert required in text, f"Missing {required!r} in docs/runbook.md"


def _load_latest_benchmark_summary() -> dict[str, Any]:
    summary_path = REPO_ROOT / "benchmarks" / "results" / "latest-summary.json"
    assert summary_path.is_file(), f"Missing {summary_path}"
    return json.loads(summary_path.read_text(encoding="utf-8"))


def test_latest_benchmark_summary_contains_real_measured_metrics_and_hpa_scale_out() -> None:
    summary = _load_latest_benchmark_summary()
    assert summary["schema_version"] == "v1"
    assert summary["base_url"] == "http://localhost:8080"

    overhead = summary["control_plane_overhead_ms"]
    assert overhead["sample_count"] > 0
    assert overhead["p50_ms"] > 0
    assert overhead["p95_ms"] >= overhead["p50_ms"]

    scenarios = summary["scenarios"]
    assert scenarios["normal_json"]["requests"] > 0
    assert scenarios["normal_json"]["latency_ms"]["p95"] > 0
    assert scenarios["sse_stream"]["requests"] > 0
    assert scenarios["sse_stream"]["latency_ms"]["p95"] > 0
    assert scenarios["failover"]["success_rate"] > 0
    assert scenarios["failover"]["primary_recovered"] is True
    assert scenarios["quota_exhaustion"]["blocked_429"] > 0
    assert scenarios["quota_exhaustion"]["block_accuracy"] == 1.0
    assert scenarios["hpa_sustained"]["observed_max_replicas"] >= 2
    assert scenarios["hpa_sustained"]["observed_max_ready_replicas"] >= 2
    assert scenarios["hpa_sustained"]["policy_restored"] is True


def test_benchmarks_doc_and_readme_match_latest_summary_verbatim_and_glossary() -> None:
    summary = _load_latest_benchmark_summary()
    overhead = summary["control_plane_overhead_ms"]
    scenarios = summary["scenarios"]

    expected_numbers = [
        f"{overhead['p50_ms']:.3f}",
        f"{overhead['p95_ms']:.3f}",
        f"{scenarios['normal_json']['latency_ms']['p50']:.3f}",
        f"{scenarios['normal_json']['latency_ms']['p95']:.3f}",
        f"{scenarios['sse_stream']['latency_ms']['p50']:.3f}",
        f"{scenarios['sse_stream']['latency_ms']['p95']:.3f}",
        f"{scenarios['failover']['latency_ms']['p95']:.3f}",
        f"{scenarios['quota_exhaustion']['allowed_200']}",
        f"{scenarios['quota_exhaustion']['blocked_429']}",
        f"{scenarios['hpa_sustained']['observed_max_replicas']}",
        f"{scenarios['hpa_sustained']['peak_cpu_utilization_pct']}%",
    ]

    benchmarks_doc = REPO_ROOT / "docs" / "benchmarks.md"
    assert benchmarks_doc.is_file(), f"Missing {benchmarks_doc}"
    bench_text = benchmarks_doc.read_text(encoding="utf-8")
    assert_glossary_compliance(bench_text, doc_name="docs/benchmarks.md")
    for token in expected_numbers:
        assert token in bench_text, f"docs/benchmarks.md missing measured value {token!r}"

    readme_path = REPO_ROOT / "README.md"
    assert readme_path.is_file(), f"Missing {readme_path}"
    readme_text = readme_path.read_text(encoding="utf-8")
    assert_glossary_compliance(readme_text, doc_name="README.md")
    assert "```mermaid" in readme_text
    for required_ref in (
        "make up",
        "make smoke",
        "make bench",
        "make gcp-up",
        "make gcp-down",
        "NetworkPolicy",
        "GLOSSARY.md",
        "docs/adr/",
        "docs/benchmarks.md",
        "docs/runbook.md",
        "docs/postmortem.md",
    ):
        assert required_ref in readme_text, f"README.md missing {required_ref!r}"
    for token in expected_numbers:
        assert token in readme_text, f"README.md missing measured value {token!r}"


def test_postmortem_covers_adrs_evolution_and_real_incidents() -> None:
    postmortem_path = REPO_ROOT / "docs" / "postmortem.md"
    assert postmortem_path.is_file(), f"Missing {postmortem_path}"
    text = postmortem_path.read_text(encoding="utf-8")
    assert_glossary_compliance(text, doc_name="docs/postmortem.md")

    for required in (
        "ADR-0001",
        "ADR-0002",
        "ADR-0003",
        "ADR-0004",
        "ADR-0005",
        "ADR-0006",
        "1.84.0",
        "1.039 GiB",
        "FastMCP",
        "421",
        "dns_sd_configs",
        "CVE-2026-124851",
        "libzstd1",
        "multi-region",
        "Control Plane",
        "Model Router",
        "MCP Runtime",
        "Policy Bundle",
    ):
        assert required in text, f"Missing {required!r} in docs/postmortem.md"
