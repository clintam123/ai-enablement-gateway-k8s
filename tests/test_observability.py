"""Contract tests for observability configs, Helm headless Service, and local Terraform."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from gateway_api.telemetry import ControlPlaneMetrics
from platform_common import AuditEvent

REPO_ROOT = Path(__file__).resolve().parent.parent
OBS_DIR = REPO_ROOT / "deploy" / "observability"
TF_LOCAL_DIR = REPO_ROOT / "terraform" / "local"
PROMETHEUS_CONFIG_PATH = OBS_DIR / "prometheus" / "prometheus.yml"
PROMETHEUS_RULES_PATH = OBS_DIR / "prometheus" / "slo-alerts.yml"
GRAFANA_DATASOURCES_PATH = OBS_DIR / "grafana" / "datasources.yaml"
GRAFANA_PROVIDER_PATH = OBS_DIR / "grafana" / "dashboards-provider.yaml"
GRAFANA_DASHBOARD_PATH = OBS_DIR / "grafana" / "dashboards" / "ai-gateway-overview.json"


def _observed_control_plane_metric_names() -> set[str]:
    """Emit representative observations from ControlPlaneMetrics and return exported names."""
    metrics = ControlPlaneMetrics()
    metrics.observe(
        AuditEvent(
            trace_id="a" * 32,
            request_id="req-ok",
            actor_id="dev-1",
            team="platform-eng",
            role="developer",
            requested_model="chat-default",
            routed_model="fallback-1",
            fallback_used=True,
            policy_version="v1+test",
            policy_action="allow",
            prompt_tokens=10,
            completion_tokens=20,
            estimated_cost_usd=0.001,
            latency_ms=100.0,
            status_code=200,
        ),
        route="/v1/chat/completions",
        stream=False,
        duration_seconds=0.1,
        upstream_duration_seconds=0.08,
        effective_model="chat-default",
    )
    metrics.observe(
        AuditEvent(
            trace_id="b" * 32,
            request_id="req-deny",
            actor_id="dev-1",
            team="platform-eng",
            role="developer",
            requested_model="chat-default",
            policy_version="v1+test",
            policy_action="deny",
            triggered_rules=["budget_quota_exceeded"],
            latency_ms=5.0,
            status_code=429,
        ),
        route="/v1/chat/completions",
        stream=False,
        duration_seconds=0.005,
        effective_model="chat-default",
        denial_reason="budget_quota_exceeded",
    )
    payload, _ = metrics.render_latest()
    names: set[str] = set()
    for line in payload.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        metric_token = line.split("{", 1)[0].split(" ", 1)[0]
        names.add(metric_token)
    return names


def test_prometheus_config_and_slo_alerts_match_control_plane_metrics() -> None:
    assert PROMETHEUS_CONFIG_PATH.is_file(), f"Missing {PROMETHEUS_CONFIG_PATH}"
    prom_cfg = yaml.safe_load(PROMETHEUS_CONFIG_PATH.read_text(encoding="utf-8"))
    assert "/etc/prometheus/rules/*.yml" in prom_cfg.get("rule_files", [])

    scrape_configs = prom_cfg.get("scrape_configs", [])
    gw_jobs = [
        job
        for job in scrape_configs
        if any(
            "ai-gateway-gateway-api-headless.ai-gateway.svc.cluster.local"
            in (sd.get("names") or [])
            for sd in job.get("dns_sd_configs") or []
        )
    ]
    assert len(gw_jobs) == 1
    gw_job = gw_jobs[0]
    assert gw_job.get("metrics_path", "/metrics") == "/metrics"
    dns_sd = gw_job["dns_sd_configs"][0]
    assert dns_sd["type"] == "A"
    assert dns_sd["port"] == 8000

    assert PROMETHEUS_RULES_PATH.is_file(), f"Missing {PROMETHEUS_RULES_PATH}"
    rules_doc = yaml.safe_load(PROMETHEUS_RULES_PATH.read_text(encoding="utf-8"))
    groups = rules_doc.get("groups", [])
    assert [g["name"] for g in groups] == ["ai-enablement-gateway-slo"]

    rules_by_name = {rule["alert"]: rule for rule in groups[0]["rules"]}
    expected_alerts = {
        "GatewayHighP95Overhead": "gateway_overhead_duration_seconds_bucket",
        "GatewayHigh5xxErrorRate": "gateway_requests_total",
        "GatewayHighUpstreamFailoverRate": "gateway_upstream_failovers_total",
        "GatewayTeamBudgetQuotaExhaustion": "gateway_policy_denials_total",
    }
    assert set(rules_by_name) == set(expected_alerts)

    exported_names = _observed_control_plane_metric_names()
    for alert_name, expected_metric in expected_alerts.items():
        rule = rules_by_name[alert_name]
        expr = rule["expr"]
        assert expected_metric in expr
        assert rule.get("for")
        assert rule.get("labels", {}).get("severity")
        assert rule.get("annotations", {}).get("summary")
        referenced_gateway_metrics = set(re.findall(r"\bgateway_[a-z0-9_]+\b", expr))
        assert referenced_gateway_metrics
        assert referenced_gateway_metrics.issubset(exported_names)

    assert 'status=~"5.."' in rules_by_name["GatewayHigh5xxErrorRate"]["expr"]
    assert "gateway_requests_total" in rules_by_name["GatewayHighUpstreamFailoverRate"]["expr"]
    assert (
        'reason="budget_quota_exceeded"'
        in rules_by_name["GatewayTeamBudgetQuotaExhaustion"]["expr"]
    )


def test_grafana_provisioning_and_overview_dashboard_contract() -> None:
    assert GRAFANA_DATASOURCES_PATH.is_file(), f"Missing {GRAFANA_DATASOURCES_PATH}"
    ds_doc = yaml.safe_load(GRAFANA_DATASOURCES_PATH.read_text(encoding="utf-8"))
    assert ds_doc["apiVersion"] == 1
    ds_by_uid = {ds["uid"]: ds for ds in ds_doc["datasources"]}
    assert set(ds_by_uid) == {"prometheus", "jaeger"}
    assert ds_by_uid["prometheus"]["type"] == "prometheus"
    assert ds_by_uid["prometheus"]["isDefault"] is True
    assert (
        ds_by_uid["prometheus"]["url"] == "http://prometheus.observability.svc.cluster.local:9090"
    )
    assert ds_by_uid["jaeger"]["type"] == "jaeger"
    assert ds_by_uid["jaeger"]["url"] == "http://jaeger.observability.svc.cluster.local:16686"

    assert GRAFANA_PROVIDER_PATH.is_file(), f"Missing {GRAFANA_PROVIDER_PATH}"
    provider_doc = yaml.safe_load(GRAFANA_PROVIDER_PATH.read_text(encoding="utf-8"))
    assert provider_doc["apiVersion"] == 1
    providers = provider_doc["providers"]
    assert len(providers) >= 1
    assert providers[0]["type"] == "file"
    assert providers[0]["options"]["path"] == "/var/lib/grafana/dashboards"

    assert GRAFANA_DASHBOARD_PATH.is_file(), f"Missing {GRAFANA_DASHBOARD_PATH}"
    dashboard = json.loads(GRAFANA_DASHBOARD_PATH.read_text(encoding="utf-8"))
    assert dashboard["uid"] == "ai-gateway-overview"
    assert dashboard["title"]
    panels = dashboard["panels"]
    assert len(panels) >= 6

    exported_names = _observed_control_plane_metric_names()
    all_exprs: list[str] = []
    occupied_cells: set[tuple[int, int]] = set()
    panel_ids: set[int] = set()

    for panel in panels:
        panel_id = panel["id"]
        assert panel_id not in panel_ids
        panel_ids.add(panel_id)
        assert panel["title"]
        assert panel["datasource"]["uid"] == "prometheus"

        gp = panel["gridPos"]
        assert gp["w"] > 0 and gp["h"] > 0
        assert gp["x"] >= 0 and gp["y"] >= 0 and gp["x"] + gp["w"] <= 24
        for cx in range(gp["x"], gp["x"] + gp["w"]):
            for cy in range(gp["y"], gp["y"] + gp["h"]):
                assert (cx, cy) not in occupied_cells, f"Overlapping panel gridPos at {(cx, cy)}"
                occupied_cells.add((cx, cy))

        targets = panel.get("targets") or []
        assert targets, f"Panel {panel['title']} has no targets"
        for target in targets:
            expr = target["expr"]
            all_exprs.append(expr)
            referenced = set(re.findall(r"\bgateway_[a-z0-9_]+\b", expr))
            assert referenced, f"Panel target expr missing gateway_* metric: {expr}"
            assert referenced.issubset(exported_names), (
                f"Unknown ControlPlaneMetrics metrics in dashboard: {referenced - exported_names}"
            )

    combined_expr = "\n".join(all_exprs)
    for required_metric in (
        "gateway_request_duration_seconds_bucket",
        "gateway_overhead_duration_seconds_bucket",
        "gateway_requests_total",
        "gateway_llm_tokens_total",
        "gateway_estimated_cost_usd_total",
        "gateway_upstream_failovers_total",
        "gateway_policy_denials_total",
    ):
        assert required_metric in combined_expr

    # Verify p50 & p95 latency queries exist for both request and overhead histograms
    req_latency_exprs = [e for e in all_exprs if "gateway_request_duration_seconds_bucket" in e]
    overhead_exprs = [e for e in all_exprs if "gateway_overhead_duration_seconds_bucket" in e]
    assert any("0.5" in e for e in req_latency_exprs)
    assert any("0.95" in e for e in req_latency_exprs)
    assert any("0.5" in e for e in overhead_exprs)
    assert any("0.95" in e for e in overhead_exprs)
    assert any(
        "budget_quota_exceeded" in e or "gateway_policy_denials_total" in e for e in all_exprs
    )


def _render_chart(*extra_args: str) -> list[dict[str, Any]]:
    helm_bin = shutil.which("helm")
    assert helm_bin is not None, "helm binary must be available in PATH"
    proc = subprocess.run(
        [
            helm_bin,
            "template",
            "ai-gateway",
            str(REPO_ROOT / "deploy" / "helm" / "ai-enablement-platform"),
            "--namespace",
            "ai-gateway",
            *extra_args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"helm template failed:\n{proc.stdout}\n{proc.stderr}"
    return [doc for doc in yaml.safe_load_all(proc.stdout) if isinstance(doc, dict)]


def _by_kind_and_name(docs: list[dict[str, Any]], kind: str) -> dict[str, dict[str, Any]]:
    return {
        doc["metadata"]["name"]: doc
        for doc in docs
        if doc.get("kind") == kind and isinstance(doc.get("metadata", {}).get("name"), str)
    }


def test_helm_renders_headless_service_and_toggles_otlp_and_network_policies() -> None:
    default_docs = _render_chart()
    services = _by_kind_and_name(default_docs, "Service")
    deployments = _by_kind_and_name(default_docs, "Deployment")
    netpols = _by_kind_and_name(default_docs, "NetworkPolicy")

    assert "ai-gateway-gateway-api" in services
    assert "ai-gateway-gateway-api-headless" in services

    headless = services["ai-gateway-gateway-api-headless"]
    assert headless["metadata"]["namespace"] == "ai-gateway"
    assert headless["spec"]["clusterIP"] == "None"
    assert headless["spec"]["ports"] == [
        {"name": "http", "port": 8000, "targetPort": "http", "protocol": "TCP"}
    ]
    gw_pod_labels = deployments["ai-gateway-gateway-api"]["spec"]["template"]["metadata"]["labels"]
    for key, val in headless["spec"]["selector"].items():
        assert gw_pod_labels.get(key) == val

    default_env = {
        e["name"]: e
        for e in deployments["ai-gateway-gateway-api"]["spec"]["template"]["spec"]["containers"][0][
            "env"
        ]
    }
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in default_env
    default_gw_egress_ports = {
        (p["protocol"], p["port"])
        for rule in netpols["ai-gateway-gateway-api"]["spec"]["egress"]
        for p in rule.get("ports") or []
    }
    assert ("TCP", 4317) not in default_gw_egress_ports
    assert ("TCP", 4318) not in default_gw_egress_ports

    # Observability enabled
    enabled_docs = _render_chart(
        "--set",
        "observability.otlpEndpoint=http://jaeger.observability.svc.cluster.local:4318",
        "--set",
        "observability.prometheusScrape=true",
        "--set",
        "networkPolicy.allowObservabilityScrape=true",
        "--set",
        "networkPolicy.allowOtlpEgress=true",
    )
    enabled_dep = _by_kind_and_name(enabled_docs, "Deployment")["ai-gateway-gateway-api"]
    enabled_env = {
        e["name"]: e for e in enabled_dep["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert (
        enabled_env["OTEL_EXPORTER_OTLP_ENDPOINT"]["value"]
        == "http://jaeger.observability.svc.cluster.local:4318"
    )
    enabled_np = _by_kind_and_name(enabled_docs, "NetworkPolicy")["ai-gateway-gateway-api"]
    otlp_egress_rules = [
        rule
        for rule in enabled_np["spec"]["egress"]
        if any(
            peer.get("namespaceSelector", {})
            .get("matchLabels", {})
            .get("kubernetes.io/metadata.name")
            == "observability"
            for peer in rule.get("to") or []
        )
    ]
    assert len(otlp_egress_rules) == 1
    assert {(p["protocol"], p["port"]) for p in otlp_egress_rules[0]["ports"]} == {
        ("TCP", 4317),
        ("TCP", 4318),
    }

    # Observability disabled
    disabled_docs = _render_chart(
        "--set",
        "observability.otlpEndpoint=",
        "--set",
        "observability.prometheusScrape=false",
        "--set",
        "networkPolicy.allowObservabilityScrape=false",
        "--set",
        "networkPolicy.allowOtlpEgress=false",
    )
    disabled_dep = _by_kind_and_name(disabled_docs, "Deployment")["ai-gateway-gateway-api"]
    disabled_svc = _by_kind_and_name(disabled_docs, "Service")["ai-gateway-gateway-api"]
    disabled_env = {
        e["name"]: e for e in disabled_dep["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in disabled_env
    assert "prometheus.io/scrape" not in (
        disabled_dep["spec"]["template"]["metadata"].get("annotations") or {}
    )
    assert "prometheus.io/scrape" not in (disabled_svc["metadata"].get("annotations") or {})
    disabled_np = _by_kind_and_name(disabled_docs, "NetworkPolicy")["ai-gateway-gateway-api"]
    disabled_ingress_ns = {
        peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
        for rule in disabled_np["spec"]["ingress"]
        for peer in rule.get("from") or []
        if "namespaceSelector" in peer
    }
    assert disabled_ingress_ns == {"traefik"}
    disabled_egress_ports = {
        (p["protocol"], p["port"])
        for rule in disabled_np["spec"]["egress"]
        for p in rule.get("ports") or []
    }
    assert ("TCP", 4317) not in disabled_egress_ports
    assert ("TCP", 4318) not in disabled_egress_ports


def _extract_hcl_resource_blocks(hcl_text: str) -> list[tuple[str, str, str]]:
    """Extract top-level `(resource_type, resource_name, body)` tuples from HCL text."""
    blocks: list[tuple[str, str, str]] = []
    pattern = re.compile(r'(?m)^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
    for match in pattern.finditer(hcl_text):
        res_type, res_name = match.groups()
        depth = 1
        idx = match.end()
        while idx < len(hcl_text) and depth > 0:
            char = hcl_text[idx]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            idx += 1
        blocks.append((res_type, res_name, hcl_text[match.end() : idx - 1]))
    return blocks


def test_local_terraform_observability_module_and_toggle_contract() -> None:
    obs_tf_path = TF_LOCAL_DIR / "observability.tf"
    assert obs_tf_path.is_file(), f"Missing {obs_tf_path}"

    tf_bin = shutil.which("terraform")
    assert tf_bin is not None, "terraform binary must be available in PATH"
    fmt_proc = subprocess.run(
        [tf_bin, f"-chdir={TF_LOCAL_DIR}", "fmt", "-check", "-diff"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert fmt_proc.returncode == 0, f"terraform fmt -check failed:\n{fmt_proc.stdout}"

    if not (TF_LOCAL_DIR / ".terraform").exists():
        init_proc = subprocess.run(
            [tf_bin, f"-chdir={TF_LOCAL_DIR}", "init", "-backend=false", "-input=false"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert init_proc.returncode == 0, (
            f"terraform init failed:\n{init_proc.stdout}\n{init_proc.stderr}"
        )

    validate_proc = subprocess.run(
        [tf_bin, f"-chdir={TF_LOCAL_DIR}", "validate"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert validate_proc.returncode == 0, (
        f"terraform validate failed:\n{validate_proc.stdout}\n{validate_proc.stderr}"
    )

    variables_hcl = (TF_LOCAL_DIR / "variables.tf").read_text(encoding="utf-8")
    for var_snippet in (
        'variable "enable_observability"',
        'variable "observability_namespace"',
        'default     = "observability"',
        'variable "prometheus_image"',
        'default     = "prom/prometheus:v3.2.1"',
        'variable "grafana_image"',
        'default     = "grafana/grafana:11.5.2"',
        'variable "jaeger_image"',
        'default     = "cr.jaegertracing.io/jaegertracing/jaeger:2.23.0"',
    ):
        assert var_snippet in variables_hcl

    obs_hcl = obs_tf_path.read_text(encoding="utf-8")
    blocks = _extract_hcl_resource_blocks(obs_hcl)
    assert len(blocks) >= 15

    # Every resource in observability.tf must be gated by enable_observability
    for res_type, res_name, body in blocks:
        assert re.search(r"count\s*=\s*var\.enable_observability\s*\?\s*1\s*:\s*0", body), (
            f"Resource {res_type}.{res_name} is missing enable_observability count gate"
        )

    by_id = {(res_type, res_name): body for res_type, res_name, body in blocks}
    ns_body = by_id[("kubernetes_namespace_v1", "observability")]
    assert '"kubernetes.io/metadata.name" = var.observability_namespace' in ns_body

    for workload, expected_uid, expected_probe in (
        ("prometheus", "65534", "/-/healthy"),
        ("grafana", "472", "/api/health"),
        ("jaeger", "10001", "16686"),
    ):
        sa_body = by_id[("kubernetes_service_account_v1", workload)]
        assert re.search(r"automount_service_account_token\s*=\s*false", sa_body)

        dep_body = by_id[("kubernetes_deployment_v1", workload)]
        for required_setting in (
            "automount_service_account_token = false",
            "run_as_non_root = true",
            f"run_as_user     = {expected_uid}",
            "read_only_root_filesystem  = true",
            "allow_privilege_escalation = false",
            'drop = ["ALL"]',
            'type = "RuntimeDefault"',
            "liveness_probe",
            "readiness_probe",
            expected_probe,
            "requests",
            "limits",
        ):
            assert required_setting in dep_body, (
                f"Deployment {workload} missing hardened setting: {required_setting}"
            )

    grafana_dep = by_id[("kubernetes_deployment_v1", "grafana")]
    for env_key in (
        "GF_AUTH_ANONYMOUS_ENABLED",
        "GF_AUTH_ANONYMOUS_ORG_ROLE",
        "GF_PATHS_DATA",
        "GF_PATHS_PROVISIONING",
    ):
        assert env_key in grafana_dep

    # Zero-trust NetworkPolicies in observability namespace
    netpols = {
        name: body for res_type, name, body in blocks if res_type == "kubernetes_network_policy_v1"
    }
    assert {
        "default_deny",
        "dns_egress",
        "prometheus",
        "grafana",
        "jaeger",
    }.issubset(set(netpols))
    assert "kube-system" in netpols["dns_egress"]
    assert "8000" in netpols["prometheus"]
    assert "9090" in netpols["prometheus"]
    assert "4317" in netpols["jaeger"]
    assert "4318" in netpols["jaeger"]
    assert "16686" in netpols["jaeger"]
    assert "9090" in netpols["grafana"]
    assert "16686" in netpols["grafana"]

    # main.tf Helm release passes observability values and waits on observability stack
    main_hcl = (TF_LOCAL_DIR / "main.tf").read_text(encoding="utf-8")
    for snippet in (
        "otlpEndpoint",
        "prometheusScrape",
        "allowObservabilityScrape",
        "allowOtlpEgress",
        "var.enable_observability",
        "kubernetes_namespace_v1.observability",
    ):
        assert snippet in main_hcl

    outputs_hcl = (TF_LOCAL_DIR / "outputs.tf").read_text(encoding="utf-8")
    assert 'output "observability_enabled"' in outputs_hcl
    assert 'output "observability_namespace"' in outputs_hcl


def test_makefile_and_ci_expose_observability_toggle() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "ENABLE_OBSERVABILITY ?= true" in makefile
    assert '-var="enable_observability=$(ENABLE_OBSERVABILITY)"' in makefile

    ci_doc = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text())
    smoke_steps_yaml = yaml.safe_dump(ci_doc["jobs"]["kind-smoke"]["steps"])
    assert "ENABLE_OBSERVABILITY=false" in smoke_steps_yaml
