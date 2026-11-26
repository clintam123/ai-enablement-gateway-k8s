"""Manifest contract tests for the hardened platform Helm chart."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from scripts.validate_aliases import validate_policy_and_router_aliases

REPO_ROOT = Path(__file__).resolve().parent.parent
CHART_DIR = REPO_ROOT / "deploy" / "helm" / "ai-enablement-platform"
CANONICAL_POLICY_PATH = REPO_ROOT / "policies" / "policy-bundle.yaml"
CANONICAL_LITELLM_CONFIG_PATH = REPO_ROOT / "services" / "litellm-proxy" / "config.yaml"


def _render_helm_manifests(
    *extra_args: str,
    release_name: str = "ai-gateway",
    namespace: str = "ai-gateway",
) -> list[dict[str, Any]]:
    helm_bin = shutil.which("helm")
    assert helm_bin is not None, "helm binary must be available in PATH"
    cmd = [
        helm_bin,
        "template",
        release_name,
        str(CHART_DIR),
        "--namespace",
        namespace,
        *extra_args,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, (
        f"helm template failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    docs = [doc for doc in yaml.safe_load_all(proc.stdout) if isinstance(doc, dict)]
    assert docs, "helm template produced no Kubernetes manifests"
    return docs


def test_helm_chart_files_match_canonical_sources() -> None:
    chart_policy = CHART_DIR / "files" / "policy-bundle.yaml"
    chart_litellm = CHART_DIR / "files" / "litellm-config.yaml"

    assert chart_policy.is_file(), f"Missing chart policy file: {chart_policy}"
    assert chart_litellm.is_file(), f"Missing chart litellm config file: {chart_litellm}"

    assert chart_policy.read_bytes() == CANONICAL_POLICY_PATH.read_bytes()
    assert chart_litellm.read_bytes() == CANONICAL_LITELLM_CONFIG_PATH.read_bytes()

    aliases = validate_policy_and_router_aliases(chart_policy, chart_litellm)
    assert set(aliases) == {"chat-default", "chat-fast", "chat-premium"}


def test_helm_lint_and_template_render_configmaps() -> None:
    helm_bin = shutil.which("helm")
    assert helm_bin is not None, "helm binary must be available in PATH"

    lint = subprocess.run(
        [helm_bin, "lint", str(CHART_DIR)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert lint.returncode == 0, f"helm lint failed:\n{lint.stdout}\n{lint.stderr}"

    docs = _render_helm_manifests()
    configmaps = [doc for doc in docs if doc.get("kind") == "ConfigMap"]
    assert len(configmaps) >= 2

    all_cm_data: dict[str, str] = {}
    for cm in configmaps:
        assert cm["metadata"]["namespace"] == "ai-gateway"
        all_cm_data.update(cm.get("data") or {})

    assert all_cm_data.get("policy-bundle.yaml") == CANONICAL_POLICY_PATH.read_text(
        encoding="utf-8"
    )
    assert all_cm_data.get("config.yaml") == CANONICAL_LITELLM_CONFIG_PATH.read_text(
        encoding="utf-8"
    )


def _by_kind_and_name(docs: list[dict[str, Any]], kind: str) -> dict[str, dict[str, Any]]:
    return {
        doc["metadata"]["name"]: doc
        for doc in docs
        if doc.get("kind") == kind and isinstance(doc.get("metadata", {}).get("name"), str)
    }


def _env_map(container: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["name"]: item for item in container.get("env") or []}


def _volume_map(pod_spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["name"]: item for item in pod_spec.get("volumes") or []}


def _mount_map(container: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["mountPath"]: item for item in container.get("volumeMounts") or []}


def test_all_workloads_define_hardened_security_rbac_probes_and_resources() -> None:
    docs = _render_helm_manifests()
    deployments = _by_kind_and_name(docs, "Deployment")
    service_accounts = _by_kind_and_name(docs, "ServiceAccount")
    roles = _by_kind_and_name(docs, "Role")
    role_bindings = _by_kind_and_name(docs, "RoleBinding")

    expected_workloads = {
        "ai-gateway-gateway-api",
        "ai-gateway-litellm-proxy",
        "ai-gateway-mock-llm-primary",
        "ai-gateway-mock-llm-fallback",
        "ai-gateway-redis",
    }
    assert set(deployments) == expected_workloads

    bound_sas: set[str] = set()
    for rb in role_bindings.values():
        assert rb["metadata"]["namespace"] == "ai-gateway"
        role_name = rb["roleRef"]["name"]
        assert role_name in roles
        assert roles[role_name].get("rules") == []
        for subject in rb["subjects"]:
            if subject.get("kind") == "ServiceAccount":
                assert subject["namespace"] == "ai-gateway"
                bound_sas.add(subject["name"])

    for workload_name in expected_workloads:
        dep = deployments[workload_name]
        assert dep["metadata"]["namespace"] == "ai-gateway"
        pod_spec = dep["spec"]["template"]["spec"]

        sa_name = pod_spec["serviceAccountName"]
        assert sa_name == workload_name
        assert sa_name in service_accounts
        assert service_accounts[sa_name]["metadata"]["namespace"] == "ai-gateway"
        assert service_accounts[sa_name]["automountServiceAccountToken"] is False
        assert pod_spec["automountServiceAccountToken"] is False
        assert sa_name in bound_sas

        pod_sec = pod_spec["securityContext"]
        assert pod_sec["runAsNonRoot"] is True
        assert pod_sec["seccompProfile"]["type"] == "RuntimeDefault"

        containers = pod_spec["containers"]
        assert len(containers) == 1
        container = containers[0]
        c_sec = container["securityContext"]
        assert c_sec["runAsNonRoot"] is True
        assert c_sec["readOnlyRootFilesystem"] is True
        assert c_sec["allowPrivilegeEscalation"] is False
        assert c_sec["capabilities"]["drop"] == ["ALL"]

        resources = container["resources"]
        assert resources["requests"]["cpu"]
        assert resources["requests"]["memory"]
        assert resources["limits"]["cpu"]
        assert resources["limits"]["memory"]

        assert container["livenessProbe"]
        assert container["readinessProbe"]


def test_litellm_proxy_stateless_non_root_and_probe_contract() -> None:
    docs = _render_helm_manifests()
    dep = _by_kind_and_name(docs, "Deployment")["ai-gateway-litellm-proxy"]
    pod_meta = dep["spec"]["template"]["metadata"]
    pod_spec = dep["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]

    assert container["image"] == "ghcr.io/berriai/litellm:1.84.0"
    assert container["securityContext"]["runAsUser"] == 65532
    assert container["securityContext"]["runAsGroup"] == 65532
    assert container["args"] == ["--config", "/app/config.yaml", "--port", "4000"]

    envs = _env_map(container)
    assert "DATABASE_URL" not in envs
    assert envs["LITELLM_NON_ROOT"]["value"] == "true"
    assert envs["HOME"]["value"] == "/tmp"
    assert envs["XDG_CACHE_HOME"]["value"] == "/tmp/cache"
    assert envs["LITELLM_MIGRATION_DIR"]["value"] == "/tmp/migrations"
    assert envs["PRISMA_BINARY_CACHE_DIR"]["value"] == "/tmp/cache/prisma"
    assert envs["TIKTOKEN_CACHE_DIR"]["value"] == "/tmp/cache/tiktoken"
    assert envs["LITELLM_MASTER_KEY"]["valueFrom"]["secretKeyRef"]["key"] == "litellm-master-key"

    mounts = _mount_map(container)
    volumes = _volume_map(pod_spec)
    assert mounts["/tmp"]["name"] in volumes
    assert "emptyDir" in volumes[mounts["/tmp"]["name"]]
    assert mounts["/app/config.yaml"]["readOnly"] is True
    assert mounts["/app/config.yaml"]["subPath"] == "config.yaml"
    assert "configMap" in volumes[mounts["/app/config.yaml"]["name"]]

    assert container["livenessProbe"]["httpGet"]["path"] == "/health/liveliness"
    assert container["readinessProbe"]["httpGet"]["path"] == "/health/readiness"

    baseline_checksum = pod_meta["annotations"]["checksum/litellm-config"]
    assert baseline_checksum
    updated_docs = _render_helm_manifests(
        "--set-string",
        "configMaps.litellmConfigOverride=model_list: []\n",
    )
    updated_dep = _by_kind_and_name(updated_docs, "Deployment")["ai-gateway-litellm-proxy"]
    updated_checksum = updated_dep["spec"]["template"]["metadata"]["annotations"][
        "checksum/litellm-config"
    ]
    assert updated_checksum != baseline_checksum


def test_gateway_api_redis_and_mock_provider_contracts() -> None:
    docs = _render_helm_manifests()
    deployments = _by_kind_and_name(docs, "Deployment")
    services = _by_kind_and_name(docs, "Service")

    # Control Plane (gateway-api)
    gw = deployments["ai-gateway-gateway-api"]
    gw_pod = gw["spec"]["template"]["spec"]
    gw_container = gw_pod["containers"][0]
    assert gw_container["securityContext"]["runAsUser"] == 10001
    assert gw_container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert gw_container["readinessProbe"]["httpGet"]["path"] == "/readyz"

    gw_envs = _env_map(gw_container)
    assert gw_envs["GATEWAY_REDIS_URL"]["value"] == "redis://ai-gateway-redis:6379/0"
    assert (
        gw_envs["GATEWAY_MODEL_ROUTER_BASE_URL"]["value"] == "http://ai-gateway-litellm-proxy:4000"
    )
    assert gw_envs["GATEWAY_POLICY_BUNDLE_PATH"]["value"] == "/etc/gateway/policy-bundle.yaml"
    assert gw_envs["GATEWAY_API_KEYS_PATH"]["value"] == "/etc/gateway/secrets/api-keys.json"
    assert gw_envs["GATEWAY_JWT_JWKS_JSON"]["valueFrom"]["secretKeyRef"]["key"] == "jwks.json"
    assert (
        gw_envs["GATEWAY_MODEL_ROUTER_API_KEY"]["valueFrom"]["secretKeyRef"]["key"]
        == "litellm-master-key"
    )

    gw_mounts = _mount_map(gw_container)
    gw_volumes = _volume_map(gw_pod)
    assert gw_mounts["/etc/gateway/policy-bundle.yaml"]["readOnly"] is True
    assert "configMap" in gw_volumes[gw_mounts["/etc/gateway/policy-bundle.yaml"]["name"]]
    assert gw_mounts["/etc/gateway/secrets"]["readOnly"] is True
    assert "secret" in gw_volumes[gw_mounts["/etc/gateway/secrets"]["name"]]
    assert "emptyDir" in gw_volumes[gw_mounts["/tmp"]["name"]]

    gw_checksum = gw["spec"]["template"]["metadata"]["annotations"]["checksum/policy-bundle"]
    assert gw_checksum
    updated_gw_docs = _render_helm_manifests(
        "--set-string",
        "configMaps.policyBundleOverride=schema_version: v1\n",
    )
    updated_gw = _by_kind_and_name(updated_gw_docs, "Deployment")["ai-gateway-gateway-api"]
    assert (
        updated_gw["spec"]["template"]["metadata"]["annotations"]["checksum/policy-bundle"]
        != gw_checksum
    )

    # Redis
    redis_dep = deployments["ai-gateway-redis"]
    redis_pod = redis_dep["spec"]["template"]["spec"]
    redis_container = redis_pod["containers"][0]
    assert redis_container["image"] == "redis:7.4.2-alpine"
    assert redis_container["securityContext"]["runAsUser"] == 999
    assert redis_container["args"] == ["redis-server", "--save", "", "--appendonly", "no"]
    assert redis_container["livenessProbe"]["exec"]["command"] == ["redis-cli", "ping"]
    assert redis_container["readinessProbe"]["exec"]["command"] == ["redis-cli", "ping"]
    redis_mounts = _mount_map(redis_container)
    redis_volumes = _volume_map(redis_pod)
    assert "emptyDir" in redis_volumes[redis_mounts["/data"]["name"]]
    assert "emptyDir" in redis_volumes[redis_mounts["/tmp"]["name"]]

    # Mock Providers (primary + fallback)
    for role_name in ("mock-llm-primary", "mock-llm-fallback"):
        dep = deployments[f"ai-gateway-{role_name}"]
        c = dep["spec"]["template"]["spec"]["containers"][0]
        assert c["securityContext"]["runAsUser"] == 10001
        envs = _env_map(c)
        assert envs["MOCK_LLM_PROVIDER_NAME"]["value"] == role_name
        assert envs["MOCK_LLM_MOCK_MODE_ENABLED"]["value"] == "true"
        assert c["livenessProbe"]["httpGet"]["path"] == "/healthz"
        assert c["readinessProbe"]["httpGet"]["path"] == "/healthz"
        assert role_name in services
        assert services[role_name]["spec"]["ports"][0]["port"] == 8000

    assert "ai-gateway-gateway-api" in services
    assert services["ai-gateway-gateway-api"]["spec"]["ports"][0]["port"] == 8000
    assert "ai-gateway-litellm-proxy" in services
    assert services["ai-gateway-litellm-proxy"]["spec"]["ports"][0]["port"] == 4000
    assert "ai-gateway-redis" in services
    assert services["ai-gateway-redis"]["spec"]["ports"][0]["port"] == 6379


def test_hpa_targets_gateway_api_with_two_plus_max_replicas() -> None:
    docs = _render_helm_manifests()
    hpas = _by_kind_and_name(docs, "HorizontalPodAutoscaler")
    assert "ai-gateway-gateway-api" in hpas

    hpa = hpas["ai-gateway-gateway-api"]
    assert hpa["apiVersion"] == "autoscaling/v2"
    assert hpa["metadata"]["namespace"] == "ai-gateway"

    spec = hpa["spec"]
    assert spec["scaleTargetRef"] == {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "name": "ai-gateway-gateway-api",
    }
    assert spec["minReplicas"] >= 1
    assert spec["maxReplicas"] >= 2
    assert any(
        m.get("type") == "Resource"
        and m.get("resource", {}).get("name") == "cpu"
        and m.get("resource", {}).get("target", {}).get("type") == "Utilization"
        for m in spec["metrics"]
    )

    gw_dep = _by_kind_and_name(docs, "Deployment")["ai-gateway-gateway-api"]
    assert "replicas" not in gw_dep["spec"]


def test_traefik_ingress_exposes_api_and_blocks_metrics_externally() -> None:
    docs = _render_helm_manifests()
    ingresses = _by_kind_and_name(docs, "Ingress")
    middlewares = _by_kind_and_name(docs, "Middleware")

    assert middlewares == {}
    assert list(ingresses) == ["ai-gateway-gateway-api"]

    ingress = ingresses["ai-gateway-gateway-api"]
    assert ingress["apiVersion"] == "networking.k8s.io/v1"
    assert ingress["metadata"]["namespace"] == "ai-gateway"
    assert ingress["spec"]["ingressClassName"] == "traefik"

    exposed_paths: set[str] = set()
    for rule in ingress["spec"]["rules"]:
        for path_entry in rule["http"]["paths"]:
            exposed_paths.add(path_entry["path"])
            backend = path_entry["backend"]["service"]
            assert backend["name"] == "ai-gateway-gateway-api"
            assert backend["port"]["number"] == 8000

    assert exposed_paths == {"/v1", "/mcp", "/healthz", "/readyz"}
    assert "/metrics" not in exposed_paths

    # Defense-in-depth Traefik Middleware toggle
    mw_docs = _render_helm_manifests("--set", "ingress.traefikMiddleware.enabled=true")
    mw_ingresses = _by_kind_and_name(mw_docs, "Ingress")
    mw_objects = _by_kind_and_name(mw_docs, "Middleware")
    assert "ai-gateway-block-metrics" in mw_objects
    mw = mw_objects["ai-gateway-block-metrics"]
    assert mw["apiVersion"] == "traefik.io/v1alpha1"
    assert mw["spec"]["ipAllowList"]["sourceRange"] == ["127.0.0.1/32"]
    assert mw["spec"]["ipAllowList"]["rejectStatusCode"] == 404

    block_ingress = mw_ingresses["ai-gateway-block-metrics"]
    assert (
        block_ingress["metadata"]["annotations"]["traefik.ingress.kubernetes.io/router.middlewares"]
        == "ai-gateway-ai-gateway-block-metrics@kubernetescrd"
    )
    assert block_ingress["spec"]["rules"][0]["http"]["paths"][0]["path"] == "/metrics"
    primary_mw_ingress = mw_ingresses["ai-gateway-gateway-api"]
    assert all(
        p["backend"]["service"]["port"]["number"] == 8000
        for p in primary_mw_ingress["spec"]["rules"][0]["http"]["paths"]
    )


def _flatten_policy_peers(rules: list[dict[str, Any]], peer_key: str) -> list[dict[str, Any]]:
    peers: list[dict[str, Any]] = []
    for rule in rules:
        for peer in rule.get(peer_key) or []:
            peers.append(peer)
    return peers


def test_zero_trust_network_policies_enforce_isolation_boundaries() -> None:
    docs = _render_helm_manifests()
    netpols = _by_kind_and_name(docs, "NetworkPolicy")

    expected_names = {
        "ai-gateway-default-deny",
        "ai-gateway-dns-egress",
        "ai-gateway-gateway-api",
        "ai-gateway-litellm-proxy",
        "ai-gateway-mock-llm-primary",
        "ai-gateway-mock-llm-fallback",
        "ai-gateway-redis",
    }
    assert expected_names.issubset(set(netpols))

    # Default deny
    default_deny = netpols["ai-gateway-default-deny"]
    assert default_deny["spec"]["podSelector"] == {}
    assert default_deny["spec"]["policyTypes"] == ["Ingress", "Egress"]

    # DNS egress allows UDP + TCP 53 to kube-system for gateway-api and litellm-proxy
    dns = netpols["ai-gateway-dns-egress"]
    assert dns["spec"]["policyTypes"] == ["Egress"]
    dns_expr = dns["spec"]["podSelector"]["matchExpressions"][0]
    assert dns_expr["key"] == "app.kubernetes.io/component"
    assert set(dns_expr["values"]) == {"gateway-api", "litellm-proxy"}
    dns_ports = {(p["protocol"], p["port"]) for p in dns["spec"]["egress"][0]["ports"]}
    assert dns_ports == {("UDP", 53), ("TCP", 53)}
    assert (
        dns["spec"]["egress"][0]["to"][0]["namespaceSelector"]["matchLabels"][
            "kubernetes.io/metadata.name"
        ]
        == "kube-system"
    )

    # gateway-api: ingress ONLY from traefik and observability on 8000;
    # egress ONLY to litellm-proxy & redis
    gw_np = netpols["ai-gateway-gateway-api"]
    gw_selector = gw_np["spec"]["podSelector"]["matchLabels"]
    assert gw_selector["app.kubernetes.io/component"] == "gateway-api"
    gw_ingress_ns = {
        peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
        for peer in _flatten_policy_peers(gw_np["spec"]["ingress"], "from")
        if "namespaceSelector" in peer
    }
    assert gw_ingress_ns == {"traefik", "observability"}
    for rule in gw_np["spec"]["ingress"]:
        assert {(p["protocol"], p["port"]) for p in rule["ports"]} == {("TCP", 8000)}

    gw_egress_peers = _flatten_policy_peers(gw_np["spec"]["egress"], "to")
    gw_egress_components = {
        peer["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
        for peer in gw_egress_peers
        if "podSelector" in peer
    }
    assert gw_egress_components == {"litellm-proxy", "redis"}
    assert "mock-llm-primary" not in gw_egress_components
    assert "mock-llm-fallback" not in gw_egress_components
    assert not any("ipBlock" in peer for peer in gw_egress_peers)

    # litellm-proxy: ingress ONLY from gateway-api:4000;
    # default egress ONLY to mock-llm-primary/fallback:8000
    router_np = netpols["ai-gateway-litellm-proxy"]
    router_from_components = {
        peer["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
        for peer in _flatten_policy_peers(router_np["spec"]["ingress"], "from")
    }
    assert router_from_components == {"gateway-api"}
    assert {(p["protocol"], p["port"]) for p in router_np["spec"]["ingress"][0]["ports"]} == {
        ("TCP", 4000)
    }

    router_to_components = {
        peer["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
        for peer in _flatten_policy_peers(router_np["spec"]["egress"], "to")
        if "podSelector" in peer
    }
    assert router_to_components == {"mock-llm-primary", "mock-llm-fallback"}
    assert not any(
        "ipBlock" in peer for peer in _flatten_policy_peers(router_np["spec"]["egress"], "to")
    )

    # mock-llm-primary & mock-llm-fallback: ingress ONLY from litellm-proxy:8000; zero egress
    for mock_name in ("mock-llm-primary", "mock-llm-fallback"):
        mock_np = netpols[f"ai-gateway-{mock_name}"]
        mock_from = {
            peer["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
            for peer in _flatten_policy_peers(mock_np["spec"]["ingress"], "from")
        }
        assert mock_from == {"litellm-proxy"}
        assert {(p["protocol"], p["port"]) for p in mock_np["spec"]["ingress"][0]["ports"]} == {
            ("TCP", 8000)
        }
        assert mock_np["spec"].get("egress", []) == []

    # redis: ingress ONLY from gateway-api:6379; zero egress
    redis_np = netpols["ai-gateway-redis"]
    redis_from = {
        peer["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
        for peer in _flatten_policy_peers(redis_np["spec"]["ingress"], "from")
    }
    assert redis_from == {"gateway-api"}
    assert {(p["protocol"], p["port"]) for p in redis_np["spec"]["ingress"][0]["ports"]} == {
        ("TCP", 6379)
    }
    assert redis_np["spec"].get("egress", []) == []

    # Optional external Provider egress on litellm-proxy blocks RFC1918 + link-local metadata
    ext_docs = _render_helm_manifests("--set", "networkPolicy.allowExternalProviderEgress=true")
    ext_router = _by_kind_and_name(ext_docs, "NetworkPolicy")["ai-gateway-litellm-proxy"]
    ip_blocks = [
        peer["ipBlock"]
        for peer in _flatten_policy_peers(ext_router["spec"]["egress"], "to")
        if "ipBlock" in peer
    ]
    assert len(ip_blocks) == 1
    assert ip_blocks[0]["cidr"] == "0.0.0.0/0"
    assert {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}.issubset(
        set(ip_blocks[0]["except"])
    )
