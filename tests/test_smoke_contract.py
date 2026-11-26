"""Offline contract tests for local Credential bundle, Terraform, Makefile, smoke suite, and CI."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import fakeredis
import httpx
import jwt
import pytest
import yaml
from jwt import PyJWKSet

from gateway_api.app import create_app
from gateway_api.config import ControlPlaneSettings
from mock_llm.app import create_app as create_mock_provider_app
from mock_llm.config import MockProviderSettings
from scripts.generate_test_keys import (
    DEFAULT_AUDIENCE,
    DEFAULT_ISSUER,
    hash_api_key,
    write_local_credential_bundle,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TF_LOCAL_DIR = REPO_ROOT / "terraform" / "local"
CI_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def test_gitignore_excludes_local_credentials_and_terraform_state() -> None:
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".local/", ".terraform/", "*.tfstate", "*.tfvars", "!*.tfvars.example"):
        assert pattern in gitignore


def test_generate_test_keys_write_bundle_is_deterministic_and_complete(tmp_path: Path) -> None:
    bundle_a = tmp_path / "bundle-a"
    bundle_b = tmp_path / "bundle-b"

    for bundle_dir in (bundle_a, bundle_b):
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "generate_test_keys.py"),
                "--write-bundle",
                str(bundle_dir),
                "--issued-at",
                "1700000000",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr

    creds_a = json.loads((bundle_a / "credentials.json").read_text(encoding="utf-8"))
    creds_b = json.loads((bundle_b / "credentials.json").read_text(encoding="utf-8"))
    assert creds_a == creds_b

    assert (bundle_a / "jwks.json").is_file()
    assert (bundle_a / "private.pem").is_file()
    assert (bundle_a / "public.pem").is_file()
    assert (bundle_a / "api-keys.json").is_file()
    assert (bundle_a / "local.tfvars.json").is_file()

    jwks_data = json.loads((bundle_a / "jwks.json").read_text(encoding="utf-8"))
    assert creds_a["jwks"] == jwks_data
    jwk_set = PyJWKSet.from_dict(jwks_data)

    master_key = creds_a["litellm_master_key"]
    assert isinstance(master_key, str) and master_key.startswith("sk-litellm-")

    api_keys_text = (bundle_a / "api-keys.json").read_text(encoding="utf-8")
    assert "sk-gw-" not in api_keys_text
    api_keys_doc = json.loads(api_keys_text)
    stored_keys = api_keys_doc["api_keys"]

    expected_teams = {
        "platform-eng": "admin",
        "product-eng": "developer",
        "ops-eng": "ops",
    }
    assert set(creds_a["teams"]) == set(expected_teams)

    for team_name, expected_role in expected_teams.items():
        team_creds = creds_a["teams"][team_name]
        assert team_creds["team"] == team_name
        assert team_creds["role"] == expected_role
        plaintext_key = team_creds["api_key"]
        assert plaintext_key.startswith(f"sk-gw-{team_name}-")
        digest = hash_api_key(plaintext_key)
        assert team_creds["api_key_sha256"] == digest
        assert stored_keys[digest] == {
            "actor_id": team_creds["actor_id"],
            "team": team_name,
            "role": expected_role,
            "revoked": False,
        }

        token = team_creds["rs256_jwt"]
        kid = jwt.get_unverified_header(token)["kid"]
        decoded = jwt.decode(
            token,
            jwk_set[kid].key,
            algorithms=["RS256"],
            issuer=DEFAULT_ISSUER,
            audience=DEFAULT_AUDIENCE,
            options={"verify_exp": False},
        )
        assert decoded["sub"] == team_creds["actor_id"]
        assert decoded["team"] == team_name
        assert decoded["role"] == expected_role

    tfvars = json.loads((bundle_a / "local.tfvars.json").read_text(encoding="utf-8"))
    assert json.loads(tfvars["gateway_api_keys_json"]) == api_keys_doc
    assert json.loads(tfvars["gateway_jwks_json"]) == jwks_data
    assert tfvars["litellm_master_key"] == master_key


def test_local_terraform_fmt_and_contract() -> None:
    for filename in ("versions.tf", "variables.tf", "main.tf", "outputs.tf"):
        assert (TF_LOCAL_DIR / filename).is_file(), f"Missing {filename} in terraform/local/"

    tf_bin = shutil.which("terraform")
    assert tf_bin is not None, "terraform binary must be available in PATH"
    fmt_proc = subprocess.run(
        [tf_bin, f"-chdir={TF_LOCAL_DIR}", "fmt", "-check", "-diff"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert fmt_proc.returncode == 0, (
        f"terraform fmt -check failed:\n{fmt_proc.stdout}\n{fmt_proc.stderr}"
    )

    versions_hcl = (TF_LOCAL_DIR / "versions.tf").read_text(encoding="utf-8")
    for required in (
        ">= 1.6",
        "tehcyx/kind",
        "hashicorp/kubernetes",
        "hashicorp/helm",
        "hashicorp/null",
        "hashicorp/random",
        "hashicorp/tls",
    ):
        assert required in versions_hcl

    all_tf = "\n".join(p.read_text(encoding="utf-8") for p in sorted(TF_LOCAL_DIR.glob("*.tf")))
    assert not re.search(r"sk-gw-[A-Za-z0-9_-]{6,}", all_tf)
    assert not re.search(r"sk-litellm-[A-Za-z0-9_-]{6,}", all_tf)
    assert "BEGIN RSA PRIVATE KEY" not in all_tf
    assert "BEGIN PRIVATE KEY" not in all_tf

    main_hcl = (TF_LOCAL_DIR / "main.tf").read_text(encoding="utf-8")
    for expected_snippet in (
        "disable_default_cni = true",
        'pod_subnet          = "192.168.0.0/16"',
        "container_port = 30080",
        "host_port      = 8080",
        'listen_address = "127.0.0.1"',
        "tigera-operator",
        "metrics-server",
        "--kubelet-insecure-tls",
        "traefik",
        "NodePort",
        "ai-gateway-credentials",
        "ai-gateway-router-credentials",
        "../../deploy/helm/ai-enablement-platform",
    ):
        assert expected_snippet in main_hcl


def test_makefile_defines_required_targets() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    for target in ("dev-creds:", "build-images:", "up:", "down:", "test:", "lint:", "smoke:"):
        assert target in makefile
    assert "--write-bundle" in makefile
    assert "scripts/smoke_test.py" in makefile
    assert "TF_DIR := terraform/local" in makefile
    assert "terraform -chdir=$(TF_DIR)" in makefile


class _LocalIngressAndClusterTransport(httpx.AsyncBaseTransport):
    """Route external Ingress URLs (blocking /metrics) and port-forwards to real ASGI apps."""

    def __init__(
        self,
        *,
        gateway_app: Any,
        primary_app: Any,
        fallback_app: Any,
        expose_metrics_externally: bool = False,
    ) -> None:
        self._gateway = httpx.ASGITransport(app=gateway_app)
        self._primary = httpx.ASGITransport(app=primary_app)
        self._fallback = httpx.ASGITransport(app=fallback_app)
        self._expose_metrics_externally = expose_metrics_externally

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        port = request.url.port or 80
        path = request.url.path
        if port == 18001:
            return await self._primary.handle_async_request(request)
        if port == 18002:
            return await self._gateway.handle_async_request(request)
        if path == "/metrics" and not self._expose_metrics_externally:
            return httpx.Response(status_code=404, text="404 page not found\n")
        return await self._gateway.handle_async_request(request)

    async def aclose(self) -> None:
        await self._gateway.aclose()
        await self._primary.aclose()
        await self._fallback.aclose()


class _FailoverRouterTransport(httpx.AsyncBaseTransport):
    """Simulate LiteLLM Proxy primary-to-fallback failover over real primary/fallback mock apps."""

    def __init__(self, primary_app: Any, fallback_app: Any) -> None:
        self._primary = httpx.ASGITransport(app=primary_app)
        self._fallback = httpx.ASGITransport(app=fallback_app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        model_alias = payload["model"]
        primary_resp = await self._primary.handle_async_request(request)
        if primary_resp.status_code < 500:
            headers = dict(primary_resp.headers)
            headers.update(
                {
                    "x-litellm-attempted-fallbacks": "0",
                    "x-litellm-model-id": f"{model_alias}-primary",
                    "x-litellm-model-group": model_alias,
                }
            )
            return httpx.Response(
                status_code=primary_resp.status_code,
                headers=headers,
                stream=primary_resp.stream,
            )
        await primary_resp.aclose()

        fallback_resp = await self._fallback.handle_async_request(request)
        headers = dict(fallback_resp.headers)
        headers.update(
            {
                "x-litellm-attempted-fallbacks": "1",
                "x-litellm-model-id": f"{model_alias}-fallback",
                "x-litellm-model-group": f"{model_alias}-fallback",
            }
        )
        return httpx.Response(
            status_code=fallback_resp.status_code,
            headers=headers,
            stream=fallback_resp.stream,
        )


def _build_offline_smoke_harness(
    tmp_path: Path,
    *,
    expose_metrics_externally: bool = False,
    netpol_blocks_primary: bool = True,
):
    bundle_dir = tmp_path / ".local"
    write_local_credential_bundle(bundle_dir)
    api_keys_doc = json.loads((bundle_dir / "api-keys.json").read_text(encoding="utf-8"))
    jwks_doc = json.loads((bundle_dir / "jwks.json").read_text(encoding="utf-8"))

    primary_app = create_mock_provider_app(
        MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    fallback_app = create_mock_provider_app(
        MockProviderSettings(provider_name="mock-llm-fallback", mock_mode_enabled=True)
    )
    gateway_app = create_app(
        settings=ControlPlaneSettings(
            policy_bundle_path=REPO_ROOT / "policies" / "policy-bundle.yaml",
            model_router_base_url="http://litellm-proxy:4000",
            model_router_api_key="sk-litellm-test",
            api_keys=api_keys_doc,
            jwt_jwks=jwks_doc,
        ),
        model_router_transport=_FailoverRouterTransport(primary_app, fallback_app),
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
    )
    transport = _LocalIngressAndClusterTransport(
        gateway_app=gateway_app,
        primary_app=primary_app,
        fallback_app=fallback_app,
        expose_metrics_externally=expose_metrics_externally,
    )

    def kubectl_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["top", "pods"]:
            return subprocess.CompletedProcess(
                args=["kubectl", *args],
                returncode=0,
                stdout=(
                    "NAME                                     CPU(cores)   MEMORY(bytes)\n"
                    "ai-gateway-gateway-api-abc               5m           64Mi\n"
                ),
                stderr="",
            )
        if args[:2] == ["get", "hpa"]:
            hpa_payload = {
                "metadata": {"name": "ai-gateway-gateway-api"},
                "status": {
                    "currentReplicas": 1,
                    "desiredReplicas": 1,
                    "currentMetrics": [
                        {
                            "type": "Resource",
                            "resource": {
                                "name": "cpu",
                                "current": {"averageUtilization": 12},
                            },
                        }
                    ],
                },
            }
            return subprocess.CompletedProcess(
                args=["kubectl", *args],
                returncode=0,
                stdout=json.dumps(hpa_payload),
                stderr="",
            )
        if args[0] == "exec":
            script = args[-1]
            if "mock-llm-primary" in script:
                if netpol_blocks_primary:
                    return subprocess.CompletedProcess(
                        args=["kubectl", *args],
                        returncode=3,
                        stdout="BLOCKED:TimeoutError\n",
                        stderr="",
                    )
                return subprocess.CompletedProcess(
                    args=["kubectl", *args],
                    returncode=0,
                    stdout="CONNECTED\n",
                    stderr="",
                )
            if "ai-gateway-litellm-proxy" in script:
                return subprocess.CompletedProcess(
                    args=["kubectl", *args],
                    returncode=0,
                    stdout="CONNECTED\n",
                    stderr="",
                )
        raise AssertionError(f"Unexpected kubectl call in offline test: {args}")

    @contextmanager
    def port_forward_factory(service_name: str, remote_port: int, namespace: str) -> Iterator[int]:
        del namespace
        if service_name == "svc/mock-llm-primary" and remote_port == 8000:
            yield 18001
        elif service_name == "svc/ai-gateway-gateway-api" and remote_port == 8000:
            yield 18002
        else:
            raise AssertionError(f"Unexpected port-forward target: {service_name}:{remote_port}")

    return bundle_dir / "credentials.json", transport, kubectl_runner, port_forward_factory


async def test_smoke_suite_passes_offline_against_real_gateway_and_mock_apps(
    tmp_path: Path,
) -> None:
    from scripts.smoke_test import SmokeAssertionError, run_smoke_suite

    creds_path, transport, kubectl_runner, pf_factory = _build_offline_smoke_harness(tmp_path)
    results = await run_smoke_suite(
        base_url="http://localhost:8080",
        credentials_path=creds_path,
        http_transport=transport,
        kubectl_runner=kubectl_runner,
        port_forward_factory=pf_factory,
        avoid_minute_rollover=False,
    )
    assert len(results) == 10
    assert all(item.passed for item in results)
    assert SmokeAssertionError is not None


async def test_smoke_suite_fails_when_metrics_exposed_or_network_policy_bypassed(
    tmp_path: Path,
) -> None:
    from scripts.smoke_test import SmokeAssertionError, run_smoke_suite

    creds_a, transport_a, kubectl_a, pf_a = _build_offline_smoke_harness(
        tmp_path / "exposed-metrics",
        expose_metrics_externally=True,
    )
    with pytest.raises(SmokeAssertionError, match="/metrics"):
        await run_smoke_suite(
            base_url="http://localhost:8080",
            credentials_path=creds_a,
            http_transport=transport_a,
            kubectl_runner=kubectl_a,
            port_forward_factory=pf_a,
            avoid_minute_rollover=False,
        )

    creds_b, transport_b, kubectl_b, pf_b = _build_offline_smoke_harness(
        tmp_path / "netpol-open",
        netpol_blocks_primary=False,
    )
    with pytest.raises(SmokeAssertionError, match="NetworkPolicy"):
        await run_smoke_suite(
            base_url="http://localhost:8080",
            credentials_path=creds_b,
            http_transport=transport_b,
            kubectl_runner=kubectl_b,
            port_forward_factory=pf_b,
            avoid_minute_rollover=False,
        )


def test_ci_workflow_defines_static_and_live_kind_smoke_jobs() -> None:
    assert CI_WORKFLOW_PATH.is_file(), "Missing .github/workflows/ci.yml"
    workflow = yaml.safe_load(CI_WORKFLOW_PATH.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    assert len(jobs) >= 2

    all_steps_text = yaml.safe_dump(workflow)
    for required_cmd in (
        "uv sync --locked",
        "uv run ruff check .",
        "uv run ruff format --check .",
        "uv run pytest",
        "scripts/validate_aliases.py",
        "helm lint deploy/helm/ai-enablement-platform",
        "helm template",
        "terraform -chdir=terraform/local fmt -check",
        "terraform -chdir=terraform/local init -backend=false",
        "terraform -chdir=terraform/local validate",
    ):
        assert required_cmd in all_steps_text

    smoke_job = jobs["kind-smoke"]
    assert smoke_job["needs"]
    smoke_steps = smoke_job["steps"]
    smoke_yaml = yaml.safe_dump(smoke_steps)
    assert "make up" in smoke_yaml
    assert "make smoke" in smoke_yaml
    assert any(
        step.get("if") == "always()" and "make down" in (step.get("run") or "")
        for step in smoke_steps
    )
