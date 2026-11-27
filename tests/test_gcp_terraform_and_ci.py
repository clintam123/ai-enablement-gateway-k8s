"""Contract tests for GCP GKE Autopilot Terraform, Helm Workload Identity, and CI gates."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CHART_DIR = REPO_ROOT / "deploy" / "helm" / "ai-enablement-platform"
TF_GCP_DIR = REPO_ROOT / "terraform" / "gcp"


def _render_helm_manifests(*extra_args: str) -> list[dict[str, Any]]:
    helm_bin = shutil.which("helm")
    assert helm_bin is not None, "helm binary must be available in PATH"
    cmd = [
        helm_bin,
        "template",
        "ai-gateway",
        str(CHART_DIR),
        "--namespace",
        "ai-gateway",
        *extra_args,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"helm template failed:\n{proc.stdout}\n{proc.stderr}"
    return [doc for doc in yaml.safe_load_all(proc.stdout) if isinstance(doc, dict)]


def _by_kind_and_name(docs: list[dict[str, Any]], kind: str) -> dict[str, dict[str, Any]]:
    return {
        doc["metadata"]["name"]: doc
        for doc in docs
        if doc.get("kind") == kind and isinstance(doc.get("metadata", {}).get("name"), str)
    }


def test_helm_gateway_service_account_workload_identity_annotations() -> None:
    default_docs = _render_helm_manifests()
    default_sas = _by_kind_and_name(default_docs, "ServiceAccount")
    assert "annotations" not in default_sas["ai-gateway-gateway-api"]["metadata"]

    sa_email = "ai-gateway-control-plane@demo-project.iam.gserviceaccount.com"
    annotated_docs = _render_helm_manifests(
        "--set-string",
        rf"gatewayApi.serviceAccount.annotations.iam\.gke\.io/gcp-service-account={sa_email}",
    )
    annotated_sas = _by_kind_and_name(annotated_docs, "ServiceAccount")
    assert annotated_sas["ai-gateway-gateway-api"]["metadata"]["annotations"] == {
        "iam.gke.io/gcp-service-account": sa_email,
    }
    assert "annotations" not in annotated_sas["ai-gateway-mcp-runtime"]["metadata"]


def test_gcp_terraform_fmt_validate_and_contract(tmp_path: Path) -> None:
    for filename in ("versions.tf", "variables.tf", "main.tf", "outputs.tf"):
        assert (TF_GCP_DIR / filename).is_file(), f"Missing {filename} in terraform/gcp/"

    tf_bin = shutil.which("terraform")
    assert tf_bin is not None, "terraform binary must be available in PATH"

    fmt_proc = subprocess.run(
        [tf_bin, f"-chdir={TF_GCP_DIR}", "fmt", "-check", "-diff"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert fmt_proc.returncode == 0, (
        f"terraform fmt -check failed:\n{fmt_proc.stdout}\n{fmt_proc.stderr}"
    )

    tf_copy = tmp_path / "terraform" / "gcp"
    tf_copy.mkdir(parents=True)
    for tf_file in TF_GCP_DIR.glob("*.tf"):
        (tf_copy / tf_file.name).write_text(tf_file.read_text(encoding="utf-8"), encoding="utf-8")

    init_proc = subprocess.run(
        [tf_bin, f"-chdir={tf_copy}", "init", "-backend=false", "-input=false"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert init_proc.returncode == 0, (
        f"terraform init -backend=false failed:\n{init_proc.stdout}\n{init_proc.stderr}"
    )

    val_proc = subprocess.run(
        [tf_bin, f"-chdir={tf_copy}", "validate"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert val_proc.returncode == 0, (
        f"terraform validate failed:\n{val_proc.stdout}\n{val_proc.stderr}"
    )

    versions_hcl = (TF_GCP_DIR / "versions.tf").read_text(encoding="utf-8")
    for required in (
        ">= 1.6",
        "hashicorp/google",
        "~> 6.0",
        "hashicorp/kubernetes",
        "hashicorp/helm",
        "hashicorp/random",
        "hashicorp/tls",
    ):
        assert required in versions_hcl

    all_tf = "\n".join(p.read_text(encoding="utf-8") for p in sorted(TF_GCP_DIR.glob("*.tf")))
    assert not re.search(r"sk-gw-[A-Za-z0-9_-]{6,}", all_tf)
    assert not re.search(r"sk-litellm-[A-Za-z0-9_-]{6,}", all_tf)
    assert "BEGIN RSA PRIVATE KEY" not in all_tf
    assert "BEGIN PRIVATE KEY" not in all_tf

    main_hcl = (TF_GCP_DIR / "main.tf").read_text(encoding="utf-8")
    main_hcl_no_comments = "\n".join(
        line for line in main_hcl.splitlines() if not line.lstrip().startswith("#")
    )
    for forbidden_standard_field in (
        "initial_node_count",
        "remove_default_node_pool",
        "node_config",
    ):
        assert not re.search(rf"\b{forbidden_standard_field}\b", main_hcl_no_comments)

    for expected_snippet in (
        "google_compute_network",
        "auto_create_subnetworks = false",
        "google_compute_subnetwork",
        "private_ip_google_access = true",
        "secondary_ip_range",
        "google_artifact_registry_repository",
        'format        = "DOCKER"',
        "google_container_cluster",
        "enable_autopilot    = true",
        "deletion_protection = false",
        "disable_on_destroy         = false",
        "roles/iam.workloadIdentityUser",
        "iam.gke.io/gcp-service-account",
        "ai-gateway-credentials",
        "ai-gateway-mcp-credentials",
        "ai-gateway-router-credentials",
        "ai-gateway-provider-keys",
        "GEMINI_API_KEY",
        "allowExternalProviderEgress = var.enable_gemini_provider",
        "../../deploy/helm/ai-enablement-platform",
    ):
        assert expected_snippet in main_hcl

    outputs_hcl = (TF_GCP_DIR / "outputs.tf").read_text(encoding="utf-8")
    for required_output in (
        'output "cluster_name"',
        'output "region"',
        'output "cluster_endpoint"',
        'output "artifact_registry_url"',
        'output "workload_identity_sa_email"',
        'output "kubectl_credentials_command"',
    ):
        assert required_output in outputs_hcl


def test_makefile_defines_gcp_and_security_scan_targets() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    for target in ("gcp-up:", "gcp-down:", "checkov:", "trivy:"):
        assert target in makefile
    assert "terraform/gcp" in makefile
    assert "--skip-check" not in makefile
    assert "checkov" in makefile
    assert "trivy" in makefile
    assert "--ignore-unfixed" in makefile
    assert "CRITICAL,HIGH" in makefile
    assert "ghcr.io/berriai/litellm:1.84.0" in makefile


def test_checkov_inline_skips_carry_explicit_justifications_and_no_global_skips() -> None:
    tf_skip_re = re.compile(r"#\s*checkov:skip=(CKV[A-Z0-9_]*)(?::(.*))?$")
    tf_files = sorted((REPO_ROOT / "terraform").rglob("*.tf"))
    assert tf_files
    tf_skip_count = 0
    for tf_file in tf_files:
        for lineno, line in enumerate(tf_file.read_text(encoding="utf-8").splitlines(), start=1):
            if "checkov:skip" not in line:
                continue
            match = tf_skip_re.search(line.strip())
            assert match is not None, f"Malformed checkov skip in {tf_file}:{lineno}: {line}"
            reason = (match.group(2) or "").strip()
            assert len(reason) >= 12, (
                f"Checkov skip in {tf_file}:{lineno} lacks meaningful justification: {line}"
            )
            tf_skip_count += 1
    assert tf_skip_count >= 1

    helm_skip_re = re.compile(r'checkov\.io/skip\d*:\s*"?(CKV[A-Z0-9_]*)=(.+?)"?\s*$')
    helm_files = sorted((CHART_DIR / "templates").glob("*.yaml"))
    assert helm_files
    helm_skip_count = 0
    for helm_file in helm_files:
        for lineno, line in enumerate(helm_file.read_text(encoding="utf-8").splitlines(), start=1):
            if "checkov.io/skip" not in line:
                continue
            match = helm_skip_re.search(line.strip())
            assert match is not None, f"Malformed Helm checkov skip in {helm_file}:{lineno}: {line}"
            reason = match.group(2).strip()
            assert len(reason) >= 12, (
                f"Helm checkov skip in {helm_file}:{lineno} lacks meaningful justification: {line}"
            )
            helm_skip_count += 1
    assert helm_skip_count >= 1

    ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    makefile_text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "--skip-check" not in ci_text
    assert "--skip-check" not in makefile_text


def test_ci_workflow_enforces_gcp_terraform_checkov_and_trivy_gates() -> None:
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    ci_text = ci_path.read_text(encoding="utf-8")
    assert "--skip-check" not in ci_text

    workflow = yaml.safe_load(ci_text)
    jobs = workflow["jobs"]

    validate_yaml = yaml.safe_dump(jobs["validate-and-test"]["steps"], width=4096)
    for expected in (
        "terraform -chdir=terraform/gcp fmt -check -diff",
        "terraform -chdir=terraform/gcp init -backend=false",
        "terraform -chdir=terraform/gcp validate",
        "checkov -d terraform/local --framework terraform",
        "checkov -d terraform/gcp --framework terraform",
        "helm template ai-gateway deploy/helm/ai-enablement-platform --namespace ai-gateway",
        "checkov -f /tmp/helm-rendered.yaml --framework kubernetes",
    ):
        assert expected in validate_yaml

    assert "trivy-scan" in jobs
    trivy_steps_yaml = yaml.safe_dump(jobs["trivy-scan"]["steps"], width=4096)
    for expected in (
        "ai-gateway-api:ci",
        "ai-mcp-runtime:ci",
        "ai-mock-llm:ci",
        "--ignore-unfixed --severity CRITICAL,HIGH --exit-code 1",
        (
            "--ignore-unfixed --severity CRITICAL,HIGH --exit-code 0 "
            "--format sarif --output litellm-trivy.sarif ghcr.io/berriai/litellm:1.84.0"
        ),
        "actions/upload-artifact@v4",
        "litellm-trivy.sarif",
    ):
        assert expected in trivy_steps_yaml
