---
status: accepted
---

# Ephemeral GKE Autopilot Target Instead of AWS EKS

Standardize cloud Terraform on `terraform/gcp` provisioning a single-region GKE Autopilot cluster, VPC, Artifact Registry, Workload Identity, and Helm release—dropping `terraform/aws-eks`. An existing $10/month GCP credit plus Gemini API access makes GKE Autopilot both CI-validated (`terraform validate` + `checkov`) and genuinely deployable for short-lived `apply → smoke test → destroy` verification runs, whereas an AWS EKS module could never be live-tested under a $0 spend constraint.

## Considered Options

- **Validate-only `terraform/aws-eks`:** Matches AWS-heavy job descriptions, but cannot be live-tested at $0 and risks silent runtime drift.
- **Maintain both `terraform/gcp` and `terraform/aws-eks`:** Doubles Terraform maintenance and CI surface without adding architectural depth.

## Consequences

- `terraform/gcp` must stay lean with minimal pod resource requests and one-command teardown (`make gcp-down`) so ephemeral runs stay comfortably under $10/month.
- Optional Gemini API credentials can be wired via Kubernetes `Secret` to demonstrate real provider routing alongside the default `$0` `mock-llm`.
