---
status: accepted
---

# Traefik Ingress Controller Instead of Archived Ingress-NGINX

Install Traefik in `terraform/local` to back the Helm chart's Kubernetes `Ingress` resource rather than community `kubernetes/ingress-nginx`, which reached end-of-life and was archived in March 2026. Traefik runs as a single lightweight pod on `kind`, provides a clean namespace selector for zero-trust `NetworkPolicy` ingress rules, and keeps the Helm chart portable across local `kind` and GKE without requiring Gateway API CRDs in `helm template` and `checkov` validation.

## Considered Options

- **Community `kubernetes/ingress-nginx`:** Archived in March 2026 with no further security patches.
- **Kubernetes Gateway API (`Gateway` + `HTTPRoute` via Envoy Gateway):** Modern CNCF long-term standard, but adds CRD lifecycle overhead on ephemeral `kind` clusters and extra `checkov` custom-resource handling for a single-service front door.

## Consequences

- Local traffic (`http://localhost:8080`) flows through a real, actively maintained Kubernetes `Ingress` controller while blocking `/metrics` from external exposure.
- Migrating to `HTTPRoute` later requires only swapping the single Ingress template in `deploy/helm/ai-enablement-platform`.
