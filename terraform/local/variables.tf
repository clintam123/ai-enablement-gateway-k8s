variable "cluster_name" {
  description = "Name of the local Kind cluster."
  type        = string
  default     = "ai-enablement-gateway"
}

variable "kind_node_image" {
  description = "Optional Kind node image override (defaults to Kind CLI architecture-matched image)."
  type        = string
  default     = ""
}

variable "kubeconfig_path" {
  description = "Optional kubeconfig path override (defaults to standard ~/.kube/config)."
  type        = string
  default     = ""
}

variable "platform_namespace" {
  description = "Kubernetes namespace for the AI Enablement Gateway release."
  type        = string
  default     = "ai-gateway"
}

variable "traefik_namespace" {
  description = "Kubernetes namespace for the Traefik Ingress controller."
  type        = string
  default     = "traefik"
}

variable "calico_chart_version" {
  description = "Pinned Calico Helm chart version for CRDs and tigera-operator."
  type        = string
  default     = "v3.33.1"
}

variable "gateway_image_repository" {
  description = "Local Docker image repository for the Control Plane (gateway-api)."
  type        = string
  default     = "ai-gateway-api"
}

variable "gateway_image_tag" {
  description = "Local Docker image tag for the Control Plane (gateway-api)."
  type        = string
  default     = "dev"
}

variable "mock_llm_image_repository" {
  description = "Local Docker image repository for Mock Providers (mock-llm)."
  type        = string
  default     = "ai-mock-llm"
}

variable "mock_llm_image_tag" {
  description = "Local Docker image tag for Mock Providers (mock-llm)."
  type        = string
  default     = "dev"
}

variable "mcp_runtime_image_repository" {
  description = "Local Docker image repository for the Guarded MCP Runtime (mcp-runtime)."
  type        = string
  default     = "ai-mcp-runtime"
}

variable "mcp_runtime_image_tag" {
  description = "Local Docker image tag for the Guarded MCP Runtime (mcp-runtime)."
  type        = string
  default     = "dev"
}

variable "litellm_image" {
  description = "Pinned Model Router (LiteLLM Proxy) image pre-loaded into Kind when cached locally."
  type        = string
  default     = "ghcr.io/berriai/litellm:1.84.0"
}

variable "redis_image" {
  description = "Pinned Redis image pre-loaded into Kind when cached locally."
  type        = string
  default     = "redis:7.4.2-alpine"
}

variable "gateway_api_keys_json" {
  description = "JSON payload mapping SHA-256 sk-gw- API key digests to Actor metadata."
  type        = string
  default     = ""
  sensitive   = true
}

variable "gateway_jwks_json" {
  description = "JSON JWKS payload used by the Control Plane to verify RS256 JWT Credentials."
  type        = string
  default     = ""
  sensitive   = true
}

variable "litellm_master_key" {
  description = "Internal Model Router master key shared between gateway-api and litellm-proxy Secrets."
  type        = string
  default     = ""
  sensitive   = true
}

variable "internal_identity_secret" {
  description = "HS256 signing secret (>=32 bytes) shared between gateway-api and mcp-runtime Secrets."
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_observability" {
  description = "Deploy lightweight single-pod Prometheus, Grafana, and Jaeger OTLP observability stack."
  type        = bool
  default     = true
}

variable "observability_namespace" {
  description = "Kubernetes namespace for Prometheus, Grafana, and Jaeger workloads."
  type        = string
  default     = "observability"
}

variable "prometheus_image" {
  description = "Pinned Prometheus container image."
  type        = string
  default     = "prom/prometheus:v3.2.1"
}

variable "grafana_image" {
  description = "Pinned Grafana container image."
  type        = string
  default     = "grafana/grafana:11.5.2"
}

variable "jaeger_image" {
  description = "Pinned Jaeger v2 all-in-one OTLP container image."
  type        = string
  default     = "cr.jaegertracing.io/jaegertracing/jaeger:2.23.0"
}
