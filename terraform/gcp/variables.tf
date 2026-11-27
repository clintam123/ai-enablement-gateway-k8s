variable "project_id" {
  description = "GCP project ID where the ephemeral GKE Autopilot cluster and Artifact Registry live."
  type        = string
}

variable "region" {
  description = "Single GCP region for the VPC, Artifact Registry, and GKE Autopilot cluster."
  type        = string
  default     = "us-central1"
}

variable "cluster_name" {
  description = "Name of the ephemeral GKE Autopilot cluster."
  type        = string
  default     = "ai-enablement-gateway-gcp"
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

variable "artifact_registry_repo" {
  description = "Docker Artifact Registry repository ID for Control Plane, MCP Runtime, and Mock Provider images."
  type        = string
  default     = "ai-enablement-gateway"
}

variable "image_tag" {
  description = "Container image tag pushed to Artifact Registry for custom platform images."
  type        = string
  default     = "dev"
}

variable "gateway_image_name" {
  description = "Image name in Artifact Registry for the Control Plane (gateway-api)."
  type        = string
  default     = "ai-gateway-api"
}

variable "mcp_runtime_image_name" {
  description = "Image name in Artifact Registry for the Guarded MCP Runtime (mcp-runtime)."
  type        = string
  default     = "ai-mcp-runtime"
}

variable "mock_llm_image_name" {
  description = "Image name in Artifact Registry for the Mock Provider (mock-llm)."
  type        = string
  default     = "ai-mock-llm"
}

variable "litellm_image_repository" {
  description = "Pinned upstream Model Router (LiteLLM Proxy) repository."
  type        = string
  default     = "ghcr.io/berriai/litellm"
}

variable "litellm_image_tag" {
  description = "Pinned upstream Model Router (LiteLLM Proxy) tag."
  type        = string
  default     = "1.84.0"
}

variable "redis_image_repository" {
  description = "Pinned Redis image repository."
  type        = string
  default     = "redis"
}

variable "redis_image_tag" {
  description = "Pinned Redis image tag."
  type        = string
  default     = "7.4.2-alpine"
}

variable "enable_project_services" {
  description = "Enable required GCP APIs via google_project_service (set false if APIs are pre-enabled)."
  type        = bool
  default     = true
}

variable "gateway_service_account_name" {
  description = "Kubernetes ServiceAccount name for the Control Plane bound to the GCP IAM service account."
  type        = string
  default     = "ai-gateway-gateway-api"
}

variable "control_plane_gcp_sa_id" {
  description = "GCP IAM service account ID bound via Workload Identity to the Control Plane ServiceAccount."
  type        = string
  default     = "ai-gateway-control-plane"
}

variable "vpc_subnet_cidr" {
  description = "Primary IPv4 CIDR range for the GKE Autopilot subnetwork."
  type        = string
  default     = "10.10.0.0/20"
}

variable "pods_secondary_cidr" {
  description = "Secondary IPv4 CIDR range for GKE Autopilot pods."
  type        = string
  default     = "10.20.0.0/16"
}

variable "services_secondary_cidr" {
  description = "Secondary IPv4 CIDR range for GKE Autopilot services."
  type        = string
  default     = "10.24.0.0/20"
}

variable "master_ipv4_cidr_block" {
  description = "Private /28 IPv4 CIDR range for the GKE control plane VPC peering."
  type        = string
  default     = "172.16.0.0/28"
}

variable "master_authorized_cidr_blocks" {
  description = "Authorized CIDR blocks allowed to reach the GKE control plane endpoint."
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = []
}

variable "enable_gemini_provider" {
  description = "Enable optional Google Gemini external Provider egress and Secret wiring (default false keeps $0 Mock Providers)."
  type        = bool
  default     = false
}

variable "gemini_api_key" {
  description = "Optional Google Gemini API key stored in ai-gateway-provider-keys when enable_gemini_provider is true."
  type        = string
  default     = ""
  sensitive   = true
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
