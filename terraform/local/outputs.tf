output "cluster_name" {
  description = "Name of the local Kind cluster."
  value       = kind_cluster.this.name
}

output "kubeconfig_path" {
  description = "Path to the kubeconfig file configured for the Kind cluster."
  value       = kind_cluster.this.kubeconfig_path
}

output "gateway_url" {
  description = "Local Control Plane base URL served through Traefik Ingress."
  value       = "http://localhost:8080"
}

output "platform_namespace" {
  description = "Kubernetes namespace hosting the AI Enablement Gateway release."
  value       = kubernetes_namespace_v1.ai_gateway.metadata[0].name
}

output "traefik_namespace" {
  description = "Kubernetes namespace hosting the Traefik Ingress controller."
  value       = kubernetes_namespace_v1.traefik.metadata[0].name
}

output "observability_enabled" {
  description = "Whether the lightweight observability stack is deployed."
  value       = var.enable_observability
}

output "observability_namespace" {
  description = "Kubernetes namespace hosting Prometheus, Grafana, and Jaeger when enabled."
  value       = var.enable_observability ? kubernetes_namespace_v1.observability[0].metadata[0].name : ""
}
