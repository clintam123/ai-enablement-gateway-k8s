output "cluster_name" {
  description = "Name of the ephemeral GKE Autopilot cluster."
  value       = google_container_cluster.autopilot.name
}

output "region" {
  description = "GCP region where the cluster and Artifact Registry are provisioned."
  value       = var.region
}

output "cluster_endpoint" {
  description = "Kubernetes API endpoint for the GKE Autopilot cluster."
  value       = "https://${google_container_cluster.autopilot.endpoint}"
}

output "artifact_registry_url" {
  description = "Docker Artifact Registry repository URL for pushing custom platform images."
  value       = local.registry_prefix
}

output "workload_identity_sa_email" {
  description = "GCP IAM service account email bound to the Control Plane Kubernetes ServiceAccount."
  value       = google_service_account.gateway_control_plane.email
}

output "platform_namespace" {
  description = "Kubernetes namespace hosting the AI Enablement Gateway release."
  value       = kubernetes_namespace_v1.ai_gateway.metadata[0].name
}

output "traefik_namespace" {
  description = "Kubernetes namespace hosting the Traefik Ingress controller."
  value       = kubernetes_namespace_v1.traefik.metadata[0].name
}

output "kubectl_credentials_command" {
  description = "Command to configure kubectl credentials for the GKE Autopilot cluster."
  value       = "gcloud container clusters get-credentials ${google_container_cluster.autopilot.name} --region ${var.region} --project ${var.project_id}"
}
