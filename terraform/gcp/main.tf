provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = "https://${google_container_cluster.autopilot.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.autopilot.master_auth[0].cluster_ca_certificate)
}

provider "helm" {
  kubernetes = {
    host                   = "https://${google_container_cluster.autopilot.endpoint}"
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(google_container_cluster.autopilot.master_auth[0].cluster_ca_certificate)
  }
}

resource "random_password" "litellm_master_key_fallback" {
  length  = 24
  special = false
}

resource "random_password" "internal_identity_secret_fallback" {
  length  = 48
  special = false
}

resource "tls_private_key" "ephemeral_fallback" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

locals {
  required_services = var.enable_project_services ? toset([
    "artifactregistry.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
  ]) : toset([])

  registry_prefix = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.containers.repository_id}"

  effective_api_keys_json = (
    var.gateway_api_keys_json != ""
    ? var.gateway_api_keys_json
    : jsonencode({ api_keys = {} })
  )
  effective_jwks_json = var.gateway_jwks_json
  effective_litellm_master_key = (
    var.litellm_master_key != ""
    ? var.litellm_master_key
    : "sk-litellm-${random_password.litellm_master_key_fallback.result}"
  )
  effective_internal_identity_secret = (
    var.internal_identity_secret != ""
    ? var.internal_identity_secret
    : random_password.internal_identity_secret_fallback.result
  )
  fallback_public_key_sha256 = sha256(tls_private_key.ephemeral_fallback.public_key_pem)
  wire_gemini_provider       = var.enable_gemini_provider && var.gemini_api_key != ""
  litellm_gemini_config_yaml = yamlencode({
    model_list = [
      {
        model_name = "chat-default"
        litellm_params = {
          model   = "gemini/gemini-2.5-flash"
          api_key = "os.environ/GEMINI_API_KEY"
        }
        model_info = {
          id = "chat-default-gemini"
        }
      },
      {
        model_name = "chat-fast"
        litellm_params = {
          model    = "openai/chat-fast"
          api_base = "http://mock-llm-primary:8000/v1"
          api_key  = "mock-unused"
        }
        model_info = {
          id = "chat-fast-primary"
        }
      },
      {
        model_name = "chat-premium"
        litellm_params = {
          model    = "openai/chat-premium"
          api_base = "http://mock-llm-primary:8000/v1"
          api_key  = "mock-unused"
        }
        model_info = {
          id = "chat-premium-primary"
        }
      },
      {
        model_name = "chat-default-fallback"
        litellm_params = {
          model    = "openai/chat-default"
          api_base = "http://mock-llm-fallback:8000/v1"
          api_key  = "mock-unused"
        }
        model_info = {
          id = "chat-default-fallback"
        }
      },
      {
        model_name = "chat-fast-fallback"
        litellm_params = {
          model    = "openai/chat-fast"
          api_base = "http://mock-llm-fallback:8000/v1"
          api_key  = "mock-unused"
        }
        model_info = {
          id = "chat-fast-fallback"
        }
      },
      {
        model_name = "chat-premium-fallback"
        litellm_params = {
          model    = "openai/chat-premium"
          api_base = "http://mock-llm-fallback:8000/v1"
          api_key  = "mock-unused"
        }
        model_info = {
          id = "chat-premium-fallback"
        }
      },
    ]
    litellm_settings = {
      drop_params     = true
      num_retries     = 2
      request_timeout = 15
      fallbacks = [
        { "chat-default" = ["chat-default-fallback"] },
        { "chat-fast" = ["chat-fast-fallback"] },
        { "chat-premium" = ["chat-premium-fallback"] },
      ]
    }
    router_settings = {
      routing_strategy = "simple-shuffle"
      num_retries      = 2
      timeout          = 15
      allowed_fails    = 3
      cooldown_time    = 30
    }
    general_settings = {
      master_key                  = "os.environ/LITELLM_MASTER_KEY"
      always_include_stream_usage = true
    }
  })
}

resource "google_project_service" "required" {
  for_each = local.required_services

  project                    = var.project_id
  service                    = each.value
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_compute_network" "vpc" {
  name                    = "${var.cluster_name}-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.required]
}

resource "google_compute_firewall" "allow_internal" {
  name    = "${var.cluster_name}-allow-internal"
  network = google_compute_network.vpc.name

  direction = "INGRESS"
  priority  = 1000

  source_ranges = [
    var.vpc_subnet_cidr,
    var.pods_secondary_cidr,
    var.services_secondary_cidr,
  ]

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }
}

resource "google_compute_firewall" "deny_all_ingress" {
  name    = "${var.cluster_name}-deny-all-ingress"
  network = google_compute_network.vpc.name

  direction = "INGRESS"
  priority  = 65534

  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}

resource "google_compute_subnetwork" "gke" {
  name                     = "${var.cluster_name}-subnet"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = var.vpc_subnet_cidr
  private_ip_google_access = true
  stack_type               = "IPV4_ONLY"

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_secondary_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_secondary_cidr
  }
}

resource "google_compute_router" "nat" {
  name    = "${var.cluster_name}-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.cluster_name}-nat"
  router                             = google_compute_router.nat.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

resource "google_artifact_registry_repository" "containers" {
  #checkov:skip=CKV_GCP_84:Ephemeral Artifact Registry uses Google-managed encryption keys to stay under $10/month without persistent KMS key rings
  location      = var.region
  repository_id = var.artifact_registry_repo
  description   = "Container images for AI Enablement Gateway (Control Plane, MCP Runtime, Mock Provider)"
  format        = "DOCKER"

  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "keep-recent-versions"
    action = "KEEP"

    most_recent_versions {
      keep_count = 5
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_container_cluster" "autopilot" {
  #checkov:skip=CKV_GCP_12:GKE Autopilot enables Dataplane V2 NetworkPolicy natively and rejects Standard network_policy blocks
  #checkov:skip=CKV_GCP_61:Subnet VPC Flow Logs are enabled and GKE Autopilot enforces intranode visibility natively while rejecting enable_intranode_visibility
  #checkov:skip=CKV_GCP_65:Ephemeral demo cluster has no Google Workspace domain group; Workload Identity and K8s RBAC enforce access
  #checkov:skip=CKV_GCP_66:Trivy image CVE gates enforce build-time image integrity without requiring Binary Authorization KMS attestors
  #checkov:skip=CKV_GCP_69:GKE Autopilot enables the GKE Metadata Server automatically and rejects Standard node_config blocks
  name                = var.cluster_name
  location            = var.region
  enable_autopilot    = true
  network             = google_compute_network.vpc.id
  subnetwork          = google_compute_subnetwork.gke.id
  deletion_protection = false

  resource_labels = {
    app        = "ai-enablement-gateway"
    managed-by = "terraform"
  }

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = google_compute_subnetwork.gke.secondary_ip_range[0].range_name
    services_secondary_range_name = google_compute_subnetwork.gke.secondary_ip_range[1].range_name
  }

  release_channel {
    channel = "REGULAR"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = var.master_ipv4_cidr_block
  }

  master_authorized_networks_config {
    dynamic "cidr_blocks" {
      for_each = var.master_authorized_cidr_blocks
      content {
        cidr_block   = cidr_blocks.value.cidr_block
        display_name = cidr_blocks.value.display_name
      }
    }
  }

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }

  depends_on = [
    google_project_service.required,
    google_compute_router_nat.nat,
  ]

  lifecycle {
    precondition {
      condition     = length(var.master_authorized_cidr_blocks) > 0
      error_message = "At least one authorized CIDR block is required in master_authorized_cidr_blocks so kubectl, Helm, and Terraform can reach the GKE control plane endpoint (pass GCP_AUTHORIZED_CIDRS or use make gcp-up)."
    }
  }
}

resource "google_service_account" "gateway_control_plane" {
  account_id   = var.control_plane_gcp_sa_id
  display_name = "AI Enablement Gateway Control Plane"
  description  = "Minimal Workload Identity service account for the Control Plane Deployment"

  depends_on = [google_project_service.required]
}

resource "google_service_account_iam_member" "gateway_workload_identity" {
  service_account_id = google_service_account.gateway_control_plane.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.platform_namespace}/${var.gateway_service_account_name}]"
}

resource "kubernetes_namespace_v1" "traefik" {
  depends_on = [google_container_cluster.autopilot]

  metadata {
    name = var.traefik_namespace
    labels = {
      "kubernetes.io/metadata.name" = var.traefik_namespace
    }
  }
}

resource "helm_release" "traefik" {
  depends_on = [kubernetes_namespace_v1.traefik]

  name       = "traefik"
  repository = "https://traefik.github.io/charts"
  chart      = "traefik"
  namespace  = kubernetes_namespace_v1.traefik.metadata[0].name
  wait       = true
  timeout    = 600

  values = [
    yamlencode({
      deployment = {
        replicas = 1
      }
      ingressClass = {
        enabled        = true
        isDefaultClass = true
        name           = "traefik"
      }
      providers = {
        kubernetesIngress = {
          ingressClass = "traefik"
        }
        kubernetesCRD = {
          ingressClass = "traefik"
        }
      }
      service = {
        spec = {
          type = "LoadBalancer"
        }
      }
      ports = {
        websecure = {
          expose = {
            default = false
          }
        }
      }
      resources = {
        requests = {
          cpu    = "50m"
          memory = "64Mi"
        }
        limits = {
          cpu    = "250m"
          memory = "256Mi"
        }
      }
    })
  ]
}

resource "kubernetes_namespace_v1" "ai_gateway" {
  depends_on = [google_container_cluster.autopilot]

  metadata {
    name = var.platform_namespace
    labels = {
      "kubernetes.io/metadata.name" = var.platform_namespace
    }
  }
}

resource "kubernetes_secret_v1" "gateway_credentials" {
  metadata {
    name      = "ai-gateway-credentials"
    namespace = kubernetes_namespace_v1.ai_gateway.metadata[0].name
    annotations = {
      "ai-gateway/fallback-fingerprint" = local.fallback_public_key_sha256
    }
  }

  data = {
    "api-keys.json"            = local.effective_api_keys_json
    "jwks.json"                = local.effective_jwks_json
    "litellm-master-key"       = local.effective_litellm_master_key
    "internal-identity-secret" = local.effective_internal_identity_secret
  }
}

resource "kubernetes_secret_v1" "mcp_credentials" {
  metadata {
    name      = "ai-gateway-mcp-credentials"
    namespace = kubernetes_namespace_v1.ai_gateway.metadata[0].name
  }

  data = {
    "internal-identity-secret" = local.effective_internal_identity_secret
  }
}

resource "kubernetes_secret_v1" "router_credentials" {
  metadata {
    name      = "ai-gateway-router-credentials"
    namespace = kubernetes_namespace_v1.ai_gateway.metadata[0].name
  }

  data = {
    "litellm-master-key" = local.effective_litellm_master_key
  }
}

resource "kubernetes_secret_v1" "provider_keys" {
  count = local.wire_gemini_provider ? 1 : 0

  metadata {
    name      = "ai-gateway-provider-keys"
    namespace = kubernetes_namespace_v1.ai_gateway.metadata[0].name
  }

  data = {
    "GEMINI_API_KEY" = var.gemini_api_key
  }
}

resource "helm_release" "ai_gateway" {
  depends_on = [
    helm_release.traefik,
    google_service_account_iam_member.gateway_workload_identity,
    kubernetes_secret_v1.gateway_credentials,
    kubernetes_secret_v1.mcp_credentials,
    kubernetes_secret_v1.router_credentials,
    kubernetes_secret_v1.provider_keys,
  ]

  name      = "ai-gateway"
  chart     = "${path.module}/../../deploy/helm/ai-enablement-platform"
  namespace = kubernetes_namespace_v1.ai_gateway.metadata[0].name
  wait      = true
  timeout   = 600

  values = [
    yamlencode({
      configMaps = {
        litellmConfigOverride = (
          local.wire_gemini_provider
          ? local.litellm_gemini_config_yaml
          : ""
        )
      }
      secrets = {
        router = {
          providerKeysExistingSecret = (
            local.wire_gemini_provider
            ? kubernetes_secret_v1.provider_keys[0].metadata[0].name
            : ""
          )
        }
      }
      gatewayApi = {
        image = {
          repository = "${local.registry_prefix}/${var.gateway_image_name}"
          tag        = var.image_tag
          pullPolicy = "Always"
        }
        serviceAccount = {
          annotations = {
            "iam.gke.io/gcp-service-account" = google_service_account.gateway_control_plane.email
          }
        }
        autoscaling = {
          enabled     = true
          minReplicas = 1
          maxReplicas = 2
        }
        resources = {
          requests = {
            cpu    = "100m"
            memory = "128Mi"
          }
          limits = {
            cpu    = "300m"
            memory = "384Mi"
          }
        }
      }
      mcpRuntime = {
        image = {
          repository = "${local.registry_prefix}/${var.mcp_runtime_image_name}"
          tag        = var.image_tag
          pullPolicy = "Always"
        }
        resources = {
          requests = {
            cpu    = "100m"
            memory = "128Mi"
          }
          limits = {
            cpu    = "300m"
            memory = "384Mi"
          }
        }
      }
      litellmProxy = {
        image = {
          repository = var.litellm_image_repository
          tag        = var.litellm_image_tag
          pullPolicy = "IfNotPresent"
        }
        resources = {
          requests = {
            cpu    = "250m"
            memory = "1Gi"
          }
          limits = {
            cpu    = "500m"
            memory = "1536Mi"
          }
        }
      }
      mockLlm = {
        image = {
          repository = "${local.registry_prefix}/${var.mock_llm_image_name}"
          tag        = var.image_tag
          pullPolicy = "Always"
        }
        resources = {
          requests = {
            cpu    = "50m"
            memory = "64Mi"
          }
          limits = {
            cpu    = "200m"
            memory = "256Mi"
          }
        }
      }
      redis = {
        image = {
          repository = var.redis_image_repository
          tag        = var.redis_image_tag
          pullPolicy = "IfNotPresent"
        }
        resources = {
          requests = {
            cpu    = "50m"
            memory = "64Mi"
          }
          limits = {
            cpu    = "200m"
            memory = "256Mi"
          }
        }
      }
      observability = {
        otlpEndpoint     = ""
        prometheusScrape = false
      }
      networkPolicy = {
        allowObservabilityScrape    = false
        allowOtlpEgress             = false
        allowExternalProviderEgress = var.enable_gemini_provider
      }
    })
  ]
}
