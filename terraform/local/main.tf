provider "kubernetes" {
  host                   = kind_cluster.this.endpoint
  client_certificate     = kind_cluster.this.client_certificate
  client_key             = kind_cluster.this.client_key
  cluster_ca_certificate = kind_cluster.this.cluster_ca_certificate
}

provider "helm" {
  kubernetes = {
    host                   = kind_cluster.this.endpoint
    client_certificate     = kind_cluster.this.client_certificate
    client_key             = kind_cluster.this.client_key
    cluster_ca_certificate = kind_cluster.this.cluster_ca_certificate
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
}

resource "kind_cluster" "this" {
  name            = var.cluster_name
  node_image      = var.kind_node_image != "" ? var.kind_node_image : null
  kubeconfig_path = var.kubeconfig_path != "" ? var.kubeconfig_path : null
  wait_for_ready  = true

  kind_config {
    api_version = "kind.x-k8s.io/v1alpha4"
    kind        = "Cluster"

    networking {
      disable_default_cni = true
      pod_subnet          = "192.168.0.0/16"
    }

    node {
      role = "control-plane"

      extra_port_mappings {
        container_port = 30080
        host_port      = 8080
        listen_address = "127.0.0.1"
        protocol       = "TCP"
      }
    }
  }
}

resource "null_resource" "load_images" {
  depends_on = [kind_cluster.this]

  triggers = {
    cluster_id           = kind_cluster.this.id
    gateway_image        = "${var.gateway_image_repository}:${var.gateway_image_tag}"
    mock_image           = "${var.mock_llm_image_repository}:${var.mock_llm_image_tag}"
    mcp_runtime_image    = "${var.mcp_runtime_image_repository}:${var.mcp_runtime_image_tag}"
    litellm_image        = var.litellm_image
    redis_image          = var.redis_image
    enable_observability = tostring(var.enable_observability)
    prometheus_image     = var.prometheus_image
    grafana_image        = var.grafana_image
    jaeger_image         = var.jaeger_image
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-euo", "pipefail", "-c"]
    command     = <<-EOT
      CLUSTER_NAME="${kind_cluster.this.name}"
      load_image() {
        local img="$1"
        local required="$2"
        if [ "$required" = "false" ] && ! docker image inspect "$img" >/dev/null 2>&1; then
          return 0
        fi
        if kind load docker-image "$img" --name "$CLUSTER_NAME"; then
          return 0
        fi
        local arch
        arch="$(docker exec "$${CLUSTER_NAME}-control-plane" uname -m)"
        case "$arch" in
          x86_64) arch="amd64" ;;
          aarch64) arch="arm64" ;;
        esac
        if docker save --platform "linux/$${arch}" "$img" | docker exec -i "$${CLUSTER_NAME}-control-plane" ctr --namespace=k8s.io images import --snapshotter=overlayfs -; then
          return 0
        fi
        [ "$required" = "false" ]
      }

      load_image "${var.gateway_image_repository}:${var.gateway_image_tag}" "true"
      load_image "${var.mock_llm_image_repository}:${var.mock_llm_image_tag}" "true"
      load_image "${var.mcp_runtime_image_repository}:${var.mcp_runtime_image_tag}" "true"
      load_image "${var.litellm_image}" "false"
      load_image "${var.redis_image}" "false"
      if [ "${var.enable_observability}" = "true" ]; then
        load_image "${var.prometheus_image}" "false"
        load_image "${var.grafana_image}" "false"
        load_image "${var.jaeger_image}" "false"
      fi
    EOT
  }
}

resource "kubernetes_namespace_v1" "tigera_operator" {
  depends_on = [kind_cluster.this]

  metadata {
    name = "tigera-operator"
    labels = {
      "kubernetes.io/metadata.name" = "tigera-operator"
    }
  }
}

resource "null_resource" "calico_crds" {
  depends_on = [kubernetes_namespace_v1.tigera_operator]

  triggers = {
    cluster_id     = kind_cluster.this.id
    calico_version = var.calico_chart_version
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-euo", "pipefail", "-c"]
    command     = <<-EOT
      export KUBECONFIG="${kind_cluster.this.kubeconfig_path}"
      helm template calico-crds crd.projectcalico.org.v1 \
        --repo https://docs.tigera.io/calico/charts \
        --version "${var.calico_chart_version}" \
        | kubectl apply --server-side -f -
    EOT
  }
}

resource "helm_release" "calico" {
  depends_on = [null_resource.calico_crds]

  name       = "calico"
  repository = "https://docs.tigera.io/calico/charts"
  chart      = "tigera-operator"
  version    = var.calico_chart_version
  namespace  = kubernetes_namespace_v1.tigera_operator.metadata[0].name
  wait       = true
  timeout    = 600

  values = [
    yamlencode({
      installation = {
        enabled              = true
        kubernetesProvider   = "Kind"
        controlPlaneReplicas = 1
      }
      goldmane = {
        enabled = false
      }
      whisker = {
        enabled = false
      }
    })
  ]
}

resource "null_resource" "wait_calico" {
  depends_on = [helm_release.calico]

  triggers = {
    cluster_id = kind_cluster.this.id
    release_id = helm_release.calico.id
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-euo", "pipefail", "-c"]
    command     = <<-EOT
      export KUBECONFIG="${kind_cluster.this.kubeconfig_path}"
      kubectl wait --for=condition=Available deployment/tigera-operator -n tigera-operator --timeout=180s
      for _ in $(seq 1 90); do
        if kubectl get daemonset/calico-node -n calico-system >/dev/null 2>&1 \
          && kubectl get deployment/calico-kube-controllers -n calico-system >/dev/null 2>&1; then
          break
        fi
        sleep 2
      done
      kubectl rollout status daemonset/calico-node -n calico-system --timeout=300s
      kubectl wait --for=condition=Available deployment/calico-kube-controllers -n calico-system --timeout=300s
      kubectl wait --for=condition=Ready nodes --all --timeout=180s
      kubectl rollout status deployment/coredns -n kube-system --timeout=180s
    EOT
  }
}

resource "helm_release" "metrics_server" {
  depends_on = [null_resource.wait_calico]

  name       = "metrics-server"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  namespace  = "kube-system"
  wait       = true
  timeout    = 300

  values = [
    yamlencode({
      replicas = 1
      args     = ["--kubelet-insecure-tls"]
    })
  ]
}

resource "kubernetes_namespace_v1" "traefik" {
  depends_on = [null_resource.wait_calico]

  metadata {
    name = var.traefik_namespace
    labels = {
      "kubernetes.io/metadata.name" = var.traefik_namespace
    }
  }
}

resource "helm_release" "traefik" {
  depends_on = [kubernetes_namespace_v1.traefik, null_resource.wait_calico]

  name       = "traefik"
  repository = "https://traefik.github.io/charts"
  chart      = "traefik"
  namespace  = kubernetes_namespace_v1.traefik.metadata[0].name
  wait       = true
  timeout    = 300

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
          type = "NodePort"
        }
      }
      ports = {
        web = {
          nodePort = 30080
        }
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
          cpu    = "300m"
          memory = "256Mi"
        }
      }
    })
  ]
}

resource "kubernetes_namespace_v1" "ai_gateway" {
  depends_on = [null_resource.wait_calico]

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

resource "helm_release" "ai_gateway" {
  depends_on = [
    null_resource.load_images,
    null_resource.wait_calico,
    helm_release.metrics_server,
    helm_release.traefik,
    kubernetes_secret_v1.gateway_credentials,
    kubernetes_secret_v1.mcp_credentials,
    kubernetes_secret_v1.router_credentials,
    kubernetes_namespace_v1.observability,
    kubernetes_deployment_v1.prometheus,
    kubernetes_deployment_v1.grafana,
    kubernetes_deployment_v1.jaeger,
    kubernetes_service_v1.prometheus,
    kubernetes_service_v1.grafana,
    kubernetes_service_v1.jaeger,
    kubernetes_network_policy_v1.default_deny,
    kubernetes_network_policy_v1.dns_egress,
    kubernetes_network_policy_v1.prometheus,
    kubernetes_network_policy_v1.grafana,
    kubernetes_network_policy_v1.jaeger,
  ]

  name      = "ai-gateway"
  chart     = "${path.module}/../../deploy/helm/ai-enablement-platform"
  namespace = kubernetes_namespace_v1.ai_gateway.metadata[0].name
  wait      = true
  timeout   = 600

  values = [
    yamlencode({
      gatewayApi = {
        image = {
          repository = var.gateway_image_repository
          tag        = var.gateway_image_tag
          pullPolicy = "IfNotPresent"
        }
      }
      mockLlm = {
        image = {
          repository = var.mock_llm_image_repository
          tag        = var.mock_llm_image_tag
          pullPolicy = "IfNotPresent"
        }
      }
      mcpRuntime = {
        image = {
          repository = var.mcp_runtime_image_repository
          tag        = var.mcp_runtime_image_tag
          pullPolicy = "IfNotPresent"
        }
      }
      observability = {
        otlpEndpoint = (
          var.enable_observability
          ? "http://jaeger.${var.observability_namespace}.svc.cluster.local:4318"
          : ""
        )
        prometheusScrape = var.enable_observability
      }
      networkPolicy = {
        allowObservabilityScrape = var.enable_observability
        observabilityNamespaceSelector = {
          "kubernetes.io/metadata.name" = var.observability_namespace
        }
        allowOtlpEgress = var.enable_observability
      }
    })
  ]
}
