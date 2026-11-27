locals {
  observability_prometheus_yml = replace(
    file("${path.module}/../../deploy/observability/prometheus/prometheus.yml"),
    "ai-gateway-gateway-api-headless.ai-gateway.svc.cluster.local",
    "ai-gateway-gateway-api-headless.${var.platform_namespace}.svc.cluster.local",
  )
  observability_slo_alerts_yml = file("${path.module}/../../deploy/observability/prometheus/slo-alerts.yml")
  observability_grafana_datasources_yaml = replace(
    replace(
      file("${path.module}/../../deploy/observability/grafana/datasources.yaml"),
      "prometheus.observability.svc.cluster.local",
      "prometheus.${var.observability_namespace}.svc.cluster.local",
    ),
    "jaeger.observability.svc.cluster.local",
    "jaeger.${var.observability_namespace}.svc.cluster.local",
  )
  observability_grafana_provider_yaml  = file("${path.module}/../../deploy/observability/grafana/dashboards-provider.yaml")
  observability_grafana_dashboard_json = file("${path.module}/../../deploy/observability/grafana/dashboards/ai-gateway-overview.json")
}

resource "kubernetes_namespace_v1" "observability" {
  count      = var.enable_observability ? 1 : 0
  depends_on = [null_resource.wait_calico]

  metadata {
    name = var.observability_namespace
    labels = {
      "kubernetes.io/metadata.name" = var.observability_namespace
    }
  }
}

resource "kubernetes_config_map_v1" "prometheus_config" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "prometheus-config"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
  }

  data = {
    "prometheus.yml" = local.observability_prometheus_yml
  }
}

resource "kubernetes_config_map_v1" "prometheus_rules" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "prometheus-rules"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
  }

  data = {
    "slo-alerts.yml" = local.observability_slo_alerts_yml
  }
}

resource "kubernetes_config_map_v1" "grafana_provisioning" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "grafana-provisioning"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
  }

  data = {
    "datasources.yaml" = local.observability_grafana_datasources_yaml
    "dashboards.yaml"  = local.observability_grafana_provider_yaml
  }
}

resource "kubernetes_config_map_v1" "grafana_dashboards" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "grafana-dashboards"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
  }

  data = {
    "ai-gateway-overview.json" = local.observability_grafana_dashboard_json
  }
}

resource "kubernetes_service_account_v1" "prometheus" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "prometheus"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
    labels = {
      "app.kubernetes.io/name"      = "prometheus"
      "app.kubernetes.io/component" = "prometheus"
    }
  }

  automount_service_account_token = false
}

resource "kubernetes_service_account_v1" "grafana" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "grafana"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
    labels = {
      "app.kubernetes.io/name"      = "grafana"
      "app.kubernetes.io/component" = "grafana"
    }
  }

  automount_service_account_token = false
}

resource "kubernetes_service_account_v1" "jaeger" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "jaeger"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
    labels = {
      "app.kubernetes.io/name"      = "jaeger"
      "app.kubernetes.io/component" = "jaeger"
    }
  }

  automount_service_account_token = false
}

resource "kubernetes_deployment_v1" "prometheus" {
  #checkov:skip=CKV_K8S_43:Prometheus image is parameterized and pinned by version tag in variables.tf
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "prometheus"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
    labels = {
      "app.kubernetes.io/name"      = "prometheus"
      "app.kubernetes.io/component" = "prometheus"
      "app.kubernetes.io/part-of"   = "ai-enablement-platform"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        "app.kubernetes.io/component" = "prometheus"
      }
    }

    template {
      metadata {
        labels = {
          "app.kubernetes.io/name"      = "prometheus"
          "app.kubernetes.io/component" = "prometheus"
          "app.kubernetes.io/part-of"   = "ai-enablement-platform"
        }
        annotations = {
          "checksum/config" = sha256("${local.observability_prometheus_yml}${local.observability_slo_alerts_yml}")
        }
      }

      spec {
        service_account_name            = kubernetes_service_account_v1.prometheus[0].metadata[0].name
        automount_service_account_token = false

        security_context {
          run_as_non_root = true
          run_as_user     = 65534
          run_as_group    = 65534
          fs_group        = 65534

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "prometheus"
          image             = var.prometheus_image
          image_pull_policy = "IfNotPresent"

          args = [
            "--config.file=/etc/prometheus/prometheus.yml",
            "--storage.tsdb.path=/prometheus",
            "--storage.tsdb.retention.time=2d",
          ]

          security_context {
            run_as_non_root            = true
            run_as_user                = 65534
            run_as_group               = 65534
            read_only_root_filesystem  = true
            allow_privilege_escalation = false

            capabilities {
              drop = ["ALL"]
            }
          }

          port {
            name           = "http"
            container_port = 9090
            protocol       = "TCP"
          }

          liveness_probe {
            http_get {
              path = "/-/healthy"
              port = 9090
            }
            initial_delay_seconds = 10
            period_seconds        = 15
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/-/ready"
              port = 9090
            }
            initial_delay_seconds = 5
            period_seconds        = 5
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "192Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }

          volume_mount {
            name       = "prometheus-config"
            mount_path = "/etc/prometheus/prometheus.yml"
            sub_path   = "prometheus.yml"
            read_only  = true
          }

          volume_mount {
            name       = "prometheus-rules"
            mount_path = "/etc/prometheus/rules"
            read_only  = true
          }

          volume_mount {
            name       = "prometheus-data"
            mount_path = "/prometheus"
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }

        volume {
          name = "prometheus-config"
          config_map {
            name = kubernetes_config_map_v1.prometheus_config[0].metadata[0].name
          }
        }

        volume {
          name = "prometheus-rules"
          config_map {
            name = kubernetes_config_map_v1.prometheus_rules[0].metadata[0].name
          }
        }

        volume {
          name = "prometheus-data"
          empty_dir {
            size_limit = "512Mi"
          }
        }

        volume {
          name = "tmp"
          empty_dir {
            size_limit = "32Mi"
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "prometheus" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "prometheus"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
    labels = {
      "app.kubernetes.io/name"      = "prometheus"
      "app.kubernetes.io/component" = "prometheus"
      "app.kubernetes.io/part-of"   = "ai-enablement-platform"
    }
  }

  spec {
    type = "ClusterIP"

    selector = {
      "app.kubernetes.io/component" = "prometheus"
    }

    port {
      name        = "http"
      port        = 9090
      target_port = 9090
      protocol    = "TCP"
    }
  }
}

resource "kubernetes_deployment_v1" "grafana" {
  #checkov:skip=CKV_K8S_40:Official grafana/grafana image runs as built-in grafana user UID 472
  #checkov:skip=CKV_K8S_43:Grafana image is parameterized and pinned by version tag in variables.tf
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "grafana"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
    labels = {
      "app.kubernetes.io/name"      = "grafana"
      "app.kubernetes.io/component" = "grafana"
      "app.kubernetes.io/part-of"   = "ai-enablement-platform"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        "app.kubernetes.io/component" = "grafana"
      }
    }

    template {
      metadata {
        labels = {
          "app.kubernetes.io/name"      = "grafana"
          "app.kubernetes.io/component" = "grafana"
          "app.kubernetes.io/part-of"   = "ai-enablement-platform"
        }
        annotations = {
          "checksum/provisioning" = sha256("${local.observability_grafana_datasources_yaml}${local.observability_grafana_provider_yaml}${local.observability_grafana_dashboard_json}")
        }
      }

      spec {
        service_account_name            = kubernetes_service_account_v1.grafana[0].metadata[0].name
        automount_service_account_token = false

        security_context {
          run_as_non_root = true
          run_as_user     = 472
          run_as_group    = 472
          fs_group        = 472

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "grafana"
          image             = var.grafana_image
          image_pull_policy = "IfNotPresent"

          security_context {
            run_as_non_root            = true
            run_as_user                = 472
            run_as_group               = 472
            read_only_root_filesystem  = true
            allow_privilege_escalation = false

            capabilities {
              drop = ["ALL"]
            }
          }

          port {
            name           = "http"
            container_port = 3000
            protocol       = "TCP"
          }

          env {
            name  = "GF_AUTH_ANONYMOUS_ENABLED"
            value = "true"
          }

          env {
            name  = "GF_AUTH_ANONYMOUS_ORG_ROLE"
            value = "Viewer"
          }

          env {
            name  = "GF_PATHS_DATA"
            value = "/var/lib/grafana"
          }

          env {
            name  = "GF_PATHS_PROVISIONING"
            value = "/etc/grafana/provisioning"
          }

          env {
            name  = "GF_PATHS_LOGS"
            value = "/tmp/grafana-logs"
          }

          env {
            name  = "GF_LOG_MODE"
            value = "console"
          }

          env {
            name  = "GF_ANALYTICS_REPORTING_ENABLED"
            value = "false"
          }

          env {
            name  = "GF_ANALYTICS_CHECK_FOR_UPDATES"
            value = "false"
          }

          env {
            name  = "GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES"
            value = "false"
          }

          env {
            name  = "GF_PLUGINS_PREINSTALL_DISABLED"
            value = "true"
          }

          liveness_probe {
            http_get {
              path = "/api/health"
              port = 3000
            }
            initial_delay_seconds = 10
            period_seconds        = 15
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/api/health"
              port = 3000
            }
            initial_delay_seconds = 5
            period_seconds        = 5
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "384Mi"
            }
          }

          volume_mount {
            name       = "grafana-data"
            mount_path = "/var/lib/grafana"
          }

          volume_mount {
            name       = "grafana-dashboards"
            mount_path = "/var/lib/grafana/dashboards"
            read_only  = true
          }

          volume_mount {
            name       = "grafana-provisioning"
            mount_path = "/etc/grafana/provisioning/datasources/datasources.yaml"
            sub_path   = "datasources.yaml"
            read_only  = true
          }

          volume_mount {
            name       = "grafana-provisioning"
            mount_path = "/etc/grafana/provisioning/dashboards/dashboards.yaml"
            sub_path   = "dashboards.yaml"
            read_only  = true
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }

        volume {
          name = "grafana-data"
          empty_dir {
            size_limit = "256Mi"
          }
        }

        volume {
          name = "grafana-dashboards"
          config_map {
            name = kubernetes_config_map_v1.grafana_dashboards[0].metadata[0].name
          }
        }

        volume {
          name = "grafana-provisioning"
          config_map {
            name = kubernetes_config_map_v1.grafana_provisioning[0].metadata[0].name
          }
        }

        volume {
          name = "tmp"
          empty_dir {
            size_limit = "64Mi"
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "grafana" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "grafana"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
    labels = {
      "app.kubernetes.io/name"      = "grafana"
      "app.kubernetes.io/component" = "grafana"
      "app.kubernetes.io/part-of"   = "ai-enablement-platform"
    }
  }

  spec {
    type = "ClusterIP"

    selector = {
      "app.kubernetes.io/component" = "grafana"
    }

    port {
      name        = "http"
      port        = 3000
      target_port = 3000
      protocol    = "TCP"
    }
  }
}

resource "kubernetes_deployment_v1" "jaeger" {
  #checkov:skip=CKV_K8S_43:Jaeger image is parameterized and pinned by version tag in variables.tf
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "jaeger"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
    labels = {
      "app.kubernetes.io/name"      = "jaeger"
      "app.kubernetes.io/component" = "jaeger"
      "app.kubernetes.io/part-of"   = "ai-enablement-platform"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        "app.kubernetes.io/component" = "jaeger"
      }
    }

    template {
      metadata {
        labels = {
          "app.kubernetes.io/name"      = "jaeger"
          "app.kubernetes.io/component" = "jaeger"
          "app.kubernetes.io/part-of"   = "ai-enablement-platform"
        }
      }

      spec {
        service_account_name            = kubernetes_service_account_v1.jaeger[0].metadata[0].name
        automount_service_account_token = false

        security_context {
          run_as_non_root = true
          run_as_user     = 10001
          run_as_group    = 10001
          fs_group        = 10001

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "jaeger"
          image             = var.jaeger_image
          image_pull_policy = "IfNotPresent"

          security_context {
            run_as_non_root            = true
            run_as_user                = 10001
            run_as_group               = 10001
            read_only_root_filesystem  = true
            allow_privilege_escalation = false

            capabilities {
              drop = ["ALL"]
            }
          }

          port {
            name           = "otlp-grpc"
            container_port = 4317
            protocol       = "TCP"
          }

          port {
            name           = "otlp-http"
            container_port = 4318
            protocol       = "TCP"
          }

          port {
            name           = "ui"
            container_port = 16686
            protocol       = "TCP"
          }

          liveness_probe {
            http_get {
              path = "/"
              port = 16686
            }
            initial_delay_seconds = 10
            period_seconds        = 15
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/"
              port = 16686
            }
            initial_delay_seconds = 5
            period_seconds        = 5
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }

        volume {
          name = "tmp"
          empty_dir {
            size_limit = "64Mi"
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "jaeger" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "jaeger"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
    labels = {
      "app.kubernetes.io/name"      = "jaeger"
      "app.kubernetes.io/component" = "jaeger"
      "app.kubernetes.io/part-of"   = "ai-enablement-platform"
    }
  }

  spec {
    type = "ClusterIP"

    selector = {
      "app.kubernetes.io/component" = "jaeger"
    }

    port {
      name        = "otlp-grpc"
      port        = 4317
      target_port = 4317
      protocol    = "TCP"
    }

    port {
      name        = "otlp-http"
      port        = 4318
      target_port = 4318
      protocol    = "TCP"
    }

    port {
      name        = "ui"
      port        = 16686
      target_port = 16686
      protocol    = "TCP"
    }
  }
}

resource "kubernetes_network_policy_v1" "default_deny" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "observability-default-deny"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy_v1" "dns_egress" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "observability-dns-egress"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
  }

  spec {
    pod_selector {
      match_expressions {
        key      = "app.kubernetes.io/component"
        operator = "In"
        values   = ["prometheus", "grafana"]
      }
    }

    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
      }

      ports {
        protocol = "UDP"
        port     = "53"
      }

      ports {
        protocol = "TCP"
        port     = "53"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "prometheus" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "prometheus"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/component" = "prometheus"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/component" = "grafana"
          }
        }
      }

      ports {
        protocol = "TCP"
        port     = "9090"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.platform_namespace
          }
        }

        pod_selector {
          match_labels = {
            "app.kubernetes.io/component" = "gateway-api"
          }
        }
      }

      ports {
        protocol = "TCP"
        port     = "8000"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "jaeger" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "jaeger"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/component" = "jaeger"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.platform_namespace
          }
        }
      }

      ports {
        protocol = "TCP"
        port     = "4317"
      }

      ports {
        protocol = "TCP"
        port     = "4318"
      }
    }

    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/component" = "grafana"
          }
        }
      }

      ports {
        protocol = "TCP"
        port     = "16686"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "grafana" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "grafana"
    namespace = kubernetes_namespace_v1.observability[0].metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/component" = "grafana"
      }
    }

    policy_types = ["Ingress", "Egress"]

    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/component" = "prometheus"
          }
        }
      }

      ports {
        protocol = "TCP"
        port     = "9090"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/component" = "jaeger"
          }
        }
      }

      ports {
        protocol = "TCP"
        port     = "16686"
      }
    }
  }
}
