locals {
  service_name = "portfolio-backend"

  secret_env_vars = {
    DATABASE_URL         = var.database_url_secret
    JWT_SECRET           = var.jwt_secret_id
    REFRESH_TOKEN_SECRET = var.refresh_secret_id
    ADMIN_HASH_PASSWORD  = var.admin_hash_id
    GATE_L2_ANSWER       = var.gate_l2_id
    GATE_TOKEN_SECRET    = var.gate_token_id
    RESEND_API_KEY       = var.resend_key_id
    GH_TOKEN             = var.gh_token_id
    GEMINI_API_KEY       = var.gemini_key_id
    ROADMAP_EMAIL        = var.roadmap_email_id
    ROADMAP_PASSWORD     = var.roadmap_password_id
    METRICS_BEARER_TOKEN = var.metrics_token_id
  }
}

resource "google_cloud_run_v2_service" "backend" {
  name     = local.service_name
  location = var.region
  project  = var.project_id

  deletion_protection = false

  template {
    service_account = var.service_account

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    vpc_access {
      connector = var.vpc_connector
      # DB/Redis on VM private IP only — public APIs (roadmap.sh, GitHub) use default internet egress.
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = var.image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      startup_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        initial_delay_seconds = 5
        period_seconds        = 5
        failure_threshold     = 10
        timeout_seconds       = 3
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        period_seconds  = 30
        timeout_seconds = 5
      }

      # Plain-text env vars
      env {
        name  = "ENVIRONMENT"
        value = "production"
      }
      env {
        name  = "HOST"
        value = "0.0.0.0"
      }
      env {
        name  = "PORT"
        value = "8080"
      }
      env {
        name  = "LOG_LEVEL"
        value = "info"
      }
      env {
        name  = "ENABLE_SWAGGER_UI"
        value = "false"
      }
      env {
        name  = "ADMIN_EMAIL"
        value = var.admin_email
      }
      env {
        name  = "ALLOWED_ORIGINS"
        value = var.frontend_origin
      }
      env {
        name  = "FRONTEND_ORIGIN"
        value = var.frontend_origin
      }
      env {
        name  = "SITE_URL"
        value = var.frontend_origin
      }
      env {
        name  = "SITE_TITLE"
        value = "Dimas Saputra"
      }
      env {
        name  = "SITE_DESCRIPTION"
        value = "Full-Stack Developer Portfolio"
      }
      env {
        name  = "DB_POOL_MIN"
        value = "2"
      }
      env {
        name  = "DB_POOL_MAX"
        value = "10"
      }
      env {
        name  = "GATE_L1_ANSWER"
        value = "yourblooo0"
      }
      env {
        name  = "GATE_COOKIE_MAX_AGE_DAYS"
        value = "7"
      }
      env {
        name  = "GATE_SESSION_TTL_HOURS"
        value = "24"
      }
      env {
        name  = "REDIS_URL"
        value = "redis://${var.ops_vm_internal_ip}:6379"
      }

      # Secret-backed env vars
      dynamic "env" {
        for_each = local.secret_env_vars
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
    }

    timeout = "300s"
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  lifecycle {
    ignore_changes = [
      client,
      client_version,
      template[0].containers[0].image,
    ]
  }
}

# Allow unauthenticated access (public API)
resource "google_cloud_run_v2_service_iam_member" "public" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.backend.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
