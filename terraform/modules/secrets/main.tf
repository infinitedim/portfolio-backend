locals {
  secrets = [
    "database-url",
    "jwt-secret",
    "refresh-token-secret",
    "admin-hash-password",
    "gate-l2-answer",
    "gate-token-secret",
    "resend-api-key",
    "gh-token",
    "gemini-api-key",
    "roadmap-email",
    "roadmap-password",
    "metrics-token",
    "postgres-password",
    "grafana-password",
  ]
}

resource "google_secret_manager_secret" "secrets" {
  for_each  = toset(local.secrets)
  secret_id = "portfolio-${each.key}"
  project   = var.project_id

  replication {
    auto {}
  }
}

# Cloud Run SA gets accessor on app secrets (not postgres/grafana passwords).
locals {
  cloud_run_secrets = [
    "database-url",
    "jwt-secret",
    "refresh-token-secret",
    "admin-hash-password",
    "gate-l2-answer",
    "gate-token-secret",
    "resend-api-key",
    "gh-token",
    "gemini-api-key",
    "roadmap-email",
    "roadmap-password",
    "metrics-token",
  ]
}

resource "google_secret_manager_secret_iam_member" "runtime_accessor" {
  for_each  = toset(local.cloud_run_secrets)
  secret_id = google_secret_manager_secret.secrets[each.key].secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.runtime_sa}"
}
