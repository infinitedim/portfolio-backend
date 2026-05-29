output "database_url_secret_id" {
  value = google_secret_manager_secret.secrets["database-url"].secret_id
}

output "jwt_secret_id" {
  value = google_secret_manager_secret.secrets["jwt-secret"].secret_id
}

output "refresh_secret_id" {
  value = google_secret_manager_secret.secrets["refresh-token-secret"].secret_id
}

output "admin_hash_id" {
  value = google_secret_manager_secret.secrets["admin-hash-password"].secret_id
}

output "gate_l2_id" {
  value = google_secret_manager_secret.secrets["gate-l2-answer"].secret_id
}

output "gate_token_id" {
  value = google_secret_manager_secret.secrets["gate-token-secret"].secret_id
}

output "resend_key_id" {
  value = google_secret_manager_secret.secrets["resend-api-key"].secret_id
}

output "gh_token_id" {
  value = google_secret_manager_secret.secrets["gh-token"].secret_id
}

output "gemini_key_id" {
  value = google_secret_manager_secret.secrets["gemini-api-key"].secret_id
}

output "roadmap_token_id" {
  value = google_secret_manager_secret.secrets["roadmap-auth-token"].secret_id
}

output "postgres_password_id" {
  value = google_secret_manager_secret.secrets["postgres-password"].secret_id
}

output "grafana_password_id" {
  value = google_secret_manager_secret.secrets["grafana-password"].secret_id
}
