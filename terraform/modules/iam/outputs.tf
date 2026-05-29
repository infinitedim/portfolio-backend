output "cloud_run_sa_email" {
  value = google_service_account.cloud_run.email
}

output "github_deployer_sa_email" {
  value = google_service_account.github_deployer.email
}

output "workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.github.name
}
