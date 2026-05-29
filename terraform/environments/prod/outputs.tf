output "cloud_run_url" {
  description = "Public URL of the Cloud Run backend service"
  value       = module.cloud_run.service_url
}

output "artifact_registry_repo" {
  description = "Artifact Registry repository URL for docker push"
  value       = module.artifact_registry.repository_url
}

output "ops_vm_name" {
  description = "Name of the ops VM (Postgres + observability)"
  value       = module.compute_ops.instance_name
}

output "ops_vm_internal_ip" {
  description = "Internal IP of the ops VM"
  value       = module.compute_ops.internal_ip
}

output "github_deployer_sa_email" {
  description = "Service account email for GitHub Actions deployer"
  value       = module.iam.github_deployer_sa_email
}

output "workload_identity_provider" {
  description = "Workload Identity Provider resource name for GitHub Actions auth"
  value       = module.iam.workload_identity_provider
}
