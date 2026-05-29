variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for all resources"
  type        = string
  default     = "asia-southeast2"
}

variable "zone" {
  description = "GCP zone for VM instances"
  type        = string
  default     = "asia-southeast2-a"
}

variable "environment" {
  description = "Environment name (prod, staging)"
  type        = string
  default     = "prod"
}

variable "cloud_run_image" {
  description = "Full Artifact Registry image URI for Cloud Run (set by CI or manual)"
  type        = string
  default     = ""
}

variable "frontend_origin" {
  description = "Vercel frontend URL for CORS and gate Referer"
  type        = string
  default     = "https://example.vercel.app"
}

variable "github_repo" {
  description = "GitHub repository in owner/repo format for Workload Identity Federation"
  type        = string
  default     = "yourblooo/portfolio-backend"
}

variable "vm_machine_type" {
  description = "Machine type for the ops VM (Postgres + observability)"
  type        = string
  default     = "e2-medium"
}

variable "data_disk_size_gb" {
  description = "Size of the persistent data disk in GB"
  type        = number
  default     = 50
}
