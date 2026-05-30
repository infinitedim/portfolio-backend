variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "image" {
  description = "Full Artifact Registry image URI"
  type        = string
}

variable "vpc_connector" {
  description = "VPC Access connector ID"
  type        = string
}

variable "service_account" {
  description = "Cloud Run service account email"
  type        = string
}

variable "frontend_origin" {
  description = "Frontend URL for CORS and SITE_URL"
  type        = string
}

variable "ops_vm_internal_ip" {
  description = "Internal IP of the ops VM (for DATABASE_URL host)"
  type        = string
}

# Secret Manager secret IDs
variable "database_url_secret" { type = string }
variable "jwt_secret_id" { type = string }
variable "refresh_secret_id" { type = string }
variable "admin_hash_id" { type = string }
variable "gate_l2_id" { type = string }
variable "gate_token_id" { type = string }
variable "resend_key_id" { type = string }
variable "gh_token_id" { type = string }
variable "gemini_key_id" { type = string }
variable "roadmap_email_id" { type = string }
variable "roadmap_password_id" { type = string }

variable "admin_email" {
  description = "Production admin email required by backend startup checks"
  type        = string
}

variable "metrics_token_id" {
  description = "Secret Manager ID for optional /metrics bearer token"
  type        = string
}
