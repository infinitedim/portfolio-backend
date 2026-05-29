variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "deployer_sa" {
  description = "Service account email for the GitHub deployer (push access)"
  type        = string
}

variable "runtime_sa" {
  description = "Service account email for Cloud Run (pull access)"
  type        = string
}
