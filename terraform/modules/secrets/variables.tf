variable "project_id" {
  type = string
}

variable "runtime_sa" {
  description = "Cloud Run service account email that needs accessor rights"
  type        = string
}
