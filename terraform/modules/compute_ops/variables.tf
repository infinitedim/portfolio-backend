variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "zone" {
  type = string
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "network_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "machine_type" {
  type    = string
  default = "e2-medium"
}

variable "data_disk_size" {
  description = "Persistent data disk size in GB"
  type        = number
  default     = 50
}
