terraform {
  backend "gcs" {
    # Set bucket via -backend-config or edit after bootstrap:
    # bucket = "<PROJECT_ID>-tfstate"
    prefix = "prod"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

module "network" {
  source = "../../modules/network"

  project_id  = var.project_id
  region      = var.region
  environment = var.environment
}

module "iam" {
  source = "../../modules/iam"

  project_id  = var.project_id
  github_repo = var.github_repo
}

module "artifact_registry" {
  source = "../../modules/artifact_registry"

  project_id  = var.project_id
  region      = var.region
  deployer_sa = module.iam.github_deployer_sa_email
  runtime_sa  = module.iam.cloud_run_sa_email
}

module "secrets" {
  source = "../../modules/secrets"

  project_id = var.project_id
  runtime_sa = module.iam.cloud_run_sa_email
}

module "compute_ops" {
  source = "../../modules/compute_ops"

  project_id     = var.project_id
  region         = var.region
  zone           = var.zone
  environment    = var.environment
  network_id     = module.network.network_id
  subnet_id      = module.network.subnet_id
  machine_type   = var.vm_machine_type
  data_disk_size = var.data_disk_size_gb
}

module "cloud_run" {
  source = "../../modules/cloud_run"

  project_id      = var.project_id
  region          = var.region
  environment     = var.environment
  image           = var.cloud_run_image
  vpc_connector   = module.network.vpc_connector_id
  service_account = module.iam.cloud_run_sa_email
  frontend_origin = var.frontend_origin
  database_url_secret = module.secrets.database_url_secret_id
  jwt_secret_id       = module.secrets.jwt_secret_id
  refresh_secret_id   = module.secrets.refresh_secret_id
  admin_hash_id       = module.secrets.admin_hash_id
  gate_l2_id          = module.secrets.gate_l2_id
  gate_token_id       = module.secrets.gate_token_id
  resend_key_id       = module.secrets.resend_key_id
  gh_token_id         = module.secrets.gh_token_id
  gemini_key_id       = module.secrets.gemini_key_id
  roadmap_token_id    = module.secrets.roadmap_token_id
  ops_vm_internal_ip  = module.compute_ops.internal_ip
}
