resource "google_compute_network" "main" {
  name                    = "portfolio-${var.environment}"
  auto_create_subnetworks = false
  project                 = var.project_id
}

resource "google_compute_subnetwork" "main" {
  name          = "portfolio-${var.environment}-subnet"
  ip_cidr_range = "10.10.0.0/24"
  region        = var.region
  network       = google_compute_network.main.id
  project       = var.project_id

  private_ip_google_access = true
}

resource "google_vpc_access_connector" "main" {
  name          = "portfolio-${var.environment}-vpc"
  project       = var.project_id
  region        = var.region
  ip_cidr_range = "10.10.1.0/28"
  network       = google_compute_network.main.name

  min_instances = 2
  max_instances = 3
}

# --- Firewall Rules ---

resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "portfolio-${var.environment}-allow-iap-ssh"
  network = google_compute_network.main.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["ops-vm"]
}

resource "google_compute_firewall" "allow_postgres" {
  name    = "portfolio-${var.environment}-allow-postgres"
  network = google_compute_network.main.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }

  # VPC connector CIDR + VM subnet
  source_ranges = ["10.10.1.0/28", "10.10.0.0/24"]
  target_tags   = ["ops-vm"]
}

resource "google_compute_firewall" "allow_redis" {
  name    = "portfolio-${var.environment}-allow-redis"
  network = google_compute_network.main.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["6379"]
  }

  source_ranges = ["10.10.1.0/28", "10.10.0.0/24"]
  target_tags   = ["ops-vm"]
}

resource "google_compute_firewall" "allow_grafana_iap" {
  name    = "portfolio-${var.environment}-allow-grafana-iap"
  network = google_compute_network.main.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["3000"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["ops-vm"]
}

resource "google_compute_firewall" "allow_prometheus_scrape" {
  name    = "portfolio-${var.environment}-allow-prometheus-scrape"
  network = google_compute_network.main.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["9090"]
  }

  source_ranges = ["10.10.0.0/24"]
  target_tags   = ["ops-vm"]
}

resource "google_compute_firewall" "deny_all_ingress" {
  name     = "portfolio-${var.environment}-deny-all"
  network  = google_compute_network.main.name
  project  = var.project_id
  priority = 65534

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["ops-vm"]
}
