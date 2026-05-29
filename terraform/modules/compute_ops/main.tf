resource "google_compute_address" "ops_internal" {
  name         = "portfolio-${var.environment}-ops-ip"
  project      = var.project_id
  region       = var.region
  subnetwork   = var.subnet_id
  address_type = "INTERNAL"
}

resource "google_compute_disk" "data" {
  name    = "portfolio-${var.environment}-ops-data"
  project = var.project_id
  zone    = var.zone
  type    = "pd-balanced"
  size    = var.data_disk_size
}

resource "google_compute_resource_policy" "daily_snapshot" {
  name    = "portfolio-${var.environment}-daily-snapshot"
  project = var.project_id
  region  = var.region

  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "03:00"
      }
    }

    retention_policy {
      max_retention_days    = 14
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }

    snapshot_properties {
      storage_locations = [var.region]
      labels = {
        environment = var.environment
      }
    }
  }
}

resource "google_compute_disk_resource_policy_attachment" "data_snapshot" {
  name    = google_compute_resource_policy.daily_snapshot.name
  disk    = google_compute_disk.data.name
  zone    = var.zone
  project = var.project_id
}

resource "google_compute_instance" "ops" {
  name         = "portfolio-${var.environment}-ops"
  machine_type = var.machine_type
  zone         = var.zone
  project      = var.project_id

  tags = ["ops-vm"]

  boot_disk {
    initialize_params {
      image = "projects/cos-cloud/global/images/family/cos-stable"
      size  = 20
      type  = "pd-balanced"
    }
  }

  attached_disk {
    source      = google_compute_disk.data.self_link
    device_name = "data-disk"
    mode        = "READ_WRITE"
  }

  network_interface {
    subnetwork = var.subnet_id
    network_ip = google_compute_address.ops_internal.address
    # No access_config = no external IP. SSH via IAP only.
  }

  metadata = {
    enable-oslogin = "TRUE"

    user-data = <<-CLOUDINIT
      #cloud-config
      write_files:
        - path: /etc/systemd/system/portfolio-ops.service
          content: |
            [Unit]
            Description=Portfolio Ops Stack (Postgres + Observability)
            After=network-online.target docker.service
            Wants=network-online.target

            [Service]
            Type=oneshot
            RemainAfterExit=yes
            ExecStartPre=/bin/bash -c 'mkdir -p /mnt/data/postgres /mnt/data/loki /mnt/data/prometheus /mnt/data/grafana && chown -R 999:999 /mnt/data/postgres && chown -R 10001:10001 /mnt/data/loki && chown -R 65534:65534 /mnt/data/prometheus && chown -R 472:472 /mnt/data/grafana'
            ExecStart=/usr/bin/docker compose -f /opt/portfolio/docker-compose.gcp-ops.yml up -d
            ExecStop=/usr/bin/docker compose -f /opt/portfolio/docker-compose.gcp-ops.yml down

            [Install]
            WantedBy=multi-user.target

      bootcmd:
        - |
          if ! blkid /dev/disk/by-id/google-data-disk; then
            mkfs.ext4 -m 0 -F -E lazy_itable_init=0 /dev/disk/by-id/google-data-disk
          fi
        - mkdir -p /mnt/data
        - mount -o defaults /dev/disk/by-id/google-data-disk /mnt/data || true
        - echo '/dev/disk/by-id/google-data-disk /mnt/data ext4 defaults,nofail 0 2' | grep -qxF -f /etc/fstab || echo '/dev/disk/by-id/google-data-disk /mnt/data ext4 defaults,nofail 0 2' >> /etc/fstab

      runcmd:
        - systemctl daemon-reload
        - systemctl enable portfolio-ops.service
        - systemctl start portfolio-ops.service
    CLOUDINIT
  }

  service_account {
    scopes = ["cloud-platform"]
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  allow_stopping_for_update = true

  lifecycle {
    ignore_changes = [metadata["ssh-keys"]]
  }
}
