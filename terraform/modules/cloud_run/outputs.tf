output "service_url" {
  value = google_cloud_run_v2_service.backend.uri
}

output "service_name" {
  value = google_cloud_run_v2_service.backend.name
}
