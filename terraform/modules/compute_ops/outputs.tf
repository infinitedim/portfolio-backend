output "instance_name" {
  value = google_compute_instance.ops.name
}

output "internal_ip" {
  value = google_compute_address.ops_internal.address
}

output "instance_id" {
  value = google_compute_instance.ops.instance_id
}
