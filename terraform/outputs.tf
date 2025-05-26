output "local_ip_address" {
  value = "${yandex_compute_instance.zimbra_server.network_interface.0.ip_address}"
}

output "external_ip_address" {
  value = "${yandex_compute_instance.zimbra_server.network_interface.0.nat_ip_address}"
}

output "ssh_connect" {
  value = "ssh almalinux@${yandex_compute_instance.zimbra_server.network_interface.0.nat_ip_address}"
}