output "local_ip_address_zimbra" {
  value = var.deploy_zimbra ? "${yandex_compute_instance.zimbra_server[0].network_interface.0.ip_address}" : null
}

output "external_ip_address_zimbra" {
  value = var.deploy_zimbra ? "${yandex_compute_instance.zimbra_server[0].network_interface.0.nat_ip_address}" : null
}

output "ssh_connect_zimbra" {
  value = var.deploy_zimbra ? "ssh almalinux@${yandex_compute_instance.zimbra_server[0].network_interface.0.nat_ip_address}" : null
}

output "local_ip_address_monit" {
  value = var.deploy_monitoring ? "${yandex_compute_instance.monitoring_server[0].network_interface.0.ip_address}" : null
}

output "external_ip_address_monit" {
  value = var.deploy_monitoring ? "${yandex_compute_instance.monitoring_server[0].network_interface.0.nat_ip_address}" : null
}

output "ssh_connect_monit" {
  value = var.deploy_monitoring ? "ssh almalinux@${yandex_compute_instance.monitoring_server[0].network_interface.0.nat_ip_address}" : null
}