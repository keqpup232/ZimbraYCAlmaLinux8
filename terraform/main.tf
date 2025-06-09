provider "yandex" {
  token     = var.yc_token
  cloud_id  = var.yc_cloud_id
  folder_id = var.yc_folder_id
  zone      = var.yc_zone
}

data "yandex_compute_image" "my_image" {
  family = "almalinux-8"
}

resource "yandex_vpc_network" "zimbra_network" {
  name = "zimbra-network"
}

resource "yandex_vpc_subnet" "zimbra_subnet" {
  name           = "zimbra-subnet"
  zone           = "ru-central1-a"
  network_id     = yandex_vpc_network.zimbra_network.id
  v4_cidr_blocks = ["192.168.10.0/24"]
}

resource "yandex_compute_instance" "zimbra_server" {
  name        = "zimbra-alma8"
  platform_id = "standard-v3"
  zone        = "ru-central1-a"

  resources {
    cores  = "${var.cores}"
    memory = "${var.memory}"
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.my_image.id
      size     = "${var.size}"
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.zimbra_subnet.id
    nat       = true
  }

  provisioner "remote-exec" {
    inline = [
      # Update and Install Python 3.6 and Components
      "sudo dnf -y update",
      "sudo dnf install -y python3 python3-pip python3-dnf libdnf"
    ]

    connection {
      type        = "ssh"
      user        = "almalinux"
      private_key = file("~/.ssh/id_rsa")
      host        = self.network_interface.0.nat_ip_address
    }
  }
  metadata = {
    ssh-keys = sensitive("almalinux:${file("~/.ssh/id_rsa.pub")}")
  }
}

resource "yandex_dns_zone" "zimbra_zone" {
  name        = "zimbra-zone"
  description = "DNS zone for Zimbra"
  zone        = "${var.domain_name}."
  public      = true
}

resource "yandex_dns_recordset" "zimbra_records" {
  zone_id = yandex_dns_zone.zimbra_zone.id
  name    = "mail"
  type    = "A"
  ttl     = 600
  data    = [yandex_compute_instance.zimbra_server.network_interface[0].nat_ip_address]
}

resource "yandex_dns_recordset" "zimbra_mx" {
  zone_id = yandex_dns_zone.zimbra_zone.id
  name    = "@"
  type    = "MX"
  ttl     = 600
  data    = ["0 mail.${var.domain_name}"]
}

resource "yandex_dns_recordset" "zimbra_caa" {
  zone_id = yandex_dns_zone.zimbra_zone.id
  name    = "@"
  type    = "CAA"
  ttl     = 600
  data    = ["0 issue letsencrypt.org"]
}

resource "yandex_dns_recordset" "zimbra_spf" {
  zone_id = yandex_dns_zone.zimbra_zone.id
  name    = "@"
  type    = "TXT"
  ttl     = 600
  data    = ["\"v=spf1 a mx ip4:${yandex_compute_instance.zimbra_server.network_interface.0.nat_ip_address} -all\""]
}

resource "yandex_dns_recordset" "zimbra_dmarc" {
  zone_id = yandex_dns_zone.zimbra_zone.id
  name    = "_dmarc"
  type    = "TXT"
  ttl     = 600
  data    = ["\"v=DMARC1; p=quarantine; rua=mailto:admin@${var.domain_name}; ruf=mailto:admin@${var.domain_name}; fo=1\""]
}

resource "local_file" "ansible_inventory" {
  filename = "../ansible/inventory.ini"
  content = <<-EOT
    [zimbra]
    ${yandex_compute_instance.zimbra_server.network_interface.0.nat_ip_address}

    [zimbra:vars]
    ansible_user=almalinux
    ansible_ssh_private_key_file=~/.ssh/id_rsa
    domain_name=${var.domain_name}
    hostname=mail.${var.domain_name}
    admin_password=${var.admin_password}
    local_ip_address=${yandex_compute_instance.zimbra_server.network_interface.0.ip_address}
    external_ip_address=${yandex_compute_instance.zimbra_server.network_interface.0.nat_ip_address}
    zimbra_dns_zone_name=${yandex_dns_zone.zimbra_zone.name}
  EOT

  depends_on = [
    yandex_compute_instance.zimbra_server
  ]
}