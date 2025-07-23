provider "yandex" {
  token     = var.yc_token
  cloud_id  = var.yc_cloud_id
  folder_id = var.yc_folder_id
  zone      = var.yc_zone
}

data "yandex_compute_image" "my_image" {
  family = "almalinux-8"
}

resource "yandex_vpc_network" "network" {
  count = var.deploy_zimbra || var.deploy_monitoring ? 1 : 0
  name = "network"
}

resource "yandex_vpc_subnet" "subnet" {
  count          = var.deploy_zimbra || var.deploy_monitoring ? 1 : 0
  name           = "zimbra-subnet"
  zone           = "ru-central1-a"
  network_id     = yandex_vpc_network.network[0].id
  v4_cidr_blocks = ["192.168.10.0/24"]
}

# Zimbra Server
resource "yandex_compute_instance" "zimbra_server" {
  count       = var.deploy_zimbra ? 1 : 0
  name        = "zimbra-alma8"
  platform_id = "standard-v3"
  zone        = "ru-central1-a"

  resources {
    cores  = "${var.cores_zimbra}"
    memory = "${var.memory_zimbra}"
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.my_image.id
      size     = "${var.size_zimbra}"
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.subnet[0].id
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

# Monitoring Server
resource "yandex_compute_instance" "monitoring_server" {
  count       = var.deploy_monitoring ? 1 : 0
  name        = "monitoring-alma8"
  platform_id = "standard-v3"
  zone        = "ru-central1-a"

  resources {
    cores  = "${var.cores_monit}"
    memory = "${var.memory_monit}"
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.my_image.id
      size     = "${var.size_monit}"
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.subnet[0].id
    nat       = true
  }

  provisioner "remote-exec" {
    inline = [
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
  count = var.deploy_zimbra || var.deploy_monitoring ? 1 : 0
  name        = "zimbra-zone"
  description = "DNS zone for Zimbra"
  zone        = "${var.domain}."
  public      = true
}

resource "yandex_dns_recordset" "zimbra_records" {
  count   = var.deploy_zimbra ? 1 : 0
  zone_id = yandex_dns_zone.zimbra_zone[0].id
  name    = "${var.domain_l3_mail}"
  type    = "A"
  ttl     = 600
  data    = [yandex_compute_instance.zimbra_server[0].network_interface[0].nat_ip_address]
}

resource "yandex_dns_recordset" "monitoring_A" {
  count   = var.deploy_monitoring ? 1 : 0
  zone_id = yandex_dns_zone.zimbra_zone[0].id
  name    = "${var.domain_l3_mt}"
  type    = "A"
  ttl     = 600
  data    = [yandex_compute_instance.monitoring_server[0].network_interface[0].nat_ip_address]
}

resource "yandex_dns_recordset" "zimbra_mx" {
  count   = var.deploy_zimbra ? 1 : 0
  zone_id = yandex_dns_zone.zimbra_zone[0].id
  name    = "@"
  type    = "MX"
  ttl     = 600
  data    = ["0 ${var.domain_l3_mail}.${var.domain}"]
}

resource "yandex_dns_recordset" "zimbra_caa" {
  count   = var.deploy_zimbra ? 1 : 0
  zone_id = yandex_dns_zone.zimbra_zone[0].id
  name    = "@"
  type    = "CAA"
  ttl     = 600
  data    = ["0 issue letsencrypt.org"]
}

resource "yandex_dns_recordset" "zimbra_spf" {
  count   = var.deploy_zimbra ? 1 : 0
  zone_id = yandex_dns_zone.zimbra_zone[0].id
  name    = "@"
  type    = "TXT"
  ttl     = 600
  data    = ["\"v=spf1 a mx ip4:${yandex_compute_instance.zimbra_server[0].network_interface.0.nat_ip_address} -all\""]
}

resource "yandex_dns_recordset" "zimbra_dmarc" {
  count   = var.deploy_zimbra ? 1 : 0
  zone_id = yandex_dns_zone.zimbra_zone[0].id
  name    = "_dmarc"
  type    = "TXT"
  ttl     = 600
  data    = ["\"v=DMARC1; p=quarantine; rua=mailto:admin@${var.domain}; ruf=mailto:admin@${var.domain}; fo=1\""]
}

resource "local_file" "ansible_inventory" {
  count = var.deploy_zimbra || var.deploy_monitoring ? 1 : 0
  filename = "../ansible/inventory.ini"
  content = templatefile("inventory.tftpl", {
    zimbra_ip            = var.deploy_zimbra ? yandex_compute_instance.zimbra_server[0].network_interface.0.nat_ip_address : ""
    domain               = var.deploy_zimbra || var.deploy_monitoring ? var.domain : ""
    domain_l3_mail       = var.deploy_zimbra ? var.domain_l3_mail : ""
    domain_l3_mt         = var.deploy_monitoring ? var.domain_l3_mt : ""
    admin_password       = var.deploy_zimbra ? var.admin_password : ""
    local_ip_address     = var.deploy_zimbra ? yandex_compute_instance.zimbra_server[0].network_interface.0.ip_address : ""
    external_ip_address  = var.deploy_zimbra ? yandex_compute_instance.zimbra_server[0].network_interface.0.nat_ip_address : ""
    zimbra_dns_zone_name = var.deploy_zimbra ? yandex_dns_zone.zimbra_zone[0].name : ""
    subnet               = yandex_vpc_subnet.subnet[0].v4_cidr_blocks[0]
    monitoring_ip        = var.deploy_monitoring ? yandex_compute_instance.monitoring_server[0].network_interface.0.nat_ip_address : ""
  })
}