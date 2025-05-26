variable "yc_token" {
  description = "Yandex Cloud OAuth token"
  type        = string
  sensitive   = true
}

variable "yc_cloud_id" {
  description = "Yandex Cloud ID"
  type        = string
  sensitive   = true
}

variable "yc_folder_id" {
  description = "Yandex Cloud Folder ID"
  type        = string
  sensitive   = true
}

variable "ssh_private_key" {
  description = "Path to SSH private key"
  type        = string
  default     = "~/.ssh/id_rsa"
  sensitive   = true
}

variable "yc_zone" {
  description = "Yandex Cloud zone"
  type        = string
  default     = "ru-central1-a"
}

variable "domain_name" {
  description = "Domain name for Zimbra"
  type        = string
  default     = "keqpup.ru"
}

variable "cores" {
  description = "cores for VM"
  type        = number
  default     = 4
}

variable "memory" {
  description = "memory for VM"
  type        = number
  default     = 12   # 8 Gb RAM min for Zimbra
}

variable "size" {
  description = "size disk for VM"
  type        = number
  default     = 100
}

variable "admin_password" {
  description = "admin_password for Zimbra"
  type        = string
  default     = "qEV*zqm5%5Q~"
}