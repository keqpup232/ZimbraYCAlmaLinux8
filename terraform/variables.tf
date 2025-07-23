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

variable "domain" {
  description = "Domain name for Zimbra"
  type        = string
  default     = "keqpup.ru"
}

variable "domain_l3_mail" {
  description = "Domain l3 mail server"
  type        = string
  default     = "mail"
}

variable "domain_l3_mt" {
  description = "Domain l3 monitoring server"
  type        = string
  default     = "mt"
}

variable "cores_zimbra" {
  description = "cores for VM zimbra"
  type        = number
  default     = 4
}

variable "memory_zimbra" {
  description = "memory for VM zimbra"
  type        = number
  default     = 12   # 8 Gb RAM min for Zimbra
}

variable "size_zimbra" {
  description = "size disk for VM zimbra"
  type        = number
  default     = 100
}

variable "cores_monit" {
  description = "cores for VM monitoring"
  type        = number
  default     = 4
}

variable "memory_monit" {
  description = "memory for VM monitoring"
  type        = number
  default     = 8
}

variable "size_monit" {
  description = "size disk for VM monitoring"
  type        = number
  default     = 50
}

variable "admin_password" {
  description = "admin_password for Zimbra"
  type        = string
  default     = "qEV*zqm5%5Q~"
}

variable "deploy_zimbra" {
  type        = bool
  default     = true
  description = "Deploy Zimbra server"
}

variable "deploy_monitoring" {
  type        = bool
  default     = true
  description = "Deploy monitoring server"
}