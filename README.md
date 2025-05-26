# Zimbra Mail Server Deployment on Yandex Cloud

## Overview  
This guide provides step-by-step instructions for deploying a **Zimbra 8.8.15** mail server on **AlmaLinux 8** using **Terraform** and **Ansible** in **Yandex Cloud**. The stack includes:  

- **AlmaLinux 8** – A stable and secure RHEL-based OS.  
- **Zimbra 8.8.15** – Open-source email and collaboration platform.  
- **Let’s Encrypt** – Free SSL certificates for secure mail services.  
- **Fail2Ban** – Protection against brute-force attacks.  

---

## Prerequisites

Before proceeding with the installation, ensure you have the following components properly configured:

### 1. Python Environment
- **Python version was used**: 3.11.5  
  Verify with:
  ```bash
  python3 --version
  ```

### 2. Ansible Installation
- **Ansible version was used**: 2.16.14  
  For macOS M1, install using:
  ```bash
  brew install ansible@9
  ```
  Verify with:
  ```bash
  ansible --version
  ```

### 3. DNS Configuration
Configure DNS records for your purchased domain in the public zone. If your domain is already registered, delegate it by specifying Yandex Cloud's name servers in your registrar's NS records:
```
ns1.yandexcloud.net.
ns2.yandexcloud.net.
```
Remove any other existing NS records if delegation was previously configured.

### 4. Terraform Setup
- **[Terraform](https://developer.hashicorp.com/terraform/install) version was used**: 1.11.4  
  Configure the Yandex Cloud provider by creating or editing the Terraform CLI configuration file:
  ```bash
  vim ~/.terraformrc
  ```
  Add the following content:
  ```hcl
  provider_installation {
    network_mirror {
      url = "https://terraform-mirror.yandexcloud.net/"
      include = ["registry.terraform.io/*/*"]
    }
    direct {
      exclude = ["registry.terraform.io/*/*"]
    }
  }
  ```

### 5. Yandex Cloud CLI (YC CLI)
Install the [YC CLI](https://yandex.cloud/en-ru/docs/cli/operations/install-cli) and set up your cloud, folder, and billing account:
```bash
curl -sSL https://storage.yandexcloud.net/yandexcloud-yc/install.sh | bash
```

---

## Installation

### 1. Configure Required Variables
Edit the file [`variables.tf`](./terraform/variables.tf) with the following parameters:
```hcl
variable "domain_name" {
  description = "Domain name for Zimbra"
  type        = string
  default     = "example.com"  # Replace with your domain
}

variable "cores" {
  description = "CPU cores for the VM"
  type        = number
  default     = 4
}

variable "memory" {
  description = "Memory for the VM (in GB)"
  type        = number
  default     = 12   # Minimum 8 GB RAM for Zimbra
}

variable "size" {
  description = "Disk size for the VM (in GB)"
  type        = number
  default     = 100
}

variable "admin_password" {
  description = "Admin password for Zimbra"
  type        = string
  default     = "YourSecurePassword123!"  # Replace with a strong password
}
```

### 2. Set Environment Variables
Terraform automatically picks up variables prefixed with `TF_VAR_`:
```bash
export TF_VAR_yc_token=$(yc iam create-token)
export TF_VAR_yc_cloud_id=$(yc config get cloud-id)
export TF_VAR_yc_folder_id=$(yc config get folder-id)
```

### 3. Deploy Infrastructure
1. **Initialize Terraform**:
   ```bash
   terraform -chdir=./terraform init
   ```

2. **Apply Infrastructure**:
   ```bash
   terraform -chdir=./terraform apply -auto-approve
   ```

3. **Run Ansible Playbook**:
   - For a full installation:
     ```bash
     ansible-playbook -i ./ansible/inventory.ini ./ansible/playbook.yml
     ```
   - To start from a specific task:
     ```bash
     ansible-playbook -i ./ansible/inventory.ini ./ansible/playbook.yml --start-at-task="Update mirrors.list for ClamAV"
     ```
   - To run specific roles (Zimbra, Let’s Encrypt, Fail2Ban):
     ```bash
     ansible-playbook -i ./ansible/inventory.ini ./ansible/playbook.yml --tags "zimbra|letsencrypt|fail2ban"
     ```

---

## Cleanup
To destroy the infrastructure:
```bash
terraform -chdir=./terraform destroy -auto-approve
```

---

## Stack Details

### **AlmaLinux 8**
- Base OS for stability and long-term support.
- Pre-configured with security updates.

### **Zimbra 8.8.15**
- Includes:
  - Webmail (Zimbra Web Client).
  - Calendar, Contacts, and Tasks.
  - IMAP/POP3/SMTP services.

### **Let’s Encrypt**
- Automatically provisions SSL certificates for:
  - `https://mail.example.com`
  - SMTP/IMAP encryption.

### **Fail2Ban**
- Blocks brute-force attacks on:
  - SSH.
  - Zimbra Admin Console.
  - SMTP/IMAP login attempts.

---

## Notes
- Ensure all prerequisites are met before starting the installation.
- Replace placeholder values (e.g., domain name, password) with your actual configurations.
- For troubleshooting, refer to the logs generated during the Terraform and Ansible execution.
- Access Zimbra Admin Console at `https://mail.example.com:7071`.
- Monitor Fail2Ban logs:
  ```bash
  journalctl -u fail2ban -f
  ```