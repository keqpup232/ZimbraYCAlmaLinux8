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
## Bypassing Yandex Cloud's Outbound Port 25 Block

**Important Notice**: This solution is specifically designed for **testing purposes only** to verify Zimbra mail server functionality when deployed in Yandex Cloud (YC). It is not recommended for production environments due to potential performance limitations and security considerations.

The implementation establishes a WireGuard VPN tunnel between your YC instance and a local network with a static public IP address to bypass YC's outbound port 25 restrictions.

## Limitations and Production Considerations

1. **Testing Purpose Only**:
   - This solution is designed specifically for testing Zimbra functionality
   - Not recommended for production mail servers
   - VPN tunnel may become a bottleneck for mail traffic

2. **Production Alternatives**:
   - Consider using YC's approved mail delivery services
   - Implement a mail relay service outside of YC
   - Use alternative ports with TLS encryption if supported
   - Apply for YC's port 25 unblocking for legitimate mail servers

3. **Performance Notes**:
   - Tunnel bandwidth depends on your local internet connection
   - Latency may affect mail delivery times
   - Not suitable for high-volume mail traffic

![Diagram](./tmp/schema.drawio)

### Prerequisites

Before installation, ensure you have:

1. A static public IP address on your router
2. The following ports forwarded from your router to your local machine:
   - TCP 25 (for SMTP traffic)
   - UDP 51820 (for WireGuard VPN)
3. Docker and Docker Compose installed on your local machine
   - [Installation guide](https://docs.docker.com/compose/install/)
4. Need install `wireguard-tools` package on local machine (for key generation and management) 
5. Zimbra installed via the provided Ansible [`playbook`](./ansible/playbook.yml)

### Installation
**Configuration**

1. Edit the [`main.yml`](./ansible/roles/vpn_setup/vars/main.yml) configuration file:
   ```yaml
   rout_public_ip: "x.x.x.x"  # Replace with your actual static IP
   ```

**Deployment**

Run the Ansible playbook to set up the VPN:

```bash
ansible-playbook -i ./ansible/inventory.ini ./ansible/vpn_setup.yml
```

**Verification**

After installation y can see stdout ansible tests or:

1. Verify the VPN connection is established
   ```bash
   sudo wg show
   ```
2. Test outbound SMTP traffic on port 25
   ```bash
   telnet your.mail.server 25
   ```
3. Confirm email delivery is functioning as expected
    ```bash
    tail -f /var/log/zimbra.log
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

### **WireGuard VPN**  
- Lightweight, high-performance VPN tunnel for bypassing YC’s port 25 restrictions:  
  - **Protocol**: UDP (Port `51820` forwarded on home router).  
  - **Encryption**: ChaCha20-Poly1305 for secure traffic forwarding.  
  - **Key Management**: Ephemeral keys generated during Ansible setup.  
  - **Traffic Routing**: Selective routing for SMTP (TCP/25) only.  
  - **NAT Traversal**: Built-in support for home networks behind CG-NAT. 
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