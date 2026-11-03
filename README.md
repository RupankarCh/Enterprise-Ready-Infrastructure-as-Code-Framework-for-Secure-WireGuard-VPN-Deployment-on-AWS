# CloudVPN-IaC

### Infrastructure as Code for a Personal Cloud VPN on AWS

CloudVPN-IaC is an Infrastructure-as-Code project that automates the deployment and configuration of a self-managed WireGuard VPN server on Amazon Web Services (AWS).

The project combines Terraform, Ansible, AWS Systems Manager (SSM), IAM, and WireGuard to provide a secure, reproducible, and cost-conscious VPN infrastructure.

The primary objectives are:

* Deploy VPN infrastructure using Terraform.
* Configure the VPN server using Ansible.
* Manage EC2 instances through AWS Systems Manager without exposing SSH.
* Use IAM instance roles instead of storing long-lived AWS credentials.
* Provide encrypted internet connectivity through WireGuard.
* Maintain a modular and extensible architecture for future security integrations.

---

## Architecture

The infrastructure consists of:

| Component           | Purpose                                      |
| ------------------- | -------------------------------------------- |
| Amazon VPC          | Provides an isolated networking environment. |
| Public Subnet       | Hosts the VPN server.                        |
| Internet Gateway    | Provides internet connectivity.              |
| Route Table         | Controls network traffic routing.            |
| Amazon EC2          | Hosts the WireGuard VPN server.              |
| Elastic IP          | Provides a persistent public endpoint.       |
| Security Groups     | Controls inbound and outbound traffic.       |
| AWS IAM Role        | Provides permissions to the EC2 instance.    |
| AWS Systems Manager | Enables remote administration without SSH.   |
| Terraform           | Provisions AWS infrastructure.               |
| Ansible             | Automates server configuration.              |
| WireGuard           | Provides encrypted VPN connectivity.         |

### Network Configuration

| Parameter                  | Configuration    |
| -------------------------- | ---------------- |
| AWS Region                 | ap-south-1       |
| Operating System           | Ubuntu 24.04 LTS |
| EC2 Instance Type          | t3.micro         |
| VPN Protocol               | WireGuard        |
| VPN Interface              | wg0              |
| VPN Network                | 10.8.0.0/24      |
| VPN Server Address         | 10.8.0.1         |
| VPN Client Address         | 10.8.0.2         |
| WireGuard Port             | UDP 51820        |
| DNS                        | 1.1.1.1          |
| External Network Interface | ens5             |

---

## Technology Stack

| Technology          | Purpose                        |
| ------------------- | ------------------------------ |
| Terraform           | Infrastructure provisioning    |
| AWS EC2             | VPN server hosting             |
| AWS VPC             | Network isolation              |
| AWS IAM             | Identity and access management |
| AWS Systems Manager | Secure instance management     |
| Ansible             | Configuration automation       |
| WireGuard           | VPN protocol                   |
| Ubuntu              | Server operating system        |
| iptables            | Network forwarding and NAT     |
| Git / GitHub        | Version control                |

---

## Security Design

The project follows several security principles:

* No inbound SSH access is required for instance administration.
* IAM instance roles are used instead of storing AWS credentials on EC2.
* AWS Systems Manager provides remote instance management.
* IMDSv2 is required for instance metadata access.
* EC2 source/destination checking is disabled to support VPN routing.
* WireGuard provides encrypted VPN communication.
* Server private keys are stored on the server with restricted permissions.
* Terraform state files and sensitive local configuration files are excluded from Git.
* Client configuration files and private keys are excluded from version control.

### Network Security

The WireGuard server uses:

* UDP port 51820 for VPN connections.
* IPv4 forwarding to route client traffic.
* iptables FORWARD rules to permit VPN traffic.
* NAT masquerading to allow VPN clients to access the internet through EC2.

---

## Repository Structure

```text
CloudVPN-IaC/
├── .github/
│   └── workflows/
├── .gitattributes
├── .gitignore
├── ansible/
│   ├── inventory/
│   │   └── hosts.example.yml
│   ├── output/                  # Local sensitive files; ignored by Git
│   ├── playbooks/
│   │   └── wireguard.yml
│   ├── roles/
│   │   └── wireguard/
│   │       ├── defaults/
│   │       │   └── main.yml
│   │       ├── handlers/
│   │       │   └── main.yml
│   │       ├── tasks/
│   │       │   └── main.yml
│   │       └── templates/
│   │           └── wg0.conf.j2
│   ├── vars/
│   │   └── client1.example.yml
│   ├── ansible.cfg
│   └── requirements.yml
├── cloud-init/
├── diagrams/
├── docs/
├── monitoring/
├── scripts/
├── security/
└── terraform/
    └── modules/
        ├── ec2/
        ├── security/
        └── vpc/
```

---

## Implementation Status

### Implemented

* AWS infrastructure provisioned using Terraform.
* EC2 VPN server deployed.
* VPC and networking resources configured.
* Elastic IP associated with the VPN server.
* IAM instance role configured.
* AWS Systems Manager connectivity verified.
* Ansible connectivity through SSM verified.
* EC2 source/destination check disabled.
* WireGuard installed and configured.
* WireGuard server interface configured.
* IPv4 forwarding enabled.
* iptables forwarding and NAT rules implemented.
* WireGuard client peer configuration implemented.
* Windows WireGuard client configuration generated.
* Ansible handlers implemented for WireGuard configuration changes.
* Sensitive local files excluded from Git.

### Next Development Goals

* Improve client provisioning and revocation automation.
* Implement automated client key rotation.
* Integrate AWS CloudWatch monitoring and alerting.
* Integrate Amazon GuardDuty and Security Hub.
* Implement security auditing and operational logging.
* Improve firewall hardening.
* Develop a web-based VPN management interface.
* Explore browser extension and application integration.

**Development note:** The current implementation provides a functional single-server WireGuard VPN architecture. Further production hardening, automated security monitoring, and operational validation are planned.

---

## Prerequisites

Before deployment, install:

* AWS account.
* AWS CLI.
* Terraform.
* Ansible.
* AWS Session Manager plugin.
* Python.
* Required Ansible collections.
* Git.

---

## Deployment Overview

### 1. Configure AWS credentials

Configure AWS CLI credentials on your local administration machine.

Do not store AWS access keys in the EC2 instance or commit them to Git.

### 2. Provision AWS infrastructure

Use Terraform to initialize, validate, review, and deploy the infrastructure.

Review the Terraform plan before applying changes.

### 3. Configure Ansible

Configure the SSM inventory using the provided example inventory file.

Verify connectivity:

```bash
cd ansible

ansible wireguard -m ansible.builtin.ping
```

### 4. Configure the WireGuard client public key

Create the local output directory:

```bash
mkdir -p output
```

Copy the example variables file:

```bash
cp vars/client1.example.yml output/client1.yml
```

Edit `output/client1.yml` and replace the placeholder with the actual WireGuard client public key.

Never put the client private key in this file.

### 5. Deploy WireGuard

Run:

```bash
ansible-playbook playbooks/wireguard.yml
```

The playbook installs WireGuard, enables IPv4 forwarding, generates server keys when needed, and deploys the WireGuard configuration.

### 6. Configure the VPN client

Import the generated client configuration into the WireGuard application on Windows or another supported operating system.

Activate the VPN connection.

### 7. Verify VPN connectivity

On the server, inspect the WireGuard interface:

```bash
sudo wg show
```

Check IPv4 forwarding:

```bash
sysctl net.ipv4.ip_forward
```

Expected output:

```text
net.ipv4.ip_forward = 1
```

Verify the VPN connection from the client by checking the public IP address. When full-tunnel routing is working, internet traffic should exit through the AWS VPN server.

---

## Sensitive Files and Git Security

The following files must never be committed:

* Terraform state files.
* Terraform variable files containing secrets.
* AWS credentials.
* WireGuard server private keys.
* WireGuard client private keys.
* Generated client configuration files.
* Actual local inventory files containing environment-specific details.

Example files containing placeholders may be committed.

The repository uses `.gitignore` and `.gitattributes` to help protect sensitive files and maintain consistent LF line endings.

---

## Cost Considerations

AWS resources may incur charges, including:

* EC2 compute.
* Elastic IP addresses.
* EBS storage.
* Data transfer.
* Monitoring services.

Actual costs depend on the AWS region, instance type, usage duration, and applicable AWS pricing.

Always monitor AWS billing and remove resources that are no longer required.

---

## Future Security Integration

The architecture is designed to support additional security capabilities:

| Service                           | Planned Purpose                                 |
| --------------------------------- | ----------------------------------------------- |
| Amazon CloudWatch                 | Infrastructure monitoring and alerting          |
| Amazon GuardDuty                  | Threat detection                                |
| AWS Security Hub                  | Centralized security findings                   |
| AWS CloudTrail                    | API activity auditing                           |
| AWS Systems Manager Patch Manager | Automated patch management                      |
| AWS Secrets Manager               | Centralized secret management where appropriate |

These integrations are planned enhancements and are not represented as currently deployed.

---

## Disclaimer

This project is intended for educational purposes and personal infrastructure experimentation.

Review AWS security settings, IAM permissions, network rules, VPN configurations, and billing implications before deploying in a production environment.

## License

This project is licensed under the MIT License.

