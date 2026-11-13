# CloudVPN-IaC

An Infrastructure-as-Code project for deploying a personal WireGuard VPN server on AWS using Terraform and Ansible.

The project focuses on reproducible infrastructure, secure remote administration, automated configuration, and controlled deployment through AWS Systems Manager (SSM).

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Security Architecture](#security-architecture)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Deployment Workflow](#deployment-workflow)
- [WireGuard Client Configuration](#wireguard-client-configuration)
- [Validation and Testing](#validation-and-testing)
- [Continuous Integration](#continuous-integration)
- [Security Exceptions](#security-exceptions)
- [Sensitive Files and Git Security](#sensitive-files-and-git-security)
- [Cost Considerations](#cost-considerations)
- [Future Security Integration](#future-security-integration)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Project Overview

CloudVPN-IaC automates the deployment and configuration of a WireGuard VPN server on Amazon Web Services.

The infrastructure is managed using Terraform, while Ansible configures the VPN server.

The project uses AWS Systems Manager Session Manager for remote server administration instead of exposing SSH access to the internet.

The main objectives are:

- Reproducible AWS infrastructure deployment.
- Automated WireGuard installation and configuration.
- Secure remote administration through AWS SSM.
- IAM-based authentication instead of storing AWS credentials on the EC2 server.
- Automated configuration generation from a single JSON configuration file.
- Controlled firewall installation and lifecycle management.
- GitHub Actions-based infrastructure and security validation.

## Architecture

### Infrastructure Overview

| Component | Configuration |
|---|---|
| Cloud Provider | Amazon Web Services |
| Region | ap-south-1 (configurable) |
| Infrastructure as Code | Terraform |
| Configuration Management | Ansible |
| VPN Technology | WireGuard |
| Operating System | Ubuntu 24.04 |
| EC2 Instance | t3.micro (configurable) |
| VPN Protocol | UDP |
| WireGuard Port | 51820 (configurable) |
| VPN Network | 10.8.0.0/24 |
| Remote Administration | AWS Systems Manager |
| Authentication | IAM Instance Role |
| Network | Custom VPC and public subnet |

### Architecture Flow

1. Terraform provisions the AWS infrastructure.
2. An EC2 instance is launched in the public subnet.
3. An IAM instance role provides the permissions required for Systems Manager.
4. AWS Systems Manager provides remote administration without public SSH access.
5. Ansible connects through the SSM connection plugin.
6. Ansible installs and configures WireGuard.
7. Firewall rules permit VPN traffic and the required forwarding behaviour.
8. VPN clients connect to the WireGuard server.

### Network Design

The architecture uses:

- A custom VPC.
- A public subnet.
- An Internet Gateway.
- A route table for internet connectivity.
- An EC2-based WireGuard server.
- Security groups and network ACLs.
- IPv4 forwarding for VPN traffic.

The VPN client network is separate from the AWS VPC network.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| AWS EC2 | Hosts the WireGuard VPN server |
| AWS VPC | Provides network isolation |
| AWS Security Groups | Controls instance-level network access |
| AWS Network ACLs | Provides subnet-level network filtering |
| AWS IAM | Manages permissions and instance identity |
| AWS Systems Manager | Enables remote server administration |
| Amazon S3 | Provides the SSM transfer bucket used by the Ansible connection plugin |
| Terraform | Provisions AWS infrastructure |
| Ansible | Configures the VPN server |
| WireGuard | Provides encrypted VPN connectivity |
| Python | Validates deployment configuration and runs tests |
| Bash | Automates configuration and inventory generation |
| GitHub Actions | Performs automated repository validation |
| Gitleaks | Scans repository content for exposed secrets |
| Trivy | Scans infrastructure configuration for security issues |

---

## Repository Structure

```text
CloudVPN-IaC/
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── ansible/
│   ├── ansible.cfg
│   ├── playbook.yml
│   ├── requirements.txt
│   ├── requirements.yml
│   │
│   ├── inventory/
│   │   └── hosts.example.yml
│   │
│   ├── playbooks/
│   │   └── wireguard.yml
│   │
│   ├── roles/
│   │   └── wireguard/
│   │       ├── defaults/
│   │       ├── files/
│   │       ├── tasks/
│   │       └── templates/
│   │
│   └── vars/
│       └── client1.example.yml
│
├── config/
│   └── deployment.example.json
│
├── docs/
│   └── security-exceptions.md
│
├── scripts/
│   ├── configure.sh
│   ├── generate-inventory.sh
│   ├── manage-clients.py
│   ├── server-key-authorization.py
│   └── terraform-plan-needs-server-key.py
│
├── terraform/
│   ├── modules/
│   ├── main.tf
│   ├── outputs.tf
│   ├── variables.tf
│   ├── versions.tf
│   └── .terraform.lock.hcl
│
├── tests/
│   ├── client_management/
│   ├── controller/
│   └── firewall/
│
├── cloudvpn
├── .gitignore
├── .gitattributes
├── LICENSE
└── README.md
```

The repository also contains local configuration and generated files that are intentionally excluded from Git.

---

## Security Architecture

Security is incorporated into the infrastructure and configuration-management design.

### 1. IAM Instance Role

The EC2 instance uses an IAM instance role to obtain AWS permissions.

This avoids storing long-lived AWS access keys on the VPN server.

The instance role provides the permissions required for Systems Manager functionality.

### 2. AWS Systems Manager

Systems Manager provides remote administration.

The architecture avoids exposing SSH port 22 to the internet.

The Ansible SSM connection plugin uses the EC2 instance ID, AWS region, and an S3 transfer bucket.

### 3. IMDSv2

The EC2 instance metadata configuration uses IMDSv2 to strengthen access to instance metadata.

### 4. WireGuard Key Protection

WireGuard private keys require restricted filesystem permissions.

The Ansible configuration:

- Preserves existing server keys by default.
- Does not automatically regenerate existing server keys.
- Requires explicit opt-in for server key generation.
- Restricts private-key file permissions.
- Uses protected handling for sensitive key material.

The default configuration sets:

```yaml
wireguard_server_key_generation_enabled: false
```

### 5. Firewall Management

The Ansible role manages firewall configuration and lifecycle operations.

The implementation includes:

- Firewall rule installation.
- Rule normalization.
- Rollback handling.
- Persistence support.
- Systemd startup ordering.
- Firewall disable handling.

Firewall changes should be validated carefully before deployment because incorrect rules can interrupt VPN connectivity.

### 6. Network Security

The infrastructure uses security groups and network ACLs to control network access.

Some outbound permissions are required for full-tunnel VPN functionality. These are documented separately under [Security Exceptions](#security-exceptions).

---

### 7. Deployment Controller Protection

The `cloudvpn` controller coordinates infrastructure deployment and destruction.

Security controls include:

- Exclusive controller locking using `flock`.
- Protection against unsafe lock-file types and symlinks.
- One-time server-key generation authorization.
- Authorization bound to the newly created EC2 instance ID.
- Atomic authorization marker updates.
- Restricted authorization file permissions.
- Authorization consumption after successful Ansible configuration.
- Authorization preservation when deployment fails, allowing controlled retries.

The authorization helper is:

`scripts/server-key-authorization.py`

Terraform plan analysis helps distinguish new or replaced EC2 instances from existing infrastructure.

### 8. Client Management Security

Client registration and revocation are handled by:

`scripts/manage-clients.py`

Security controls include:

- Client-name validation.
- WireGuard public-key validation.
- Duplicate client-name and VPN-address protection.
- Client registry validation.
- Client revocation.
- Protection against unsafe registry file handling.

The management utility updates the local client registry. Registration or revocation through this utility does not itself modify the running VPN server.

## Prerequisites

The following tools are required on the deployment workstation.

| Tool | Requirement | Purpose |
|---|---|---|
| Git | Installed | Clone and manage the repository |
| Terraform | >= 1.6.0; CI-tested with 1.17.1 | Infrastructure provisioning |
| Python | Python 3 | Configuration generator and tests |
| pip | Compatible with installed Python | Python dependencies |
| Ansible Core | 2.21.3 | Server configuration |
| AWS CLI | Version 2 recommended | AWS authentication and API access |
| Session Manager plugin | Installed and configured | SSM-based Ansible connections |
| WireGuard client | Compatible client application | VPN connectivity |

The AWS provider is constrained to `~> 6.0`. The committed Terraform dependency lock file records version `6.64.0`.

### Python Environment

It is recommended to use a Python virtual environment.

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

### Install Ansible Dependencies

Install the pinned Python dependencies:

```bash
python -m pip install -r ansible/requirements.lock.txt
```

### Install the required Ansible collections:

```bash
ansible-galaxy collection install -r ansible/requirements.yml
```

---

## Configuration

The project uses a central JSON configuration file.

First, create the local configuration:

```bash
cp config/deployment.example.json config/deployment.json
```

Edit:

```text
config/deployment.json
```

The example configuration contains these sections:

| Section | Purpose |
|---|---|
| schema_version | Configuration schema version |
| aws | AWS region |
| project | Project and deployment identification |
| network | VPC and subnet configuration |
| ec2 | Instance type and root volume size |
| wireguard | VPN server settings |
| client | VPN client settings |
| ssm | SSM transfer bucket configuration |

The SSM bucket name must be replaced with a valid bucket name.

### Configuration Generator

Run:

```bash
./scripts/configure.sh
```

The script:

1. Reads the local JSON configuration.
2. Validates required configuration sections.
3. Validates network CIDRs and IP addresses.
4. Validates AWS region, instance settings, and WireGuard parameters.
5. Generates Terraform variables.
6. Generates Ansible variables.
7. Writes generated files atomically.
8. Sets generated file permissions to `600`.

Generated files:

```text
terraform/terraform.auto.tfvars.json
ansible/vars/deployment.yml
```

The configuration generator does not make AWS API calls.

The generated Terraform and Ansible files are local deployment artifacts and must not be committed.

---

## Deployment Workflow

The deployment process is divided into infrastructure provisioning and server configuration.

### Step 1: Generate Configuration

From the repository root:

```bash
./scripts/configure.sh
```

Review the configuration before continuing.

### Step 2: Initialize Terraform

```bash
terraform -chdir=terraform init
```

### Step 3: Validate Terraform

```bash
terraform -chdir=terraform validate
```

### Step 4: Review the Deployment Plan

```bash
terraform -chdir=terraform plan
```

Review the proposed changes carefully.

### Step 5: Provision AWS Infrastructure

Only after reviewing and approving the plan:

```bash
terraform -chdir=terraform apply
```

Terraform provisions the AWS infrastructure defined by the project.

### Step 6: Generate the Ansible Inventory

After successful infrastructure provisioning, generate the inventory:

```bash
./scripts/generate-inventory.sh YOUR_SSM_BUCKET_NAME
```

Alternatively, provide the bucket name through the environment:

```bash
export SSM_BUCKET_NAME="YOUR_SSM_BUCKET_NAME"

./scripts/generate-inventory.sh
```

The inventory generator:

- Reads the EC2 instance ID from Terraform outputs.
- Reads the AWS region from Terraform outputs.
- Verifies access to the S3 transfer bucket.
- Generates an inventory using `amazon.aws.aws_ssm`.
- Writes the inventory atomically.
- Restricts inventory permissions to `600`.

This script makes AWS API calls. It is not part of local-only configuration validation.

The generated inventory is:

```text
ansible/inventory/hosts.yml
```

### Step 7: Configure the VPN Server

Run the Ansible playbook from the Ansible directory:

```bash
cd ansible

ANSIBLE_CONFIG="$PWD/ansible.cfg" \
ansible-playbook \
  -i inventory/hosts.yml \
  playbooks/wireguard.yml
```

Ansible connects through AWS Systems Manager and configures the VPN server.

The playbook manages WireGuard installation, IPv4 forwarding, key handling, WireGuard configuration, and firewall operations.

### Step 8: Verify the VPN Server

On the VPN server, inspect the WireGuard interface:

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

Verify the firewall configuration and confirm that the VPN interface is operational.

### Step 9: Connect the VPN Client

Import the generated client configuration into the WireGuard application.

Activate the VPN connection and verify that internet traffic exits through the AWS VPN server when full-tunnel routing is configured.

---

## WireGuard Client Configuration

The example deployment configuration defines:

| Parameter | Example |
|---|---|
| Client name | client1 |
| Client address | 10.8.0.2/32 |
| DNS | 1.1.1.1 |
| Allowed IPs | 0.0.0.0/0, ::/0 |
| Persistent Keepalive | 25 seconds |

The client configuration should contain the appropriate private key and server public key.

Never commit generated client configuration files or client private keys.

---

## Validation and Testing

The project includes local validation and automated tests.

### Terraform Validation

```bash
terraform -chdir=terraform fmt -check -recursive

terraform -chdir=terraform validate
```

### Ansible Syntax Validation

```bash
cd /home/rupankar/projects/CloudVPN-IaC

ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg" \
ansible-playbook \
  -i ansible/inventory/hosts.example.yml \
  ansible/playbooks/wireguard.yml \
  --syntax-check \
  -e wireguard_client_vars_file=ansible/vars/client1.example.yml
```

### Controller and Authorization Tests

```bash
python3 -m unittest discover -s tests/controller -v
```

### Client Management Tests

```bash
python3 -m unittest discover \
  -s tests/client_management \
  -v
```

### Firewall Tests

```bash
python3 -m unittest discover \
  -s tests/firewall \
  -p 'test_*.py' \
  -v
```

### Secret Scanning

Gitleaks is used to scan repository content for potentially exposed secrets.

### Infrastructure Security Scanning

Trivy is used to scan Terraform infrastructure configuration for security issues.

The CI security scan is currently report-only for Trivy findings. A successful CI run should not be interpreted as proof that the infrastructure is completely secure.

---

## Continuous Integration

GitHub Actions is configured through:

```text
.github/workflows/ci.yml
```

The workflow contains six jobs:

| Job | Purpose |
|---|---|
| terraform | Terraform formatting and validation |
| ansible | Ansible dependency installation and syntax validation |
| python-tests | Controller, authorization, client-management, and Python compilation tests |
| firewall-tests | Firewall shell and Python unit tests |
| gitleaks | Secret scanning |
| trivy | Terraform security scanning |

The workflow is intended to validate repository changes without provisioning AWS infrastructure.

The CI configuration uses example deployment settings and placeholder values for validation.

Actual GitHub Actions execution must be verified after the workflow is pushed to GitHub.

---

## Security Exceptions

The project documents security exceptions in:

```text
docs/security-exceptions.md
```

The documented exceptions relate to network egress requirements for full-tunnel VPN operation.

These exceptions should be reviewed before production use.

A security scan may identify broad egress rules even when they are intentional for the current VPN architecture.

The exceptions are documented rather than treated as automatically approved security controls.

---

## Sensitive Files and Git Security

The following files must never be committed:

- Terraform state files.
- Terraform variable files containing sensitive information.
- AWS credentials.
- WireGuard server private keys.
- WireGuard client private keys.
- Generated client configurations.
- Actual local Ansible inventory files.
- Generated deployment variables.
- Local environment files.

Example files containing placeholders may be committed.

The repository uses `.gitignore` to exclude local and generated artifacts and `.gitattributes` to help maintain consistent line endings.

Before publishing the repository, inspect the Git tracking status and run secret scanning.

Do not publish Terraform state or generated credentials, even if they appear to contain no obvious secrets.

---

## Cost Considerations

AWS resources may incur charges, including:

- EC2 compute.
- Elastic IP addresses.
- EBS storage.
- Network data transfer.
- S3 storage and requests.
- Other supporting AWS services.

Actual costs depend on the AWS region, instance type, usage duration, data-transfer volume, and applicable AWS pricing.

Review AWS billing and cost estimates before deployment.

---

## Future Security Integration

The architecture is designed to support additional security capabilities.

| Service | Planned Purpose |
|---|---|
| Amazon CloudWatch | Infrastructure monitoring and alerting |
| Amazon GuardDuty | Threat detection |
| AWS Security Hub | Centralized security findings |
| AWS CloudTrail | API activity auditing |
| AWS Systems Manager Patch Manager | Automated patch management |
| AWS Secrets Manager | Centralized secret management where appropriate |

These integrations are planned enhancements and are not represented as currently deployed.

---

## Disclaimer

This project is intended for educational purposes and personal infrastructure experimentation.

It should not be considered production-ready without additional security review, operational testing, access-control review, monitoring, backup planning, and cost analysis.

Review AWS security settings, IAM permissions, network rules, VPN configurations, and billing implications before deploying in a production environment.

---

## License

This project is licensed under the MIT License.
