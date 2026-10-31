# CloudVPN-IaC

### Infrastructure as Code for a Personal Cloud VPN on AWS

CloudVPN-IaC is a personal cloud VPN infrastructure project that uses Terraform, Ansible, AWS Systems Manager, and WireGuard to build and configure a self-managed VPN server on Amazon Web Services.

The goal is to create a secure, reproducible, and cost-conscious VPN deployment without exposing SSH access or storing long-lived AWS credentials on the EC2 instance.

## Architecture

The planned architecture uses:

* **Amazon VPC** – Isolated networking environment.
* **Public Subnet** – Hosts the VPN server.
* **Internet Gateway** – Provides internet connectivity.
* **Route Table** – Controls network routing.
* **Amazon EC2** – Ubuntu-based VPN server.
* **Elastic IP** – Persistent public endpoint.
* **Security Groups** – Controls inbound and outbound traffic.
* **AWS IAM Role** – Grants the EC2 instance required AWS permissions.
* **AWS Systems Manager (SSM)** – Enables remote instance management without SSH.
* **Terraform** – Provisions AWS infrastructure.
* **Ansible** – Automates server configuration.
* **WireGuard** – Provides VPN functionality.

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
| Git / GitHub        | Version control                |

## Security Design

The project follows several security principles:

* No inbound SSH access is required for instance administration.
* AWS IAM instance roles are used instead of storing AWS credentials on the EC2 instance.
* Systems Manager provides remote management.
* IMDSv2 is required for instance metadata access.
* The EC2 source/destination check is disabled to support VPN routing.
* Terraform state files and local configuration files are excluded from version control.
* WireGuard uses UDP port 51820.

## Repository Structure

```text
CloudVPN-IaC/
├── .github/
│   └── workflows/
├── ansible/
│   ├── inventory/
│   ├── playbooks/
│   └── roles/
│       └── wireguard/
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

## Current Development Status

### Implemented and verified

* AWS infrastructure provisioned using Terraform.
* EC2 instance deployed.
* VPC and networking resources configured.
* Elastic IP associated with the VPN server.
* IAM instance role configured.
* AWS Systems Manager connectivity verified.
* Ansible connectivity through SSM verified.
* EC2 source/destination check disabled.
* Terraform configuration validated.

### In progress

* Complete WireGuard server configuration.
* Configure IPv4 forwarding and NAT.
* Implement VPN client key generation.
* Generate client configuration files.
* Verify end-to-end VPN connectivity.
* Complete deployment automation.
* Add monitoring and operational documentation.

**Note:** The repository currently represents an infrastructure deployment and an ongoing VPN implementation. A fully operational VPN has not yet been verified.

## Prerequisites

* AWS account.
* AWS CLI.
* Terraform.
* Ansible.
* AWS Session Manager plugin.
* Python and required Ansible collections.
* Git.

## Deployment Overview

1. Configure AWS CLI credentials locally.
2. Initialize Terraform.
3. Review the Terraform execution plan.
4. Provision the AWS infrastructure.
5. Configure the Ansible SSM inventory.
6. Verify connectivity to the EC2 instance.
7. Deploy and configure WireGuard.
8. Configure and test VPN clients.

Refer to the documentation directory as the deployment guides are completed.

## Cost Considerations

AWS resources may incur charges while running, including EC2 compute, Elastic IP, EBS storage, and monitoring services.

Actual costs depend on the AWS region, instance type, usage duration, and applicable AWS pricing.

Always review AWS billing and clean up resources that are no longer required.

## Disclaimer

This project is intended for educational purposes and personal infrastructure experimentation. Review AWS security settings, IAM permissions, networking rules, and billing implications before deploying it in a production environment.

## License

This project is licensed under the MIT License.

