# CloudVPN Security Exception Register

- **Project:** Personal VPN
- **Environment:** AWS
- **Region:** ap-south-1
- **Document status:** Proposed exceptions — pending formal approval
**Review frequency:** Every 90 days and after significant architecture changes

---

## 1. Purpose

This document records security scanner findings that are currently
retained because of the VPN's full-tunnel networking requirements.

These exceptions are not automatically approved risk acceptances.
They require review by the project security owner.

## 2. AWS-0102 — Unrestricted Outbound Network ACL

- **Severity:** Critical
- **Resource:** `aws_network_acl_rule.outbound`
- **Location:** `terraform/modules/security/main.tf`
- **Current configuration:** `protocol = "-1"`
**Destination:** `0.0.0.0/0`

### Business justification

The VPN provides full-tunnel connectivity. VPN clients may need to
access arbitrary internet destinations and use different IP protocols.

A restrictive outbound NACL could interrupt legitimate VPN traffic.

### Existing security controls

- Inbound NACL rules are explicitly defined.
- The host firewall controls forwarded VPN-client traffic.
- Private RFC1918 destination ranges are blocked by the VPN forwarding policy.
- Link-local destinations are blocked.
- Established return traffic is explicitly permitted.
- Unexpected traffic involving the VPN interface is dropped.

### Residual risk

The outbound NACL permits all outbound protocols and destinations.
The host firewall's forwarding policy does not constitute a complete
restriction on traffic originating directly from the EC2 host.

### Proposed treatment

Retain provisionally, subject to security-owner approval.

Evaluate whether outbound NACL restrictions can be introduced without
breaking full-tunnel connectivity or stateless return traffic.

---

## 3. AWS-0104 — Unrestricted Security Group Egress

- **Severity:** Critical
- **Resource:** `aws_vpc_security_group_egress_rule.all`
- **Location:** `terraform/modules/security/main.tf`
- **Current configuration:** `ip_protocol = "-1"`
**Destination:** `0.0.0.0/0`

### Business justification

The VPN server requires outbound connectivity for client traffic
forwarding and server operations, including DNS, software updates,
and management-related communications.

Restricting egress to a small set of ports could interrupt legitimate
VPN client applications.

### Existing security controls

- VPN forwarding is controlled by the CloudVPN host firewall.
- Private-network destinations are blocked for forwarded VPN traffic.
- Link-local destinations are blocked.
- The EC2 instance uses an IAM role rather than stored AWS credentials.
- The EC2 instance requires IMDSv2.

### Residual risk

The security group allows unrestricted outbound traffic from the
EC2 network interface.

The host forwarding firewall does not restrict every connection
originating directly from the EC2 host.

### Proposed treatment

Retain provisionally, subject to security-owner approval.

Evaluate destination-aware egress controls, DNS requirements,
management dependencies and operational impact before narrowing rules.

---

## 4. Related Security Architecture

The following controls are implemented in the project configuration:

| Control | Implementation |
|---|---|
| VPN tunnel | WireGuard |
| VPN network forwarding | IPv4 forwarding |
| VPN internet NAT | iptables MASQUERADE |
| VPN client isolation | CloudVPN FORWARD chain |
| Private network protection | RFC1918 destination drops |
| Link-local protection | Link-local destination drops |
| Return traffic | Conntrack RELATED,ESTABLISHED |
| Firewall persistence | systemd service |
| Firewall startup dependency | WireGuard systemd drop-in |
| EC2 management | AWS Systems Manager |
| Instance credentials | IAM instance role |
| Metadata protection | IMDSv2 required |
| Root storage | Encrypted gp3 volume |
| Public endpoint | Elastic IP |
| Automatic subnet public IP | Disabled |

These controls have been reviewed in local configuration. Their
effective runtime enforcement has not been established by this document.

## 5. Validation Evidence

| Validation | Recorded result |
|---|---|
| Terraform validate | Passed |
| Terraform formatting check | Passed |
| Isolated VPC Trivy scan | 0 findings |
| Isolated security-module Trivy scan | 2 critical findings |
| Firewall automated tests | 45 passed |
| Firewall Bash syntax | Passed |
| Ansible syntax | Passed |

No AWS deployment or runtime security verification is implied.

## 6. Future Security Improvements

1. Evaluate VPC Flow Logs with an explicit cost assessment.
2. Evaluate centralized security monitoring and alerting.
3. Review server-originated outbound traffic separately from forwarded
   VPN-client traffic.
4. Evaluate DNS-aware egress restrictions.
5. Review NACL ephemeral-port requirements.
6. Introduce periodic security configuration audits.
7. Reassess these exceptions after architecture changes.

## 7. Approval Record

| Field | Value |
|---|---|
| Security owner | Pending assignment |
| AWS-0102 approval | Pending |
| AWS-0104 approval | Pending |
| Approval date | Pending |
| Next review date | Pending |

**Important:** Scanner findings must not be suppressed merely to obtain
a clean scan. Any future exception or remediation must preserve the
documented security rationale and VPN functionality.
