output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "public_subnet_id" {
  description = "Public subnet ID"
  value       = module.vpc.public_subnet_id
}

output "internet_gateway_id" {
  description = "Internet Gateway ID"
  value       = module.vpc.internet_gateway_id
}

output "public_route_table_id" {
  description = "Public route table ID"
  value       = module.vpc.public_route_table_id
}

output "network_acl_id" {
  description = "Network ACL ID"
  value       = module.security.network_acl_id
}

output "wireguard_security_group_id" {
  description = "WireGuard Security Group ID"
  value       = module.security.security_group_id
}

output "ec2_instance_id" {
  description = "VPN EC2 instance ID"
  value       = module.ec2.instance_id
}

output "vpn_public_ip" {
  description = "Stable public IP address of the VPN server (Elastic IP)"
  value       = module.ec2.vpn_elastic_ip
}

output "vpn_private_ip" {
  description = "VPN server private IP"
  value       = module.ec2.private_ip
}

output "vpn_elastic_ip" {
  description = "Elastic IP address of the VPN server"
  value       = module.ec2.vpn_elastic_ip
}

output "aws_region" {
  description = "AWS region hosting the VPN infrastructure"
  value       = var.aws_region
}
