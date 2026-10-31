output "security_group_id" {
  description = "WireGuard security group ID"
  value       = aws_security_group.wireguard.id
}

output "network_acl_id" {
  description = "Network ACL ID"
  value       = aws_network_acl.main.id
}