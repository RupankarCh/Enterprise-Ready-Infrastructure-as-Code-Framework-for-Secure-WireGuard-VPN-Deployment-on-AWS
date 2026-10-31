output "instance_id" {
  description = "VPN EC2 instance ID"
  value       = aws_instance.vpn.id
}

output "public_ip" {
  description = "VPN server public IP"
  value       = aws_instance.vpn.public_ip
}

output "private_ip" {
  description = "VPN server private IP"
  value       = aws_instance.vpn.private_ip
}

output "availability_zone" {
  description = "VPN server Availability Zone"
  value       = aws_instance.vpn.availability_zone
}

output "vpn_elastic_ip" {
  description = "Elastic IP address of the VPN server"
  value       = aws_eip.vpn.public_ip
}
