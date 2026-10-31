resource "aws_network_acl" "main" {
  vpc_id = var.vpc_id

  tags = {
    Name = "${var.project_name}-nacl"
  }
}

resource "aws_network_acl_rule" "inbound" {
  network_acl_id = aws_network_acl.main.id

  rule_number = 100
  egress      = false

  protocol    = "-1"
  rule_action = "allow"

  cidr_block = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "outbound" {
  network_acl_id = aws_network_acl.main.id

  rule_number = 100
  egress      = true

  protocol    = "-1"
  rule_action = "allow"

  cidr_block = "0.0.0.0/0"
}

resource "aws_network_acl_association" "public" {
  network_acl_id = aws_network_acl.main.id
  subnet_id      = var.public_subnet_id
}

resource "aws_security_group" "wireguard" {
  name        = "${var.project_name}-wireguard-sg"
  description = "Security group for WireGuard VPN"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project_name}-wireguard-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "wireguard" {
  security_group_id = aws_security_group.wireguard.id

  description = "WireGuard VPN traffic"

  ip_protocol = "udp"
  from_port   = var.wireguard_port
  to_port     = var.wireguard_port

  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.wireguard.id

  description = "HTTPS traffic"

  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443

  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.wireguard.id

  description = "Allow outbound traffic"

  ip_protocol = "-1"
  cidr_ipv4   = "0.0.0.0/0"
}