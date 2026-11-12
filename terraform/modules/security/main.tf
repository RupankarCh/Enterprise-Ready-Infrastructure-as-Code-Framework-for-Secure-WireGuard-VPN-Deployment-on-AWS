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

  protocol    = "udp"
  rule_action = "allow"

  from_port = var.wireguard_port
  to_port   = var.wireguard_port

  cidr_block = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "inbound_tcp_ephemeral" {
  network_acl_id = aws_network_acl.main.id

  rule_number = 110
  egress      = false

  protocol    = "tcp"
  rule_action = "allow"

  from_port = 1024
  to_port   = 65535

  cidr_block = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "inbound_udp_ephemeral" {
  network_acl_id = aws_network_acl.main.id

  rule_number = 120
  egress      = false

  protocol    = "udp"
  rule_action = "allow"

  from_port = 1024
  to_port   = 65535

  cidr_block = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "inbound_icmp_pmtu" {
  network_acl_id = aws_network_acl.main.id

  rule_number = 130
  egress      = false

  protocol    = "icmp"
  rule_action = "allow"

  from_port = 3
  to_port   = 4

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


resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.wireguard.id

  description = "Allow outbound traffic"

  ip_protocol = "-1"
  cidr_ipv4   = "0.0.0.0/0"
}
