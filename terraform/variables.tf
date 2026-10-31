#########################################
# AWS Configuration
#########################################

variable "aws_region" {
  description = "AWS Region"
  type        = string
  default     = "ap-south-1"
}

variable "aws_profile" {
  description = "AWS CLI Profile"
  type        = string
  default     = "default"
}

#########################################
# Project Information
#########################################

variable "project_name" {
  description = "Project Name"
  type        = string
  default     = "CloudVPN-IaC"
}

variable "environment" {
  description = "Deployment Environment"
  type        = string
  default     = "Dev"
}

variable "owner" {
  description = "Project Owner"
  type        = string
  default     = "Your Name"
}

#########################################
# Networking
#########################################

variable "vpc_cidr" {
  description = "CIDR block of VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block of Public Subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "availability_zone" {
  description = "Availability Zone"
  type        = string
  default     = "ap-south-1a"
}

#########################################
# Security
#########################################

variable "wireguard_port" {
  description = "WireGuard UDP Port"
  type        = number
  default     = 51820
}

variable "ec2_instance_type" {
  description = "EC2 instance type for the VPN server"
  type        = string
  default     = "t3.micro"
}

variable "root_volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 20
}