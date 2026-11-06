# Discover available Availability Zones in the selected AWS region
data "aws_availability_zones" "available" {
  state = "available"
}

# Use the user-selected AZ or automatically select the first available AZ
locals {
  selected_availability_zone = (
    var.availability_zone != null
    ? var.availability_zone
    : sort(data.aws_availability_zones.available.names)[0]
  )
}

module "vpc" {
  source = "./modules/vpc"

  project_name       = var.project_name
  vpc_cidr           = var.vpc_cidr
  public_subnet_cidr = var.public_subnet_cidr
  availability_zone  = local.selected_availability_zone
}

module "security" {
  source = "./modules/security"

  project_name     = var.project_name
  vpc_id           = module.vpc.vpc_id
  public_subnet_id = module.vpc.public_subnet_id
  wireguard_port   = var.wireguard_port
}

module "ec2" {
  source = "./modules/ec2"

  project_name = var.project_name

  public_subnet_id = module.vpc.public_subnet_id

  security_group_id = module.security.security_group_id

  instance_type = var.ec2_instance_type

  root_volume_size = var.root_volume_size
}
