#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CONFIG_FILE="$PROJECT_ROOT/config/deployment.json"
TERRAFORM_OUTPUT="$PROJECT_ROOT/terraform/terraform.auto.tfvars.json"
ANSIBLE_OUTPUT="$PROJECT_ROOT/ansible/vars/deployment.yml"

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: Python 3 is required."
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: Configuration not found: $CONFIG_FILE"
    echo "Copy config/deployment.example.json to config/deployment.json."
    exit 1
fi

python3 - "$CONFIG_FILE" "$TERRAFORM_OUTPUT" "$ANSIBLE_OUTPUT" <<'PY'
import ipaddress
import json
import os
import re
import sys
import tempfile
from pathlib import Path

config_path = Path(sys.argv[1])
terraform_path = Path(sys.argv[2])
ansible_path = Path(sys.argv[3])

def fail(message):
    raise SystemExit(f"ERROR: {message}")

def required(mapping, key, section):
    if key not in mapping:
        fail(f"Missing configuration: {section}.{key}")
    return mapping[key]

def validate_string(value, label, pattern=None):
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
    if pattern and not re.fullmatch(pattern, value):
        fail(f"Invalid {label}: {value}")

try:
    config = json.loads(config_path.read_text())
except (OSError, json.JSONDecodeError) as exc:
    fail(f"Cannot read configuration: {exc}")

if not isinstance(config, dict):
    fail("Configuration root must be a JSON object")

expected = {
    "schema_version", "aws", "project", "network",
    "ec2", "wireguard", "client", "ssm"
}

if set(config) != expected:
    fail(
        f"Configuration sections mismatch. "
        f"Missing: {sorted(expected - set(config))}; "
        f"unexpected: {sorted(set(config) - expected)}"
    )

if config["schema_version"] != 1:
    fail("Unsupported configuration schema version")

for section in expected - {"schema_version"}:
    if not isinstance(config[section], dict):
        fail(f"Section {section} must be an object")

aws = config["aws"]
project = config["project"]
network = config["network"]
ec2 = config["ec2"]
wg = config["wireguard"]
client = config["client"]
ssm = config["ssm"]

region = required(aws, "region", "aws")
validate_string(region, "AWS region", r"[a-z]{2}(?:-gov)?-[a-z]+-\d+")

name = required(project, "name", "project")
deployment_id = required(project, "deployment_id", "project")
environment = required(project, "environment", "project")
owner = required(project, "owner", "project")

validate_string(name, "project.name", r"[A-Za-z0-9][A-Za-z0-9_-]{0,30}")
validate_string(deployment_id, "project.deployment_id", r"[a-z][a-z0-9-]{2,30}")
validate_string(environment, "project.environment", r"[A-Za-z0-9_-]{1,30}")
validate_string(owner, "project.owner")

vpc = ipaddress.ip_network(required(network, "vpc_cidr", "network"), strict=True)
subnet = ipaddress.ip_network(
    required(network, "public_subnet_cidr", "network"), strict=True
)

if vpc.version != 4 or subnet.version != 4:
    fail("VPC and public subnet must use IPv4")

if not subnet.subnet_of(vpc):
    fail("Public subnet must be contained within the VPC CIDR")

az = required(network, "availability_zone", "network")
if az is not None:
    validate_string(az, "network.availability_zone", r"[a-z]{2}(?:-gov)?-[a-z]+-\d+[a-z]")

instance_type = required(ec2, "instance_type", "ec2")
validate_string(instance_type, "EC2 instance type", r"[a-z0-9]+[a-z0-9.]*")

volume_size = required(ec2, "root_volume_size", "ec2")
if type(volume_size) is not int or not 8 <= volume_size <= 16384:
    fail("ec2.root_volume_size must be an integer between 8 and 16384")

port = required(wg, "port", "wireguard")
if type(port) is not int or not 1 <= port <= 65535:
    fail("wireguard.port must be an integer between 1 and 65535")

interface = required(wg, "interface", "wireguard")
validate_string(interface, "wireguard.interface", r"[A-Za-z0-9_.-]{1,15}")

vpn_network = ipaddress.ip_network(
    required(wg, "network", "wireguard"), strict=True
)
server_address = ipaddress.ip_interface(
    required(wg, "server_address", "wireguard")
)

if vpn_network.version != 4 or server_address.version != 4:
    fail("This configuration currently supports IPv4 WireGuard networks only")

if server_address.ip not in vpn_network:
    fail("WireGuard server address must belong to the VPN network")

if server_address.network.prefixlen != vpn_network.prefixlen:
    fail("WireGuard server address prefix must match the VPN network prefix")

dns = required(wg, "dns", "wireguard")
ipaddress.ip_address(dns)

firewall_enabled = required(wg, "firewall_enabled", "wireguard")
if type(firewall_enabled) is not bool:
    fail("wireguard.firewall_enabled must be true or false")

client_name = required(client, "name", "client")
validate_string(client_name, "client.name", r"[A-Za-z0-9_-]{1,32}")

client_address = ipaddress.ip_interface(
    required(client, "address", "client")
)

if client_address.version != 4 or client_address.ip not in vpn_network:
    fail("Client address must belong to the VPN network")

if client_address.ip == server_address.ip:
    fail("Server and client addresses must be different")

client_dns = required(client, "dns", "client")
ipaddress.ip_address(client_dns)

allowed_ips = required(client, "allowed_ips", "client")
validate_string(allowed_ips, "client.allowed_ips")

keepalive = required(client, "persistent_keepalive", "client")
if type(keepalive) is not int or not 0 <= keepalive <= 65535:
    fail("Client persistent_keepalive must be an integer from 0 to 65535")

bucket = required(ssm, "bucket_name", "ssm")
validate_string(bucket, "SSM bucket name")

if bucket == "REPLACE_WITH_YOUR_SSM_BUCKET":
    fail("Replace the SSM bucket placeholder before configuration")

if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
    fail("Invalid S3 bucket name format")

# Terraform receives only infrastructure configuration.
terraform_vars = {
    "aws_region": region,
    "project_name": name,
    "environment": environment,
    "owner": owner,
    "vpc_cidr": str(vpc),
    "public_subnet_cidr": str(subnet),
    "availability_zone": az,
    "wireguard_port": port,
    "ec2_instance_type": instance_type,
    "root_volume_size": volume_size,
}

# JSON is also valid YAML. This avoids adding a YAML dependency.
ansible_vars = {
    "wireguard_interface": interface,
    "wireguard_port": port,
    "wireguard_network": str(vpn_network),
    "wireguard_server_address": str(server_address),
    "wireguard_client_name": client_name,
    "wireguard_client_address": str(client_address),
    "wireguard_dns": dns,
    "wireguard_client_dns": client_dns,
    "wireguard_firewall_enabled": firewall_enabled,
    "wireguard_firewall_persist": True,
    "wireguard_server_key_generation_enabled": False,
    "cloudvpn_deployment_id": deployment_id,
    "cloudvpn_project_name": name,
}

def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent
    )

    try:
        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temp_name, path)
        os.chmod(path, 0o600)

    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise

atomic_write(
    terraform_path,
    json.dumps(terraform_vars, indent=2) + "\n"
)

atomic_write(
    ansible_path,
    json.dumps(ansible_vars, indent=2) + "\n"
)

print("Configuration validation: PASS")
print("Terraform variables generated.")
print("Ansible variables generated.")
print("Generated files have permissions 600.")
print("No AWS API calls were made.")
PY
