#!/usr/bin/env bash

set -Eeuo pipefail

# Resolve project root independently of current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TERRAFORM_DIR="$PROJECT_ROOT/terraform"
INVENTORY_DIR="$PROJECT_ROOT/ansible/inventory"
INVENTORY_FILE="$INVENTORY_DIR/hosts.yml"

# Accept S3 bucket as argument or environment variable
SSM_BUCKET_NAME="${1:-${SSM_BUCKET_NAME:-}}"

# Check required commands
for command in terraform aws; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $command"
        exit 1
    fi
done

# Validate bucket input
if [[ -z "$SSM_BUCKET_NAME" ]]; then
    echo "ERROR: SSM bucket name is required."
    echo "Usage: $0 <s3-bucket-name>"
    echo "Or set SSM_BUCKET_NAME environment variable."
    exit 1
fi

if [[ ! "$SSM_BUCKET_NAME" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
    echo "ERROR: Invalid S3 bucket name format."
    exit 1
fi

# Ensure Terraform configuration exists
if [[ ! -d "$TERRAFORM_DIR" ]]; then
    echo "ERROR: Terraform directory not found."
    exit 1
fi

# Read values from Terraform state
echo "Reading Terraform outputs..."

EC2_INSTANCE_ID="$(
    terraform -chdir="$TERRAFORM_DIR" output -raw ec2_instance_id
)"

AWS_REGION="$(
    terraform -chdir="$TERRAFORM_DIR" output -raw aws_region
)"

# Validate Terraform outputs
if [[ ! "$EC2_INSTANCE_ID" =~ ^i-[a-f0-9]+$ ]]; then
    echo "ERROR: Invalid EC2 instance ID returned by Terraform."
    exit 1
fi

if [[ ! "$AWS_REGION" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]]; then
    echo "ERROR: Invalid AWS region returned by Terraform."
    exit 1
fi

# Verify access to the S3 transfer bucket
echo "Checking S3 bucket access..."

if ! aws s3api head-bucket \
    --bucket "$SSM_BUCKET_NAME" \
    --region "$AWS_REGION"; then
    echo "ERROR: Cannot access the specified S3 bucket."
    exit 1
fi

# Create inventory directory if needed
mkdir -p "$INVENTORY_DIR"

# Generate inventory atomically
TEMP_FILE="$(mktemp "$INVENTORY_DIR/.hosts.yml.XXXXXX")"

trap 'rm -f "$TEMP_FILE"' EXIT

cat > "$TEMP_FILE" <<EOF
---
all:
  children:
    wireguard:
      hosts:
        vpn-server:
          ansible_host: "$EC2_INSTANCE_ID"
          ansible_connection: amazon.aws.aws_ssm
          ansible_aws_ssm_region: "$AWS_REGION"
          ansible_aws_ssm_bucket_name: "$SSM_BUCKET_NAME"
EOF

chmod 600 "$TEMP_FILE"
mv "$TEMP_FILE" "$INVENTORY_FILE"

trap - EXIT

echo
echo "Ansible inventory generated successfully."
echo "EC2 Instance: $EC2_INSTANCE_ID"
echo "AWS Region:   $AWS_REGION"
echo "SSM Bucket:   $SSM_BUCKET_NAME"
echo "Inventory:    $INVENTORY_FILE"
