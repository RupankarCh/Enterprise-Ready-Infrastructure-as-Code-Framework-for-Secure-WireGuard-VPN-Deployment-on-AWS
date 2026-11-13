#!/usr/bin/env python3

import json
import sys


def needs_server_key_generation(plan):
    for resource in plan.get("resource_changes", []):
        if resource.get("type") != "aws_instance":
            continue

        if not resource.get("address", "").endswith(".aws_instance.vpn"):
            continue

        actions = resource.get("change", {}).get("actions", [])

        if "create" in actions:
            return True

    return False


def main():
    try:
        plan = json.load(sys.stdin)
        result = needs_server_key_generation(plan)
        print("true" if result else "false")

    except (json.JSONDecodeError, TypeError, AttributeError) as exc:
        print(f"Invalid Terraform plan JSON: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
