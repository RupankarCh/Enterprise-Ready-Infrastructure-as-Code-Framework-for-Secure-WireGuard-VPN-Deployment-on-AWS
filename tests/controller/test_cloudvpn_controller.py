import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class CloudVPNControllerIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "CloudVPN-IaC"

        self.project.mkdir()

        # Copy only the source files required for isolated testing.
        for directory in (
            "scripts",
            "config",
            "ansible",
        ):
            shutil.copytree(
                ROOT / directory,
                self.project / directory,
                ignore=shutil.ignore_patterns(
                    "__pycache__",
                    "*.pyc",
                    "*.tfstate",
                    "*.tfplan",
                    "*.auto.tfvars*",
                    "inventory",
                    "output",
                ),
            )

        shutil.copy2(ROOT / "cloudvpn", self.project / "cloudvpn")

        # Add controlled failure injection to the copied authorization helper.
        authorization_script = (
            self.project
            / "scripts"
            / "server-key-authorization.py"
        )

        helper_source = authorization_script.read_text()

        injection_point = "    args = parser.parse_args()\n"

        injection_code = """    args = parser.parse_args()

    if os.environ.get("MOCK_AUTH_FAIL_ACTION") == args.action:
        print("Injected authorization failure", file=sys.stderr)
        return 1
"""

        assert injection_point in helper_source

        authorization_script.write_text(
            helper_source.replace(
                injection_point,
                injection_code,
                1,
            )
        )

        (self.project / "terraform").mkdir()

        (self.project / "terraform" / ".terraform").mkdir()

        config = json.loads(
            (
                self.project
                / "config"
                / "deployment.example.json"
            ).read_text()
        )

        config["ssm"]["bucket_name"] = "cloudvpn-test-bucket"

        (self.project / "config" / "deployment.json").write_text(
            json.dumps(config)
        )

        self.mock_bin = self.project / "mock-bin"
        self.mock_bin.mkdir()

        self.log_file = self.project / "command.log"
        self.plan_file = self.project / "plan.json"

        self.instance_id = "i-1234567890abcdef0"

        self.create_mocks()

    def tearDown(self):
        self.temp.cleanup()

    def create_mock(self, name, content):
        path = self.mock_bin / name
        path.write_text(content)
        path.chmod(0o755)

    def create_mocks(self):

        terraform = r'''#!/usr/bin/env bash

echo "terraform $*" >> "$MOCK_LOG"

for arg in "$@"; do
    case "$arg" in
        -chdir=*)
            ;;
    esac
done

case "$*" in
    *"workspace show"*)
        echo "default"
        ;;

    *"show -json"*)
        cat "$MOCK_PLAN_FILE"
        ;;

    *"output -raw ec2_instance_id"*)
        echo "$MOCK_INSTANCE_ID"
        ;;

    *"output -raw aws_region"*)
        echo "ap-south-1"
        ;;

    *"init"*)
        exit 0
        ;;

    *"validate"*)
        exit 0
        ;;

    *" plan "*)
        exit 0
        ;;

    *" apply "*)
        exit "${MOCK_TERRAFORM_APPLY_EXIT:-0}"
        ;;

    *"state list"*)
        exit 0
        ;;

    *)
        exit 0
        ;;
esac
'''

        aws = r'''#!/usr/bin/env bash

echo "aws $*" >> "$MOCK_LOG"

case "$*" in
    *"sts get-caller-identity"*)
        echo "123456789012"
        ;;

    *"ssm describe-instance-information"*)
        if [[ "${MOCK_SSM_STATUS:-Online}" == "Online" ]]; then
            echo "Online"
        else
            echo "Offline"
        fi
        ;;

    *)
        exit 0
        ;;
esac
'''

        ansible = r'''#!/usr/bin/env bash

echo "ansible-playbook $*" >> "$MOCK_LOG"

exit "${MOCK_ANSIBLE_EXIT:-0}"
'''

        sleep = r'''#!/usr/bin/env bash
exit 0
'''

        wg = r'''#!/usr/bin/env bash
exit 0
'''

        self.create_mock("terraform", terraform)
        self.create_mock("aws", aws)
        self.create_mock("ansible-playbook", ansible)
        self.create_mock("sleep", sleep)
        self.create_mock("wg", wg)

    def create_plan(self, new_instance=True):

        actions = (
            ["create"]
            if new_instance
            else ["update"]
        )

        plan = {
            "resource_changes": [
                {
                    "type": "aws_instance",
                    "address": "module.ec2.aws_instance.vpn",
                    "change": {
                        "actions": actions
                    }
                }
            ]
        }

        self.plan_file.write_text(json.dumps(plan))

    def run_controller(
        self,
        *,
        new_instance=True,
        instance_id=None,
        ssm_status="Online",
        ansible_exit=0,
        auth_fail_action=None,
        terraform_apply_exit=0,
    ):
        self.create_plan(new_instance)

        env = os.environ.copy()

        env.update({
            "PATH": (
                str(self.mock_bin)
                + os.pathsep
                + env["PATH"]
            ),
            "MOCK_LOG": str(self.log_file),
            "MOCK_AUTH_FAIL_ACTION": auth_fail_action or "",
            "MOCK_TERRAFORM_APPLY_EXIT": str(terraform_apply_exit),
            "MOCK_PLAN_FILE": str(self.plan_file),
            "MOCK_INSTANCE_ID": (
                instance_id or self.instance_id
            ),
            "MOCK_SSM_STATUS": ssm_status,
            "MOCK_ANSIBLE_EXIT": str(ansible_exit),
        })

        return subprocess.run(
            [
                "bash",
                str(self.project / "cloudvpn"),
                "deploy",
            ],
            input="123456789012\nDEPLOY\n",
            text=True,
            capture_output=True,
            env=env,
            timeout=30,
        )

    def marker(self):
        return (
            self.project
            / "terraform"
            / ".cloudvpn-server-key-generation-authorized"
        )

    def test_new_instance_success_consumes_authorization(self):

        result = self.run_controller()

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stdout + result.stderr,
        )

        self.assertFalse(self.marker().exists())

        self.assertIn(
            "wireguard_server_key_generation_enabled=true",
            self.log_file.read_text(),
        )

    def test_ssm_failure_preserves_authorization(self):

        result = self.run_controller(
            ssm_status="Offline"
        )

        self.assertNotEqual(result.returncode, 0)

        self.assertTrue(self.marker().exists())

        self.assertEqual(
            self.marker().read_text().strip(),
            self.instance_id,
        )

    def test_ansible_failure_preserves_authorization(self):

        result = self.run_controller(
            ansible_exit=1
        )

        self.assertNotEqual(result.returncode, 0)

        self.assertTrue(self.marker().exists())

        self.assertEqual(
            self.marker().read_text().strip(),
            self.instance_id,
        )

    def test_successful_retry_consumes_existing_authorization(self):

        # First deployment: authorization is created,
        # but Ansible fails.
        first = self.run_controller(
            ansible_exit=1
        )

        self.assertNotEqual(first.returncode, 0)
        self.assertTrue(self.marker().exists())

        # Retry: Terraform reports no new instance.
        second = self.run_controller(
            new_instance=False
        )

        self.assertEqual(
            second.returncode,
            0,
            msg=second.stdout + second.stderr,
        )

        self.assertFalse(self.marker().exists())

        # Both attempts must enable initial server-key generation.
        ansible_commands = [
            line
            for line in self.log_file.read_text().splitlines()
            if line.startswith("ansible-playbook ")
        ]

        self.assertEqual(len(ansible_commands), 2)

        for command in ansible_commands:
            self.assertIn(
                "wireguard_server_key_generation_enabled=true",
                command,
            )

    def test_existing_instance_does_not_create_authorization(self):

        result = self.run_controller(
            new_instance=False
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stdout + result.stderr,
        )

        self.assertFalse(self.marker().exists())

        self.assertNotIn(
            "wireguard_server_key_generation_enabled=true",
            self.log_file.read_text(),
        )

    def test_terraform_apply_failure_creates_no_authorization(self):

        result = self.run_controller(
            terraform_apply_exit=1
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker().exists())

        self.assertNotIn(
            "ansible-playbook ",
            self.log_file.read_text(),
        )

    def test_authorization_prepare_failure_stops_deployment(self):

        result = self.run_controller(
            auth_fail_action="prepare"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker().exists())

        self.assertNotIn(
            "ansible-playbook ",
            self.log_file.read_text(),
        )

    def test_authorization_bind_failure_stops_deployment(self):

        result = self.run_controller(
            auth_fail_action="bind"
        )

        self.assertNotEqual(result.returncode, 0)

        self.assertTrue(self.marker().exists())
        self.assertEqual(
            self.marker().read_text().strip(),
            "PENDING",
        )

        self.assertNotIn(
            "ansible-playbook ",
            self.log_file.read_text(),
        )

    def test_authorization_check_failure_stops_deployment(self):

        result = self.run_controller(
            auth_fail_action="check"
        )

        self.assertNotEqual(result.returncode, 0)

        self.assertEqual(
            self.marker().read_text().strip(),
            self.instance_id,
        )

        self.assertNotIn(
            "ansible-playbook ",
            self.log_file.read_text(),
        )

    def test_invalid_instance_id_rejected(self):

        result = self.run_controller(
            instance_id="invalid-instance-id"
        )

        self.assertNotEqual(result.returncode, 0)

        self.assertEqual(
            self.marker().read_text().strip(),
            "PENDING",
        )

        self.assertNotIn(
            "ansible-playbook ",
            self.log_file.read_text(),
        )

    def test_different_instance_cannot_reuse_authorization(self):

        first = self.run_controller(
            ansible_exit=1
        )

        self.assertNotEqual(first.returncode, 0)

        self.assertEqual(
            self.marker().read_text().strip(),
            self.instance_id,
        )

        different_instance = "i-0987654321abcdef0"

        second = self.run_controller(
            new_instance=False,
            instance_id=different_instance,
        )

        self.assertEqual(
            second.returncode,
            0,
            msg=second.stdout + second.stderr,
        )

        self.assertTrue(self.marker().exists())

        self.assertEqual(
            self.marker().read_text().strip(),
            self.instance_id,
        )

        ansible_commands = [
            line
            for line in self.log_file.read_text().splitlines()
            if line.startswith("ansible-playbook ")
        ]

        self.assertEqual(len(ansible_commands), 2)

        self.assertIn(
            "wireguard_server_key_generation_enabled=true",
            ansible_commands[0],
        )

        self.assertNotIn(
            "wireguard_server_key_generation_enabled=true",
            ansible_commands[1],
        )

    def test_authorization_consume_failure_preserves_marker(self):

        result = self.run_controller(
            auth_fail_action="consume"
        )

        self.assertNotEqual(result.returncode, 0)

        self.assertTrue(self.marker().exists())

        self.assertEqual(
            self.marker().read_text().strip(),
            self.instance_id,
        )

        ansible_commands = [
            line
            for line in self.log_file.read_text().splitlines()
            if line.startswith("ansible-playbook ")
        ]

        self.assertEqual(len(ansible_commands), 1)

        self.assertIn(
            "wireguard_server_key_generation_enabled=true",
            ansible_commands[0],
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)
