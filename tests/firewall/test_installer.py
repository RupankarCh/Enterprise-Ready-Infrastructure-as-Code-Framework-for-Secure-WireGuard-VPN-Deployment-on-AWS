import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

INSTALLER = ROOT / "ansible/roles/wireguard/files/cloudvpn-firewall.sh"
NORMALIZER = ROOT / "ansible/roles/wireguard/files/cloudvpn-firewall-rule-normalize.py"

MOCK_DIR = ROOT / "tests/firewall/mock"
IPTABLES = MOCK_DIR / "mock_iptables.py"


class TestFirewallInstaller(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work = Path(self.temp_dir.name)

        self.state_file = self.work / "firewall-state.json"
        self.log_file = self.work / "firewall-operations.log"
        self.lock_file = self.work / "firewall.lock"

        self.env = os.environ.copy()

        self.env.update({
            "PATH": (
                f"{MOCK_DIR}:/usr/local/sbin:/usr/local/bin:"
                "/usr/sbin:/usr/bin:/sbin:/bin"
            ),
            "IPTABLES": str(IPTABLES),
            "RULE_NORMALIZER": str(NORMALIZER),
            "LOCK_FILE": str(self.lock_file),
            "MOCK_IPTABLES_STATE": str(self.state_file),
            "MOCK_IPTABLES_LOG": str(self.log_file),
        })

        for key in (
            "MOCK_IPTABLES_FAIL_ON",
            "MOCK_IPTABLES_FAIL_STAGE",
            "MOCK_IPTABLES_FAILURES",
            "MOCK_IPTABLES_FAIL_INSPECT_AFTER",
        ):
            self.env.pop(key, None)

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_installer(self, extra_env=None):
        env = self.env.copy()

        if extra_env:
            env.update(extra_env)

        return subprocess.run(
            ["bash", str(INSTALLER)],
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def read_state(self):
        return json.loads(self.state_file.read_text())

    def read_log(self):
        if not self.log_file.exists():
            return []

        return self.log_file.read_text().splitlines()

    def test_successful_installation(self):
        result = self.run_installer()

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stdout + result.stderr,
        )

        state = self.read_state()
        chains = state["chains"]

        self.assertIn("CLOUDVPN_FORWARD", chains)
        self.assertIn("CLOUDVPN_INPUT", chains)

        self.assertEqual(
            chains["FORWARD"][0],
            "-j CLOUDVPN_FORWARD",
        )

        self.assertEqual(
            chains["INPUT"][0],
            "-j CLOUDVPN_INPUT",
        )

        self.assertIn(
            "CloudVPN firewall successfully activated.",
            result.stdout,
        )

        self.assertNotIn("CLOUDVPN_FORWARD_STAGE", chains)
        self.assertNotIn("CLOUDVPN_INPUT_STAGE", chains)

    def test_repeated_installation_is_idempotent(self):
        first = self.run_installer()

        self.assertEqual(
            first.returncode,
            0,
            msg=first.stdout + first.stderr,
        )

        first_state = self.read_state()
        first_log_length = len(self.read_log())

        second = self.run_installer()

        self.assertEqual(
            second.returncode,
            0,
            msg=second.stdout + second.stderr,
        )

        second_state = self.read_state()

        self.assertEqual(first_state, second_state)

        self.assertEqual(
            second_state["chains"]["FORWARD"].count(
                "-j CLOUDVPN_FORWARD"
            ),
            1,
        )

        self.assertEqual(
            second_state["chains"]["INPUT"].count(
                "-j CLOUDVPN_INPUT"
            ),
            1,
        )

        second_run_log = self.read_log()[first_log_length:]

        self.assertNotIn(
            "-N CLOUDVPN_FORWARD_STAGE",
            second_run_log,
        )

        self.assertNotIn(
            "-N CLOUDVPN_INPUT_STAGE",
            second_run_log,
        )

    def test_input_firewall_disabled(self):
        result = self.run_installer({
            "INPUT_FIREWALL_ENABLED": "false",
        })

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stdout + result.stderr,
        )

        chains = self.read_state()["chains"]

        self.assertIn("CLOUDVPN_FORWARD", chains)
        self.assertNotIn("CLOUDVPN_INPUT", chains)
        self.assertNotIn("CLOUDVPN_INPUT_STAGE", chains)

        self.assertEqual(chains["INPUT"], [])

    def test_installation_succeeds_before_vpn_interface_exists(self):
        result = self.run_installer({
            "MOCK_IP_MISSING_WG0": "true",
        })

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stdout + result.stderr,
        )

        chains = self.read_state()["chains"]
        self.assertIn("CLOUDVPN_FORWARD", chains)
        self.assertIn("CLOUDVPN_INPUT", chains)

    def test_forward_hook_failure_rolls_back_resources(self):
        result = self.run_installer({
            "MOCK_IPTABLES_FAILURES": (
                "after|-I FORWARD 1 -j CLOUDVPN_FORWARD"
            ),
        })

        self.assertNotEqual(result.returncode, 0)

        chains = self.read_state()["chains"]

        self.assertEqual(
            set(chains),
            {"INPUT", "FORWARD", "OUTPUT"},
        )

        self.assertEqual(chains["INPUT"], [])
        self.assertEqual(chains["FORWARD"], [])
        self.assertEqual(chains["OUTPUT"], [])

        self.assertIn(
            "Activation compensation completed successfully.",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
