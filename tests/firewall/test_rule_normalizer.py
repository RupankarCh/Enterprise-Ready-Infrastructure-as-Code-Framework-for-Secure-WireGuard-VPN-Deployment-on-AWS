import subprocess
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

NORMALIZER = (
    PROJECT_ROOT
    / "ansible/roles/wireguard/files/"
    / "cloudvpn-firewall-rule-normalize.py"
)

CHAIN = "CLOUDVPN_TEST"

RULE_1 = "-i wg0 -o ens5 -j ACCEPT"
RULE_2 = "-i ens5 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"


def run_normalizer(mode, rules, expected_rules):
    process = subprocess.run(
        [
            sys.executable,
            str(NORMALIZER),
            mode,
            CHAIN,
            *expected_rules,
        ],
        input=rules,
        text=True,
        capture_output=True,
        check=False,
    )

    return process


class TestFirewallRuleNormalizer(unittest.TestCase):

    def test_exact_matching_rules_pass(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} {RULE_1}\n"
            f"-A {CHAIN} {RULE_2}\n"
        )

        result = run_normalizer(
            "exact",
            rules,
            [RULE_1, RULE_2],
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_option_order_is_normalized(self):
        actual = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} -o ens5 -i wg0 -j ACCEPT\n"
        )

        result = run_normalizer(
            "exact",
            actual,
            [RULE_1],
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_rule_fails_exact_mode(self):
        rules = f"-N {CHAIN}\n-A {CHAIN} {RULE_1}\n"

        result = run_normalizer(
            "exact",
            rules,
            [RULE_1, RULE_2],
        )

        self.assertNotEqual(result.returncode, 0)

    def test_unexpected_extra_rule_fails_exact_mode(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} {RULE_1}\n"
            f"-A {CHAIN} {RULE_2}\n"
            f"-A {CHAIN} -i wg0 -j DROP\n"
        )

        result = run_normalizer(
            "exact",
            rules,
            [RULE_1, RULE_2],
        )

        self.assertNotEqual(result.returncode, 0)

    def test_incomplete_staging_chain_passes_prefix_mode(self):
        rules = f"-N {CHAIN}\n-A {CHAIN} {RULE_1}\n"

        result = run_normalizer(
            "prefix",
            rules,
            [RULE_1, RULE_2],
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_staging_chain_passes_prefix_mode(self):
        rules = f"-N {CHAIN}\n"

        result = run_normalizer(
            "prefix",
            rules,
            [RULE_1, RULE_2],
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unexpected_staging_rule_fails_prefix_mode(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} -i wg0 -j DROP\n"
        )

        result = run_normalizer(
            "prefix",
            rules,
            [RULE_1, RULE_2],
        )

        self.assertNotEqual(result.returncode, 0)

    def test_duplicate_option_fails(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} -i wg0 -i ens5 -j ACCEPT\n"
        )

        result = run_normalizer(
            "exact",
            rules,
            [RULE_1],
        )

        self.assertNotEqual(result.returncode, 0)

    def test_unsupported_option_fails(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} --goto OTHER_CHAIN\n"
        )

        result = run_normalizer(
            "exact",
            rules,
            ["-j ACCEPT"],
        )

        self.assertNotEqual(result.returncode, 0)

    def test_missing_chain_declaration_fails(self):
        rules = f"-A {CHAIN} {RULE_1}\n"

        result = run_normalizer(
            "exact",
            rules,
            [RULE_1],
        )

        self.assertNotEqual(result.returncode, 0)

    def test_duplicate_chain_declaration_fails(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-N {CHAIN}\n"
            f"-A {CHAIN} {RULE_1}\n"
        )

        result = run_normalizer(
            "exact",
            rules,
            [RULE_1],
        )

        self.assertNotEqual(result.returncode, 0)

    def test_invalid_ipv4_source_fails(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} -s 999.999.999.999 -j ACCEPT\n"
        )

        result = run_normalizer(
            "exact", rules, ["-s 999.999.999.999 -j ACCEPT"]
        )

        self.assertNotEqual(result.returncode, 0)

    def test_invalid_ipv4_destination_fails(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} -d 10.0.0.1/99 -j ACCEPT\n"
        )

        result = run_normalizer(
            "exact", rules, ["-d 10.0.0.1/99 -j ACCEPT"]
        )

        self.assertNotEqual(result.returncode, 0)

    def test_ipv6_source_is_rejected(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} -s 2001:db8::1 -j ACCEPT\n"
        )

        result = run_normalizer(
            "exact", rules, ["-s 2001:db8::1 -j ACCEPT"]
        )

        self.assertNotEqual(result.returncode, 0)

    def test_valid_ipv4_host_is_accepted(self):
        rule = "-s 10.8.0.1/32 -j ACCEPT"
        rules = f"-N {CHAIN}\n-A {CHAIN} {rule}\n"

        result = run_normalizer("exact", rules, [rule])

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_valid_ipv4_network_is_accepted(self):
        rule = "-s 10.8.0.0/24 -j ACCEPT"
        rules = f"-N {CHAIN}\n-A {CHAIN} {rule}\n"

        result = run_normalizer("exact", rules, [rule])

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_valid_destination_network_is_accepted(self):
        rule = "-d 169.254.0.0/16 -j DROP"
        rules = f"-N {CHAIN}\n-A {CHAIN} {rule}\n"

        result = run_normalizer("exact", rules, [rule])

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_duplicate_actual_rules_fail(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} {RULE_1}\n"
            f"-A {CHAIN} {RULE_1}\n"
        )

        result = run_normalizer(
            "exact", rules, [RULE_1, RULE_1]
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stderr.lower())

    def test_duplicate_expected_rules_fail(self):
        rules = f"-N {CHAIN}\n-A {CHAIN} {RULE_1}\n"

        result = run_normalizer(
            "exact", rules, [RULE_1, RULE_1]
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stderr.lower())

    def test_duplicate_rules_detected_after_option_normalization(self):
        rules = (
            f"-N {CHAIN}\n"
            f"-A {CHAIN} -i wg0 -o ens5 -j ACCEPT\n"
            f"-A {CHAIN} -o ens5 -i wg0 -j ACCEPT\n"
        )

        result = run_normalizer(
            "exact", rules, [RULE_1, RULE_1]
        )

        self.assertNotEqual(result.returncode, 0)

    def test_invalid_verification_mode_fails(self):
        rules = f"-N {CHAIN}\n"

        result = run_normalizer(
            "invalid",
            rules,
            [RULE_1],
        )

        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
