import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/terraform-plan-needs-server-key.py"

spec = importlib.util.spec_from_file_location("plan_analyser", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestTerraformPlanAnalysis(unittest.TestCase):

    def make_plan(self, resource_changes):
        return {"resource_changes": resource_changes}

    def resource(self, address, actions, resource_type="aws_instance"):
        return {
            "address": address,
            "type": resource_type,
            "change": {"actions": actions},
        }

    def test_new_instance_requires_key_generation(self):
        plan = self.make_plan([
            self.resource("module.ec2.aws_instance.vpn", ["create"])
        ])
        self.assertTrue(module.needs_server_key_generation(plan))

    def test_replacement_requires_key_generation(self):
        plan = self.make_plan([
            self.resource(
                "module.ec2.aws_instance.vpn",
                ["delete", "create"]
            )
        ])
        self.assertTrue(module.needs_server_key_generation(plan))

    def test_existing_instance_update_does_not_require_generation(self):
        plan = self.make_plan([
            self.resource("module.ec2.aws_instance.vpn", ["update"])
        ])
        self.assertFalse(module.needs_server_key_generation(plan))

    def test_no_changes_does_not_require_generation(self):
        plan = self.make_plan([
            self.resource("module.ec2.aws_instance.vpn", ["no-op"])
        ])
        self.assertFalse(module.needs_server_key_generation(plan))

    def test_unrelated_instance_does_not_trigger_generation(self):
        plan = self.make_plan([
            self.resource("aws_instance.other", ["create"])
        ])
        self.assertFalse(module.needs_server_key_generation(plan))

    def test_unrelated_resource_does_not_trigger_generation(self):
        plan = self.make_plan([
            self.resource(
                "module.network.aws_vpc.main",
                ["create"],
                "aws_vpc"
            )
        ])
        self.assertFalse(module.needs_server_key_generation(plan))

    def test_missing_resource_changes_does_not_trigger_generation(self):
        self.assertFalse(module.needs_server_key_generation({}))


if __name__ == "__main__":
    unittest.main()
