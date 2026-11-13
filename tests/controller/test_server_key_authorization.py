import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/server-key-authorization.py"

spec = importlib.util.spec_from_file_location(
    "server_key_authorization",
    SCRIPT,
)

authorization = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authorization)


INSTANCE_1 = "i-1234567890abcdef0"
INSTANCE_2 = "i-abcdef12345678900"


class TestInstanceValidation(unittest.TestCase):

    def test_valid_instance_id(self):
        self.assertEqual(
            authorization.validate_instance_id(INSTANCE_1),
            INSTANCE_1,
        )

    def test_invalid_instance_id(self):
        invalid_ids = [
            "",
            "invalid",
            "i-123",
            "../i-1234567890abcdef0",
            "i-1234567890abcdef0-extra",
        ]

        for instance_id in invalid_ids:
            with self.subTest(instance_id=instance_id):
                with self.assertRaises(ValueError):
                    authorization.validate_instance_id(instance_id)


class TestAuthorizationLifecycle(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.marker = self.root / "authorization"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_prepare_creates_pending_authorization(self):
        authorization.prepare(self.marker)

        self.assertEqual(
            authorization.read_marker(self.marker),
            "PENDING",
        )

    def test_prepare_sets_restrictive_permissions(self):
        authorization.prepare(self.marker)

        permissions = os.stat(self.marker).st_mode & 0o777

        self.assertEqual(permissions, 0o600)

    def test_prepare_is_idempotent_for_pending_marker(self):
        authorization.prepare(self.marker)
        authorization.prepare(self.marker)

        self.assertEqual(
            authorization.read_marker(self.marker),
            "PENDING",
        )

    def test_bind_authorizes_instance(self):
        authorization.prepare(self.marker)
        authorization.bind(self.marker, INSTANCE_1)

        self.assertTrue(
            authorization.check(self.marker, INSTANCE_1)
        )

    def test_bind_is_idempotent_for_same_instance(self):
        authorization.prepare(self.marker)
        authorization.bind(self.marker, INSTANCE_1)

        authorization.bind(self.marker, INSTANCE_1)

        self.assertTrue(
            authorization.check(self.marker, INSTANCE_1)
        )

    def test_bind_rejects_different_instance(self):
        authorization.prepare(self.marker)
        authorization.bind(self.marker, INSTANCE_1)

        with self.assertRaises(ValueError):
            authorization.bind(self.marker, INSTANCE_2)

    def test_check_rejects_wrong_instance(self):
        authorization.prepare(self.marker)
        authorization.bind(self.marker, INSTANCE_1)

        self.assertFalse(
            authorization.check(self.marker, INSTANCE_2)
        )

    def test_consume_removes_matching_authorization(self):
        authorization.prepare(self.marker)
        authorization.bind(self.marker, INSTANCE_1)

        authorization.consume(self.marker, INSTANCE_1)

        self.assertFalse(self.marker.exists())

    def test_consume_rejects_wrong_instance(self):
        authorization.prepare(self.marker)
        authorization.bind(self.marker, INSTANCE_1)

        with self.assertRaises(ValueError):
            authorization.consume(self.marker, INSTANCE_2)

        self.assertTrue(self.marker.exists())

    def test_consumed_authorization_cannot_be_reused(self):
        authorization.prepare(self.marker)
        authorization.bind(self.marker, INSTANCE_1)
        authorization.consume(self.marker, INSTANCE_1)

        self.assertFalse(
            authorization.check(self.marker, INSTANCE_1)
        )

    def test_prepare_does_not_overwrite_bound_authorization(self):
        authorization.prepare(self.marker)
        authorization.bind(self.marker, INSTANCE_1)

        with self.assertRaises(ValueError):
            authorization.prepare(self.marker)

        self.assertTrue(
            authorization.check(self.marker, INSTANCE_1)
        )


class TestAuthorizationFileSecurity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.marker = self.root / "authorization"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_symlink_marker_rejected(self):
        target = self.root / "target"
        target.write_text("PENDING\n", encoding="utf-8")

        self.marker.symlink_to(target)

        with self.assertRaises(ValueError):
            authorization.read_marker(self.marker)

    def test_insecure_permissions_rejected(self):
        self.marker.write_text("PENDING\n", encoding="utf-8")
        os.chmod(self.marker, 0o644)

        with self.assertRaises(ValueError):
            authorization.read_marker(self.marker)

    def test_invalid_marker_content_rejected(self):
        self.marker.write_text(
            "UNAUTHORIZED\n",
            encoding="utf-8",
        )
        os.chmod(self.marker, 0o600)

        with self.assertRaises(ValueError):
            authorization.read_marker(self.marker)


if __name__ == "__main__":
    unittest.main()
