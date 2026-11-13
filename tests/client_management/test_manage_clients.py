import multiprocessing
import time
import sys
import yaml
import tempfile
import unittest
import base64
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

import importlib.util

SCRIPT_PATH = PROJECT_ROOT / "scripts" / "manage-clients.py"

spec = importlib.util.spec_from_file_location(
    "manage_clients",
    SCRIPT_PATH,
)

manage_clients = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage_clients)

def concurrent_register_worker(
    registry,
    public_key_file,
    name,
    address,
    start_event,
    result_queue,
):
    original_safe_load = manage_clients.yaml.safe_load

    def delayed_safe_load(stream):
        result = original_safe_load(stream)
        time.sleep(0.3)
        return result

    manage_clients.yaml.safe_load = delayed_safe_load

    start_event.wait(5)

    try:
        manage_clients.register_client(
            name=name,
            address=address,
            network="10.8.0.0/24",
            server_address="10.8.0.1/24",
            public_key_file=public_key_file,
            registry_file=registry,
        )
        result_queue.put((name, "success"))
    except Exception as exc:
        result_queue.put((name, str(exc)))
def concurrent_registry_worker(
    action,
    registry,
    public_key_file,
    name,
    address,
    start_event,
    result_queue,
):
    original_safe_load = manage_clients.yaml.safe_load

    def delayed_safe_load(stream):
        result = original_safe_load(stream)
        time.sleep(0.3)
        return result

    manage_clients.yaml.safe_load = delayed_safe_load
    start_event.wait(5)

    try:
        if action == "register":
            manage_clients.register_client(
                name=name,
                address=address,
                network="10.8.0.0/24",
                server_address="10.8.0.1/24",
                public_key_file=public_key_file,
                registry_file=registry,
            )
        elif action == "revoke":
            manage_clients.revoke_client(name, registry)

        result_queue.put((action, "success"))

    except Exception as exc:
        result_queue.put((action, str(exc)))

class TestClientNameValidation(unittest.TestCase):

    def test_valid_client_name(self):
        manage_clients.validate_client_name("client-01")

    def test_reject_empty_name(self):
        with self.assertRaises(ValueError):
            manage_clients.validate_client_name("")

    def test_reject_invalid_characters(self):
        with self.assertRaises(ValueError):
            manage_clients.validate_client_name("../client")

class TestRegistryListing(unittest.TestCase):

    def test_symlink_registry_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            target = temp_path / "real_registry.yml"
            registry = temp_path / "clients.yml"

            target.write_text(
                "wireguard_clients: []\n",
                encoding="utf-8"
            )

            registry.symlink_to(target)

            with self.assertRaises(ValueError):
                manage_clients.list_clients(registry)

    def test_malformed_yaml_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            registry = Path(temp_dir) / "clients.yml"

            registry.write_text(
                "wireguard_clients: [invalid\n",
                encoding="utf-8"
            )

            with self.assertRaises(yaml.YAMLError):
                manage_clients.list_clients(registry)

    def test_invalid_registry_structure_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            registry = Path(temp_dir) / "clients.yml"

            registry.write_text(
                "- client-01\n- client-02\n",
                encoding="utf-8"
            )

            with self.assertRaises(ValueError):
                manage_clients.list_clients(registry)

    def test_missing_registry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            registry = Path(temp_dir) / "missing.yml"
            manage_clients.list_clients(registry)

    def test_empty_registry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            registry = Path(temp_dir) / "clients.yml"
            registry.write_text(
                "wireguard_clients: []\n",
                encoding="utf-8",
            )
            manage_clients.list_clients(registry)


class TestClientRegistrationAndRevocation(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        self.registry = self.root / "clients.yml"
        self.public_key_file = self.root / "client.pub"

        self.public_key = base64.b64encode(
            b"A" * 32
        ).decode("ascii")

        self.public_key_file.write_text(
            self.public_key + "\n",
            encoding="ascii",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def register(self, name, address):
        manage_clients.register_client(
            name=name,
            address=address,
            network="10.8.0.0/24",
            server_address="10.8.0.1/24",
            public_key_file=self.public_key_file,
            registry_file=self.registry,
        )

    def test_concurrent_registration_and_revocation(self):
        self.register("client-01", "10.8.0.2/32")

        second_key = self.root / "client-second.pub"
        second_key.write_text(
            base64.b64encode(b"E" * 32).decode("ascii"),
            encoding="ascii",
        )

        context = multiprocessing.get_context("fork")
        start_event = context.Event()
        result_queue = context.Queue()

        workers = [
            context.Process(
                target=concurrent_registry_worker,
                args=(
                    "revoke",
                    self.registry,
                    self.public_key_file,
                    "client-01",
                    None,
                    start_event,
                    result_queue,
                ),
            ),
            context.Process(
                target=concurrent_registry_worker,
                args=(
                    "register",
                    self.registry,
                    second_key,
                    "client-02",
                    "10.8.0.3/32",
                    start_event,
                    result_queue,
                ),
            ),
        ]

        for worker in workers:
            worker.start()

        start_event.set()

        for worker in workers:
            worker.join(10)

        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join()
                self.fail("Concurrent registry operation timed out.")

            self.assertEqual(worker.exitcode, 0)

        results = [
            result_queue.get(timeout=3)
            for _ in workers
        ]

        self.assertTrue(
            all(status == "success" for _, status in results),
            results,
        )

        data = yaml.safe_load(
            self.registry.read_text(encoding="utf-8")
        )

        registered_names = {
            client["name"]
            for client in data["wireguard_clients"]
        }

        self.assertEqual(registered_names, {"client-02"})

    def test_successful_registration(self):
        self.register("client-01", "10.8.0.2/32")

        data = yaml.safe_load(
            self.registry.read_text(encoding="utf-8")
        )

        self.assertEqual(
            data["wireguard_clients"][0]["name"],
            "client-01",
        )

        self.assertEqual(
            data["wireguard_clients"][0]["address"],
            "10.8.0.2/32",
        )

        self.assertNotIn(
            "private_key",
            data["wireguard_clients"][0],
        )

        self.assertEqual(
            os.stat(self.registry).st_mode & 0o777,
            0o600,
        )

    def test_duplicate_name_rejected(self):
        self.register("client-01", "10.8.0.2/32")

        with self.assertRaisesRegex(ValueError, "already registered"):
            self.register("client-01", "10.8.0.3/32")

    def test_duplicate_address_rejected(self):
        self.register("client-01", "10.8.0.2/32")

        with self.assertRaisesRegex(ValueError, "already registered"):
            self.register("client-02", "10.8.0.2/32")

    def test_invalid_public_key_rejected(self):
        self.public_key_file.write_text(
            "invalid-public-key",
            encoding="ascii",
        )

        with self.assertRaises(ValueError):
            self.register("client-01", "10.8.0.2/32")

    def test_revoke_registered_client(self):
        self.register("client-01", "10.8.0.2/32")

        manage_clients.revoke_client(
            "client-01",
            self.registry,
        )

        data = yaml.safe_load(
            self.registry.read_text(encoding="utf-8")
        )

        self.assertEqual(data["wireguard_clients"], [])

    def test_revoke_preserves_other_clients(self):
        self.register("client-01", "10.8.0.2/32")

        second_public_key = base64.b64encode(
            b"B" * 32
        ).decode("ascii")

        self.public_key_file.write_text(
            second_public_key,
            encoding="ascii",
        )

        self.register("client-02", "10.8.0.3/32")

        manage_clients.revoke_client(
            "client-01",
            self.registry,
        )

        data = yaml.safe_load(
            self.registry.read_text(encoding="utf-8")
        )

        self.assertEqual(len(data["wireguard_clients"]), 1)

        self.assertEqual(
            data["wireguard_clients"][0]["name"],
            "client-02",
        )

    def test_revoke_unknown_client_rejected(self):
        self.registry.write_text(
            "wireguard_clients: []\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "not registered"):
            manage_clients.revoke_client(
                "unknown-client",
                self.registry,
            )

    def test_missing_registry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            registry = Path(temp_dir) / "missing.yml"

            manage_clients.list_clients(registry)

    def test_empty_registry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            registry = Path(temp_dir) / "clients.yml"
            registry.write_text(
                "wireguard_clients: []\n",
                encoding="utf-8",
            )

            manage_clients.list_clients(registry)

    def test_registry_lock_permissions(self):
        self.register("client-01", "10.8.0.2/32")

        lock_file = Path(str(self.registry) + ".lock")

        self.assertTrue(lock_file.is_file())
        self.assertEqual(
            os.stat(lock_file).st_mode & 0o777,
            0o600,
        )

    def test_registry_lock_symlink_rejected(self):
        lock_file = Path(str(self.registry) + ".lock")
        target = self.root / "lock-target"

        target.write_text("test", encoding="utf-8")
        lock_file.symlink_to(target)

        with self.assertRaises(ValueError):
            self.register("client-01", "10.8.0.2/32")

    def test_concurrent_registrations_preserve_both_clients(self):
        self.registry.write_text(
            "wireguard_clients: []\n",
            encoding="utf-8",
        )

        key_files = []

        for index, byte_value in enumerate((b"C", b"D")):
            key_file = self.root / f"client-{index}.pub"
            key_file.write_text(
                base64.b64encode(byte_value * 32).decode("ascii"),
                encoding="ascii",
            )
            key_files.append(key_file)

        context = multiprocessing.get_context("fork")
        start_event = context.Event()
        result_queue = context.Queue()

        workers = [
            context.Process(
                target=concurrent_register_worker,
                args=(
                    self.registry,
                    key_files[0],
                    "client-03",
                    "10.8.0.3/32",
                    start_event,
                    result_queue,
                ),
            ),
            context.Process(
                target=concurrent_register_worker,
                args=(
                    self.registry,
                    key_files[1],
                    "client-04",
                    "10.8.0.4/32",
                    start_event,
                    result_queue,
                ),
            ),
        ]

        for worker in workers:
            worker.start()

        start_event.set()

        for worker in workers:
            worker.join(10)

        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join()
                self.fail("Concurrent registration process timed out.")

            self.assertEqual(worker.exitcode, 0)

        results = [
            result_queue.get(timeout=3)
            for _ in workers
        ]

        self.assertTrue(
            all(status == "success" for _, status in results),
            results,
        )

        data = yaml.safe_load(
            self.registry.read_text(encoding="utf-8")
        )

        registered_names = {
            client["name"]
            for client in data["wireguard_clients"]
        }

        self.assertEqual(
            registered_names,
            {"client-03", "client-04"},
        )

if __name__ == "__main__":
    unittest.main()
