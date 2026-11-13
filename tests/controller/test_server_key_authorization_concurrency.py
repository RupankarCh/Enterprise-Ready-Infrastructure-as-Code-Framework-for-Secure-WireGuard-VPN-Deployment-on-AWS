import importlib.util
import multiprocessing
import tempfile
import time
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "server-key-authorization.py"
)

SPEC = importlib.util.spec_from_file_location(
    "server_key_authorization",
    SCRIPT,
)

AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)


def concurrent_bind(marker, instance_id, barrier, results):
    original_read = AUTH.read_marker

    def delayed_read(path):
        result = original_read(path)

        if result == "PENDING":
            time.sleep(0.2)

        return result

    AUTH.read_marker = delayed_read

    barrier.wait()

    try:
        AUTH.bind(marker, instance_id)
        results.put(("success", instance_id))
    except ValueError:
        results.put(("rejected", instance_id))


class TestAuthorizationConcurrency(unittest.TestCase):

    def test_only_one_instance_can_bind_pending_authorization(self):
        context = multiprocessing.get_context("fork")

        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "authorization")

            AUTH.prepare(marker)

            barrier = context.Barrier(2)
            results = context.Queue()

            instances = [
                "i-12345678",
                "i-87654321",
            ]

            processes = [
                context.Process(
                    target=concurrent_bind,
                    args=(marker, instance, barrier, results),
                )
                for instance in instances
            ]

            for process in processes:
                process.start()

            for process in processes:
                process.join(timeout=10)

            for process in processes:
                self.assertFalse(
                    process.is_alive(),
                    "Concurrent authorization process timed out",
                )
                self.assertEqual(process.exitcode, 0)

            outcomes = [
                results.get(timeout=3)
                for _ in processes
            ]

            successes = [
                item for item in outcomes
                if item[0] == "success"
            ]

            rejected = [
                item for item in outcomes
                if item[0] == "rejected"
            ]

            self.assertEqual(len(successes), 1)
            self.assertEqual(len(rejected), 1)

            authorized_instance = Path(marker).read_text().strip()

            self.assertEqual(
                authorized_instance,
                successes[0][1],
            )

            self.assertIn(
                authorized_instance,
                instances,
            )

            print("Concurrent bind outcomes:", outcomes)
            print("Authorized instance:", authorized_instance)


if __name__ == "__main__":
    unittest.main()
