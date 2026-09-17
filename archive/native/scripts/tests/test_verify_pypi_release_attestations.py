from __future__ import annotations

import importlib.util
import io
import subprocess
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_pypi_release_attestations.py"


def load_module():
    spec = importlib.util.spec_from_file_location("verify_pypi_release_attestations", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PyPIReleaseAttestationVerifierTests(unittest.TestCase):
    class Response:
        def __init__(self, body: bytes):
            self.body = body
            self.headers = {"Content-Length": str(len(body))}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self, limit: int) -> bytes:
            return self.body[:limit]

    def test_metadata_fetch_retries_transport_failure_with_bounded_timeout(self) -> None:
        module = load_module()
        responses = iter(
            (
                urllib.error.URLError("temporary"),
                self.Response(b'{"urls": []}'),
            )
        )
        timeouts: list[int] = []

        def open_url(request, timeout: int):
            del request
            timeouts.append(timeout)
            result = next(responses)
            if isinstance(result, BaseException):
                raise result
            return result

        metadata = module.fetch_metadata(
            "0.11.4",
            open_url=open_url,
            attempts=2,
            delay_seconds=0,
            timeout_seconds=7,
        )
        self.assertEqual(metadata, {"urls": []})
        self.assertEqual(timeouts, [7, 7])

    def test_verifies_every_distribution_against_the_expected_repository(self) -> None:
        module = load_module()
        calls: list[list[str]] = []

        timeouts: list[int] = []

        def run(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            timeouts.append(timeout_seconds)
            return subprocess.CompletedProcess(command, 0)

        metadata = {
            "urls": [
                {
                    "filename": "jacs-0.11.4.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/a/jacs-0.11.4.tar.gz",
                },
                {
                    "filename": "jacs-0.11.4-cp311-abi3-manylinux.whl",
                    "url": "https://files.pythonhosted.org/packages/b/jacs-0.11.4-cp311-abi3-manylinux.whl",
                },
            ]
        }

        with redirect_stdout(io.StringIO()):
            module.verify_release(
                "0.11.4",
                metadata,
                run=run,
                attempts=1,
                delay_seconds=0,
                timeout_seconds=17,
            )

        self.assertEqual(len(calls), 2)
        self.assertEqual(timeouts, [17, 17])
        for command in calls:
            self.assertEqual(command[:3], ["pypi-attestations", "verify", "pypi"])
            self.assertIn("--repository", command)
            self.assertIn("https://github.com/HumanAssisted/JACS", command)

    def test_rejects_distribution_urls_outside_pypi_file_host(self) -> None:
        module = load_module()
        metadata = {
            "urls": [
                {
                    "filename": "jacs-0.11.4.tar.gz",
                    "url": "https://attacker.example/jacs-0.11.4.tar.gz",
                }
            ]
        }

        with self.assertRaisesRegex(ValueError, "files.pythonhosted.org"):
            module.verify_release(
                "0.11.4",
                metadata,
                attempts=1,
                delay_seconds=0,
            )

    def test_fails_when_any_distribution_cannot_be_verified(self) -> None:
        module = load_module()

        def fail(
            command: list[str], timeout_seconds: int
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1)

        metadata = {
            "urls": [
                {
                    "filename": "jacs-0.11.4.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/a/jacs-0.11.4.tar.gz",
                }
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "jacs-0.11.4.tar.gz"):
            module.verify_release(
                "0.11.4",
                metadata,
                run=fail,
                attempts=1,
                delay_seconds=0,
            )

    def test_timeout_is_retried_but_each_attempt_remains_bounded(self) -> None:
        module = load_module()
        observed_timeouts: list[int] = []

        def timeout(command: list[str], timeout_seconds: int):
            observed_timeouts.append(timeout_seconds)
            raise subprocess.TimeoutExpired(command, timeout_seconds)

        metadata = {
            "urls": [
                {
                    "filename": "jacs-0.11.4.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/a/jacs-0.11.4.tar.gz",
                }
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "timed out"):
            module.verify_release(
                "0.11.4",
                metadata,
                run=timeout,
                attempts=2,
                delay_seconds=0,
                timeout_seconds=9,
            )
        self.assertEqual(observed_timeouts, [9, 9])

    def test_final_non_timeout_failure_is_not_mislabeled(self) -> None:
        module = load_module()
        calls = 0

        def timeout_then_fail(command: list[str], timeout_seconds: int):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            return subprocess.CompletedProcess(command, 1)

        metadata = {
            "urls": [
                {
                    "filename": "jacs-0.11.4.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/a/jacs-0.11.4.tar.gz",
                }
            ]
        }
        with self.assertRaisesRegex(RuntimeError, "verification failed"):
            module.verify_release(
                "0.11.4",
                metadata,
                run=timeout_then_fail,
                attempts=2,
                delay_seconds=0,
            )


if __name__ == "__main__":
    unittest.main()
