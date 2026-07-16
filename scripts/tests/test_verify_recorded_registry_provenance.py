from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_recorded_registry_provenance.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "verify_recorded_registry_provenance", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecordedRegistryProvenanceTests(unittest.TestCase):
    def test_selects_only_published_python_and_npm_releases(self) -> None:
        module = load_module()
        matrix = {
            "artifacts": {
                "python": {"version": "0.11.4", "status": "published"},
                "node": {"version": "0.11.4", "status": "published-current"},
                "wasm": {"version": None, "status": "unpublished"},
            }
        }
        self.assertEqual(
            module.recorded_registry_releases(matrix),
            [
                ("python", "jacs", "0.11.4"),
                ("node", "@hai.ai/jacs", "0.11.4"),
            ],
        )

    def test_verifies_each_recorded_release_with_exact_verifier(self) -> None:
        module = load_module()
        calls: list[tuple[str, str]] = []
        matrix = {
            "artifacts": {
                "python": {"version": "0.11.4", "status": "published"},
                "node": {"version": "0.11.4", "status": "published"},
                "wasm": {"version": "0.11.4", "status": "published"},
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "matrix.json"
            path.write_text(json.dumps(matrix), encoding="utf-8")
            module.verify_recorded_releases(
                path,
                verify_pypi=lambda version: calls.append(("pypi", version)),
                verify_npm=lambda package, version: calls.append((package, version)),
            )
        self.assertEqual(
            calls,
            [
                ("pypi", "0.11.4"),
                ("@hai.ai/jacs", "0.11.4"),
                ("@jacs/wasm", "0.11.4"),
            ],
        )

    def test_npm_verifier_installs_without_scripts_then_audits_signatures(self) -> None:
        module = load_module()
        calls: list[list[str]] = []

        def run(command: list[str], cwd: Path, timeout_seconds: int):
            calls.append(command)
            if command[1] == "install":
                package_root = cwd / "node_modules" / "@hai.ai" / "jacs"
                package_root.mkdir(parents=True)
                (package_root / "package.json").write_text(
                    '{"name":"@hai.ai/jacs","version":"0.11.4"}',
                    encoding="utf-8",
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        module.verify_npm_release(
            "@hai.ai/jacs",
            "0.11.4",
            run=run,
            timeout_seconds=17,
        )
        self.assertEqual(calls[0][0:2], ["npm", "install"])
        self.assertIn("--ignore-scripts", calls[0])
        self.assertIn("@hai.ai/jacs@0.11.4", calls[0])
        self.assertEqual(calls[1], ["npm", "audit", "signatures"])


if __name__ == "__main__":
    unittest.main()
