from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "check_npm_publish_metadata.py"
SPEC = importlib.util.spec_from_file_location("check_npm_publish_metadata", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metadata)


class NpmPublishMetadataTests(unittest.TestCase):
    def test_release_manifests_match_trusted_publisher_repository(self) -> None:
        for relative in (
            "archive/native/jacsnpm/package.json",
            "jacs-wasm/package.template.json",
        ):
            with self.subTest(package=relative):
                self.assertEqual(metadata.package_errors(ROOT / relative), [])

    def test_git_transport_alias_is_rejected_with_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package.json"
            package.write_text(
                json.dumps(
                    {
                        "name": "@hai.ai/jacs",
                        "version": "0.11.4",
                        "license": "Apache-2.0",
                        "publishConfig": {"access": "public"},
                        "repository": {
                            "type": "git",
                            "url": "git+https://github.com/HumanAssisted/JACS.git",
                        },
                    }
                )
            )
            self.assertIn(
                "repository.url must exactly match the npm trusted publisher",
                metadata.package_errors(package)[0],
            )

    def test_wasm_release_uses_the_shared_validator(self) -> None:
        cases = {
            "release-npm.yml": "archive/native/jacsnpm/package.json",
            "release-wasm.yml": "jacs-wasm/package.template.json",
        }
        for workflow, package in cases.items():
            text = (ROOT / ".github" / "workflows" / workflow).read_text()
            with self.subTest(workflow=workflow):
                self.assertIn(
                    f"python3 scripts/check_npm_publish_metadata.py {package}",
                    text,
                )

    def test_native_npm_release_keeps_the_full_package_surface(self) -> None:
        package = json.loads((ROOT / "archive/native/jacsnpm/package.json").read_text())
        self.assertIsNot(package.get("private"), True)
        self.assertTrue((ROOT / ".github/workflows/release-npm.yml").exists())
        for entry in (".", "./client", "./simple", "./mcp", "./a2a", "./signing-input"):
            self.assertIn(entry, package["exports"])

    def test_private_release_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package.json"
            package.write_text(json.dumps({"private": True, "repository": metadata.EXPECTED_REPOSITORY_URL}))
            self.assertIn("release package must not be private", metadata.package_errors(package))


if __name__ == "__main__":
    unittest.main()
