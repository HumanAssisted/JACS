"""Mutation checks for the public portable graph and archived build boundary."""

import copy
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("workspace_boundary", ROOT / "scripts/check_workspace_boundary.py")
assert SPEC is not None and SPEC.loader is not None
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)


class WorkspaceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        archive = self.root / "archive/native"
        (archive / "jacs").mkdir(parents=True)
        (archive / "Cargo.toml").write_text('[workspace]\nmembers = ["jacs"]\n')
        (archive / "jacs/Cargo.toml").write_text('[package]\nname = "jacs"\npublish = true\n')
        self.metadata = {
            "packages": [
                {"id": name, "name": name, "manifest_path": str(self.root / name / "Cargo.toml")}
                for name in sorted(boundary.ACTIVE)
            ],
            "workspace_members": sorted(boundary.ACTIVE),
            "resolve": {"nodes": [{"id": name, "dependencies": []} for name in sorted(boundary.ACTIVE)]},
        }

    def validate(self, metadata=None):
        with patch.object(boundary, "ROOT", self.root):
            return boundary.validate(self.metadata if metadata is None else metadata)

    def add_dependency(self, name, parent="jacs-core", path=None):
        self.metadata["packages"].append({"id": name, "name": name, "manifest_path": path or f"/registry/{name}/Cargo.toml"})
        self.metadata["resolve"]["nodes"].append({"id": name, "dependencies": []})
        next(node for node in self.metadata["resolve"]["nodes"] if node["id"] == parent)["dependencies"].append(name)

    def test_exact_portable_graph_passes(self):
        self.assertEqual(self.validate(), 5)
        self.add_dependency("serde")
        self.assertEqual(self.validate(), 6)

    def test_member_set_cannot_grow_or_shrink(self):
        for members in (sorted(boundary.ACTIVE - {"jacs-mobile"}), sorted(boundary.ACTIVE) + ["serde"]):
            metadata = copy.deepcopy(self.metadata)
            metadata["packages"].append({"id": "serde", "name": "serde", "manifest_path": "/registry/serde/Cargo.toml"})
            metadata["workspace_members"] = members
            with self.subTest(members=members), self.assertRaisesRegex(ValueError, "active workspace"):
                self.validate(metadata)

    def test_transitive_native_dependency_is_rejected(self):
        self.add_dependency("intermediate")
        self.add_dependency("reqwest", parent="intermediate")
        with self.assertRaisesRegex(ValueError, "archived integration.*reqwest"):
            self.validate()

    def test_renamed_archive_package_is_rejected_by_path(self):
        self.add_dependency("renamed-native", path=str(self.root / "archive/native/renamed/Cargo.toml"))
        with self.assertRaisesRegex(ValueError, "archived integration"):
            self.validate()

    def test_catalogued_native_package_must_allow_publication(self):
        manifest = self.root / "archive/native/jacs/Cargo.toml"
        for declaration in ("", "publish = true\n"):
            manifest.write_text('[package]\nname = "jacs"\n' + declaration)
            self.assertEqual(self.validate(), 5)
        manifest.write_text('[package]\nname = "jacs"\npublish = false\n')
        with self.assertRaisesRegex(ValueError, "publishing disabled"):
            self.validate()

    def test_standalone_archived_package_cannot_publish(self):
        archive = self.root / "archive/native"
        (archive / "Cargo.toml").write_text('[workspace]\nmembers = ["jacs"]\nexclude = ["standalone"]\n')
        (archive / "standalone").mkdir()
        standalone = archive / "standalone/Cargo.toml"
        standalone.write_text('[package]\nname = "standalone"\npublish = true\n[workspace]\n')
        with self.assertRaisesRegex(ValueError, "uncatalogued"):
            self.validate()
        standalone.write_text('[package]\nname = "standalone"\npublish = false\n[workspace]\n')
        self.assertEqual(self.validate(), 5)

    def test_active_workflow_source_references_exist(self):
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            text = workflow.read_text()
            paths = re.findall(r"uses:\s+\./([^\s]+)", text)
            # Windows source archives add a checkout prefix to these same paths.
            source_text = text.replace("$prefix/", "").replace("$GITHUB_WORKSPACE/", "").replace("${GITHUB_WORKSPACE}/", "")
            paths += re.findall(r"(?<![\w/.-])((?:[\w-]+/)*scripts/[\w/.-]+\.(?:py|sh|mjs))\b", source_text)
            for relative in paths:
                with self.subTest(workflow=workflow.name, source=relative):
                    self.assertTrue((ROOT / relative).is_file(), f"missing workflow source: {relative}")

    def test_compatibility_vectors_exclude_raw_private_keys(self):
        vectors = ROOT / "tests/fixtures/native_compat/wasm_compat"
        self.assertEqual({path.name for path in vectors.iterdir()}, {
            "agreement.json", "agreement.signers.json",
            "canonical_inputs.json", "canonical_outputs.json",
            "ed25519.public.bin", "ed25519.signed.json",
            "pq2025.public.bin", "pq2025.signed.json",
            "argon2id.encrypted.json", "pbkdf2.encrypted.bin",
        })


if __name__ == "__main__":
    unittest.main()
