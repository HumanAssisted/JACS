"""Candidate execution must fail closed before a package manager is invoked."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest import mock

from scripts.native_bindings_sdist import trim_workspace
from scripts.native_bindings_notices import sync_copies

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_bindings", ROOT / "scripts/native_bindings.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class CandidateTests(unittest.TestCase):
    def test_changed_candidate_cannot_be_installed(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            artifact = output / "candidate.tgz"
            artifact.write_bytes(b"reviewed candidate")
            native.record(output, artifact, "0.15.0")
            artifact.write_bytes(b"different candidate")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                native.candidate(output)

    def test_candidate_manifest_cannot_select_external_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            (root / "outside.tgz").write_bytes(b"external candidate")
            (output / "candidate.json").write_text(json.dumps({
                "artifact": "../outside.tgz", "version": "0.15.0",
                "sha256": hashlib.sha256(b"external candidate").hexdigest(),
            }))
            with self.assertRaisesRegex(ValueError, "inside its output directory"):
                native.candidate(output)

    def test_recorded_candidate_is_the_one_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            artifact = output / "current.tgz"
            artifact.write_bytes(b"reviewed candidate")
            (output / "stale.tgz").write_bytes(b"older candidate")
            native.record(output, artifact, "0.15.0")
            self.assertEqual(native.candidate(output), (artifact.resolve(), "0.15.0"))

    def test_pinned_compiler_wins_over_homebrew_without_disabling_shared_cache(self):
        version = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]

        def run(command, **_options):
            if command[0] == "rustup":
                return f"/toolchain/bin/{command[-1]}\n"
            return f"{Path(command[0]).name} {version} (test build)\n"

        with mock.patch.object(native, "run", side_effect=run):
            selected = native.pinned_rust_environment({
                "PATH": "/opt/homebrew/bin:/usr/bin", "RUSTC_WRAPPER": "kache",
                "CARGO_TARGET_DIR": "/isolated/native-target",
            })
        self.assertEqual(selected["RUSTC"], "/toolchain/bin/rustc")
        self.assertEqual(selected["RUSTDOC"], "/toolchain/bin/rustdoc")
        self.assertEqual(selected["CARGO"], "/toolchain/bin/cargo")
        self.assertEqual(selected["PATH"].split(":"), ["/toolchain/bin", "/opt/homebrew/bin", "/usr/bin"])
        self.assertEqual(selected["RUSTC_WRAPPER"], "kache")
        self.assertEqual(selected["CARGO_TARGET_DIR"], "/isolated/native-target")


class SourceDistributionTests(unittest.TestCase):
    def test_workspace_contains_only_packaged_members_without_dependency_changes(self):
        original = '''[workspace]
members = ["jacs-core", "jacs-wasm", "jacs-cli"]
default-members = ["jacs-core", "jacs-wasm", "jacs-cli"]
exclude = ["archive/native"]
resolver = "3"

[workspace.package]
license = "Apache-2.0"

[workspace.dependencies]
external = "1.2.3"
'''
        result = tomllib.loads(trim_workspace(original, {"jacs-core"}))
        self.assertEqual(result["workspace"]["members"], ["jacs-core"])
        self.assertEqual(result["workspace"]["default-members"], ["jacs-core"])
        self.assertEqual(result["workspace"]["exclude"], ["archive/native"])
        self.assertEqual(result["workspace"]["package"], {"license": "Apache-2.0"})
        self.assertEqual(result["workspace"]["dependencies"], {"external": "1.2.3"})

    def test_missing_entire_workspace_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "empty members"):
            trim_workspace('[workspace]\nmembers = ["jacs-core"]\n', set())


class NativeNoticeCopiesTests(unittest.TestCase):
    def test_check_never_rewrites_stale_notices_and_write_copies_exact_legal_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "canonical"
            canonical.write_bytes(b"copyright retained\n\nlicense appendix\n")
            copy = root / "copy"
            copy.write_bytes(b"stale notices\n")
            self.assertFalse(sync_copies(canonical, (copy,), write=False))
            self.assertEqual(copy.read_bytes(), b"stale notices\n")
            self.assertTrue(sync_copies(canonical, (copy,), write=True))
            self.assertEqual(copy.read_bytes(), canonical.read_bytes())
            self.assertTrue(sync_copies(canonical, (copy,), write=False))


if __name__ == "__main__":
    unittest.main()
