"""Rust publication gates fail before upload when candidate evidence changes."""

from __future__ import annotations

import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock

try:
    import rust_release as release
except ModuleNotFoundError:
    from scripts import rust_release as release


class RustReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def candidate(self, *, publishable=True):
        lock = self.write("source/Cargo.lock", "version = 4\n")
        self.write("candidate.json", json.dumps({
            "version": "0.15.0", "publishable": publishable,
            "crates": list(release.CRATES), "candidate_lock_sha256": release.sha256(lock),
        }))
        archive = self.write("archives/jacs-core-0.15.0.crate", "reviewed candidate")
        self.write("checksums.json", json.dumps({archive.name: release.sha256(archive)}))
        repacked = self.write("cargo/package/jacs-core-0.15.0.crate", "reviewed candidate")
        return archive, repacked

    def archive(self, *, missing=(), unexpected=None, overrides=None):
        archive = self.root / "candidate.crate"
        contents = {
            "Cargo.toml": '[package]\nname="jacs-core"\nversion="0.15.0"\n',
            "Cargo.lock": "version = 4\n", "LICENSE-APACHE": "Apache license",
            "THIRD-PARTY-NOTICES": "dependency notices",
        }
        contents.update(overrides or {})
        with tarfile.open(archive, "w:gz") as bundle:
            for name, value in contents.items():
                if name in missing:
                    continue
                raw = value.encode()
                entry = tarfile.TarInfo("jacs-core-0.15.0/" + name)
                entry.size = len(raw)
                bundle.addfile(entry, io.BytesIO(raw))
            if unexpected:
                entry = tarfile.TarInfo(unexpected)
                bundle.addfile(entry, io.BytesIO())
        return archive

    def test_real_catalog_has_valid_publish_order_and_registry_dependency_versions(self):
        version = tomllib.loads((release.ROOT / "jacs-core/Cargo.toml").read_text())["package"]["version"]
        release.validate_sources(release.ROOT, version)

    def test_dependency_alias_preserves_package_identity_and_path(self):
        catalog = {"core": "core/Cargo.toml", "compat": "native/compat/Cargo.toml"}
        self.write(catalog["core"], '[package]\nname="core"\nversion="0.15.0"\n')
        manifest = self.write(catalog["compat"], '[package]\nname="compat"\nversion="0.15.0"\n'
                              '[dependencies]\nold_name={package="core",version="0.15.0",path="../../core"}\n')
        with mock.patch.object(release, "CRATE_MANIFESTS", catalog):
            release.validate_sources(self.root, "0.15.0")
            original = manifest.read_text()
            for old, new, reason in (("../../core", "../../wrong", "path mismatch"),
                                     ('version="0.15.0",', '', "registry version")):
                with self.subTest(reason=reason):
                    manifest.write_text(original.replace(old, new))
                    with self.assertRaisesRegex(ValueError, reason):
                        release.validate_sources(self.root, "0.15.0")

    def test_conflicting_reviewed_registry_checksums_fail_before_fetch(self):
        for index, relative in enumerate(release.SOURCE_LOCKS):
            self.write(relative, 'version=4\n[[package]]\nname="external"\nversion="1.0.0"\n'
                       'source="registry+https://example.invalid"\n' + f'checksum="{index}"\n')
        with mock.patch.object(release, "run") as runner:
            with self.assertRaisesRegex(ValueError, "inconsistent source checksums"):
                release.vendor_reviewed_dependencies(self.root, self.root)
            runner.assert_not_called()

    def test_vendor_fetch_is_locked_but_can_populate_a_fresh_ci_cache(self):
        for relative in release.SOURCE_LOCKS:
            self.write(relative, "version=4\n")
        with mock.patch.object(release, "run", return_value="[source]\n") as runner:
            allowed, config = release.vendor_reviewed_dependencies(self.root, self.root)
        command = runner.call_args.args[0]
        self.assertIn("--locked", command)
        self.assertNotIn("--offline", command)
        self.assertEqual(command.count("--sync"), 2)
        self.assertFalse(allowed)
        self.assertEqual(config.read_text(), "[source]\n")

    def test_combined_candidates_retain_both_notice_inventories_and_license_texts(self):
        portable = "Portable notice\n  - parser 1.1.3+spec-1.1.0 (https://example.invalid)\nPortable license\n"
        native = "Native notice\n  - parser 1.1.2+spec-1.1.0 (https://example.invalid)\nNative license\n"
        root_notice = self.write("THIRD-PARTY-NOTICES", portable)
        portable_notice = self.write("portable/THIRD-PARTY-NOTICES", portable)
        native_notice = self.write("archive/native/compat/THIRD-PARTY-NOTICES", native)
        catalog = {"portable": "portable/Cargo.toml", "compat": "archive/native/compat/Cargo.toml"}
        with mock.patch.object(release, "CRATE_MANIFESTS", catalog):
            release.supplement_native_notices(self.root)
            combined = native_notice.read_text()
            release.supplement_native_notices(self.root)
        self.assertEqual(native_notice.read_text(), combined)
        self.assertIn(native.strip(), combined)
        self.assertIn(portable, combined)
        self.assertEqual(root_notice.read_text(), portable)
        self.assertEqual(portable_notice.read_text(), portable)

    def test_dirty_candidates_never_invoke_package_or_publish(self):
        self.candidate(publishable=False)
        with mock.patch.object(release.subprocess, "run") as runner:
            with self.assertRaisesRegex(ValueError, "dirty-source"):
                release.publish_one(self.root, "jacs-core")
            runner.assert_not_called()

    def test_complete_candidate_packaging_compiles_extracted_archives_before_evidence(self):
        lock = self.write("source/Cargo.lock", "version = 4\n")
        self.write("candidate.json", json.dumps({
            "version": "0.15.0", "publishable": False, "crates": ["jacs-core"],
            "candidate_lock_sha256": release.sha256(lock),
        }))
        package_dir = self.root / "cargo/package"
        package_dir.mkdir(parents=True)
        shutil.copy2(self.archive(), package_dir / "jacs-core-0.15.0.crate")
        with mock.patch.object(release, "CRATES", ("jacs-core",)), mock.patch.object(release.subprocess, "run") as runner:
            release.package_all(self.root)
        self.assertEqual(runner.call_args.args[0], ["cargo", "package", "--workspace", "--locked"])
        checksums = json.loads((self.root / "checksums.json").read_text())
        self.assertEqual(checksums, {"jacs-core-0.15.0.crate": release.sha256(self.root / "archives/jacs-core-0.15.0.crate")})

    def test_candidate_lock_and_archive_changes_prevent_publication(self):
        archive, _ = self.candidate()
        with mock.patch.object(release.subprocess, "run") as runner:
            archive.write_text("different candidate")
            with self.assertRaisesRegex(ValueError, "candidate checksum changed"):
                release.publish_one(self.root, "jacs-core")
            self.write("source/Cargo.lock", "version=3\n")
            with self.assertRaisesRegex(ValueError, "dependency lock changed"):
                release.publish_one(self.root, "jacs-core")
            runner.assert_not_called()

    def test_verified_repack_must_match_before_registry_upload(self):
        _, repacked = self.candidate()
        repacked.write_text("different repack")
        with mock.patch.object(release.subprocess, "run") as runner, mock.patch.object(
            release, "fetch_exact_version_checksum",
        ) as probe:
            with self.assertRaisesRegex(ValueError, "differs from the complete reviewed candidate"):
                release.publish_one(self.root, "jacs-core")
            self.assertEqual(runner.call_count, 1)
            self.assertEqual(runner.call_args.args[0][1], "package")
            probe.assert_not_called()

    def test_retry_skips_existing_upload_and_verifies_registry_checksum(self):
        archive, _ = self.candidate()
        for exists in (None, "registry checksum"):
            with self.subTest(exists=exists), mock.patch.object(release.subprocess, "run", return_value=mock.Mock(returncode=0)) as runner, mock.patch.object(
                release, "fetch_exact_version_checksum", return_value=exists,
            ), mock.patch.object(release, "wait_for_version") as wait, mock.patch.object(
                release, "verify_archive_checksum",
            ) as verify:
                release.publish_one(self.root, "jacs-core")
                commands = [call.args[0] for call in runner.call_args_list]
                self.assertEqual([command[1] for command in commands], ["package"] if exists else ["package", "publish"])
                self.assertTrue(all("--locked" in command for command in commands))
                wait.assert_called_once_with("jacs-core", "0.15.0")
                verify.assert_called_once_with("jacs-core", "0.15.0", archive)

    def test_archives_require_legal_payload_and_safe_paths(self):
        self.assertEqual(release.validate_archive(self.archive(), "jacs-core", "0.15.0"), {"version": 4})
        for filename in ("LICENSE-APACHE", "THIRD-PARTY-NOTICES"):
            with self.subTest(filename=filename), self.assertRaisesRegex(ValueError, "archive missing"):
                release.validate_archive(self.archive(missing=(filename,)), "jacs-core", "0.15.0")
        with self.assertRaisesRegex(ValueError, "unsupported archive path"):
            release.validate_archive(self.archive(unexpected="jacs-core-0.15.0/../escape"), "jacs-core", "0.15.0")

    def test_archive_notices_must_cover_the_actual_packaged_dependency_version(self):
        lock = 'version=4\n[[package]]\nname="parser"\nversion="1.1.3+spec-1.1.0"\nsource="registry+https://example.invalid"\n'
        notices = "  - parser 1.1.2+spec-1.1.0 (https://example.invalid)\n"
        with self.assertRaisesRegex(ValueError, "dependency notices omit packaged versions"):
            release.validate_archive(self.archive(overrides={"Cargo.lock": lock, "THIRD-PARTY-NOTICES": notices}), "jacs-core", "0.15.0")
        notices += "  - parser 1.1.3+spec-1.1.0 (https://example.invalid)\n"
        self.assertEqual(release.validate_archive(self.archive(overrides={"Cargo.lock": lock, "THIRD-PARTY-NOTICES": notices}), "jacs-core", "0.15.0"), tomllib.loads(lock))

    def test_packaged_lock_cannot_add_unreviewed_or_changed_candidate_dependencies(self):
        source = "registry+https://github.com/rust-lang/crates.io-index"
        external = {"name": "external", "version": "1.0.0", "source": source, "checksum": "reviewed"}
        core = {"name": "jacs-core", "version": "0.15.0", "source": source, "checksum": "candidate"}
        allowed = release.third_party({"package": [external]})
        checksums = {"jacs-core-0.15.0.crate": "candidate"}
        release.validate_packaged_dependencies({"package": [external, core]}, allowed, checksums, "0.15.0")
        with self.assertRaisesRegex(ValueError, "unreviewed external"):
            release.validate_packaged_dependencies({"package": [{**external, "version": "1.0.1"}]}, allowed, checksums, "0.15.0")
        with self.assertRaisesRegex(ValueError, "candidate checksum"):
            release.validate_packaged_dependencies({"package": [{**core, "checksum": "wrong"}]}, allowed, checksums, "0.15.0")


if __name__ == "__main__":
    unittest.main()
