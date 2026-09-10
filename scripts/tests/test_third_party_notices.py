from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "third_party_notices.py"
sys.path.insert(0, str(SCRIPT.parent))
import third_party_notices as notices  # noqa: E402

sys.path.pop(0)
START_MARKER = "===== BEGIN GENERATED CARGO DEPENDENCY INVENTORY ====="
END_MARKER = "===== END GENERATED CARGO DEPENDENCY INVENTORY ====="
STATIC_SUFFIX = "FULL LICENSE TEXTS\n\nLICENSE BODY MUST REMAIN BYTE-EXACT\n"
REQUIRED_CRATE_DIRS = (
    "jacs",
    "jacs-core",
    "jacs-media",
    "binding-core",
    "jacs-mcp",
    "jacs-cli",
    "jacs-duckdb",
    "jacs-redb",
    "jacs-surrealdb",
    "jacs-postgresql",
)
REQUIRED_BINDING_DIRS = ("jacsnpm", "jacspy", "jacspy/python/jacs")
REQUIRED_PACKAGE_DIRS = REQUIRED_CRATE_DIRS + REQUIRED_BINDING_DIRS


def package(
    package_id: str,
    name: str,
    version: str,
    license_expression: str | None,
    *,
    repository: str | None = None,
    homepage: str | None = None,
    source: str | None = "registry+https://github.com/rust-lang/crates.io-index",
    license_file: str | None = None,
    manifest_path: str | None = None,
) -> dict[str, object]:
    return {
        "id": package_id,
        "name": name,
        "version": version,
        "license": license_expression,
        "repository": repository,
        "homepage": homepage,
        "source": source,
        "license_file": license_file,
        "manifest_path": manifest_path,
    }


def metadata(
    packages: list[dict[str, object]],
    *,
    workspace_members: list[str],
    resolved_ids: list[str] | None = None,
) -> dict[str, object]:
    if resolved_ids is None:
        resolved_ids = [str(item["id"]) for item in packages]
    return {
        "packages": packages,
        "workspace_members": workspace_members,
        "resolve": {"nodes": [{"id": package_id} for package_id in resolved_ids]},
    }


def notice_template(inventory: str = "stale inventory\n") -> bytes:
    return (
        "THIRD-PARTY SOFTWARE NOTICES AND INFORMATION\n\n"
        "SPECIAL ACKNOWLEDGMENTS\n\n"
        f"{START_MARKER}\n"
        f"{inventory}"
        f"{END_MARKER}\n\n"
        f"{STATIC_SUFFIX}"
    ).encode()


def prepare_notice(repo: Path, content: bytes | None = None) -> Path:
    output = repo / "THIRD-PARTY-NOTICES"
    output.write_bytes(notice_template() if content is None else content)
    for crate_dir in REQUIRED_CRATE_DIRS:
        copy = repo / crate_dir / "THIRD-PARTY-NOTICES"
        copy.parent.mkdir()
        copy.write_bytes(b"stale crate copy\n")
    for binding_dir in REQUIRED_BINDING_DIRS:
        (repo / binding_dir).mkdir(parents=True, exist_ok=True)
    return output


class ThirdPartyNoticesTests(unittest.TestCase):
    def run_script(
        self,
        repo: Path,
        metadata_value: dict[str, object] | list[dict[str, object]],
        *extra_args: str,
        clarifications_file: Path | None = None,
        output: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        metadata_values = (
            metadata_value if isinstance(metadata_value, list) else [metadata_value]
        )
        metadata_args: list[str] = []
        for index, value in enumerate(metadata_values):
            metadata_path = repo / f"metadata-{index}.json"
            metadata_path.write_text(json.dumps(value), encoding="utf-8")
            metadata_args.extend(("--metadata-file", str(metadata_path)))
        mode_args = extra_args or ("--write",)
        clarification_args = (
            ["--clarifications-file", str(clarifications_file)]
            if clarifications_file is not None
            else []
        )
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                *metadata_args,
                *clarification_args,
                "--output",
                str(output or repo / "THIRD-PARTY-NOTICES"),
                *mode_args,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_generation_is_deterministic_and_excludes_workspace_members(self) -> None:
        first_party_id = "path+file:///repo/jacs#0.11.4"
        alpha_id = "registry+https://example.invalid/index#alpha@1.0.0"
        zeta_id = "registry+https://example.invalid/index#zeta@2.0.0"
        packages = [
            package(
                zeta_id,
                "zeta",
                "2.0.0",
                "MIT OR Apache-2.0",
                homepage="https://example.invalid/zeta",
            ),
            package(
                first_party_id,
                "jacs",
                "0.11.4",
                "Apache-2.0",
                repository="https://github.com/HumanAssisted/JACS",
                source=None,
            ),
            package(
                alpha_id,
                "alpha",
                "1.0.0",
                "MIT OR Apache-2.0",
                repository="https://example.invalid/alpha",
            ),
        ]
        value = metadata(packages, workspace_members=[first_party_id])

        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = Path(first_dir)
            second = Path(second_dir)
            prepare_notice(first)
            prepare_notice(second)

            first_result = self.run_script(first, value)
            reversed_value = metadata(
                list(reversed(packages)), workspace_members=[first_party_id]
            )
            second_result = self.run_script(second, reversed_value)

            self.assertEqual(first_result.returncode, 0, first_result.stderr)
            self.assertEqual(second_result.returncode, 0, second_result.stderr)
            first_bytes = (first / "THIRD-PARTY-NOTICES").read_bytes()
            self.assertEqual(first_bytes, (second / "THIRD-PARTY-NOTICES").read_bytes())
            text = first_bytes.decode()
            self.assertNotIn("jacs 0.11.4", text)
            self.assertIn("Third-party packages: 2", text)
            self.assertIn("License expression: MIT OR Apache-2.0", text)
            self.assertLess(text.index("alpha 1.0.0"), text.index("zeta 2.0.0"))
            self.assertTrue(text.endswith(STATIC_SUFFIX))
            for crate_dir in REQUIRED_PACKAGE_DIRS:
                copy = first / crate_dir / "THIRD-PARTY-NOTICES"
                self.assertFalse(copy.is_symlink())
                self.assertTrue(stat.S_ISREG(copy.lstat().st_mode))
                self.assertEqual(
                    copy.read_bytes(),
                    first_bytes,
                )

    def test_multiple_metadata_graphs_merge_and_exclude_all_workspace_members(
        self,
    ) -> None:
        jacs_id = "path+file:///repo/jacs#0.11.4"
        surreal_id = "path+file:///repo/jacs-surrealdb#0.1.19"
        shared_id = "registry+index#shared@1.0.0"
        unique_id = "registry+index#surreal-only@2.0.0"
        jacs = package(
            jacs_id,
            "jacs",
            "0.11.4",
            "Apache-2.0",
            source=None,
        )
        shared = package(shared_id, "shared", "1.0.0", "MIT")
        root_metadata = metadata(
            [jacs, shared],
            workspace_members=[jacs_id],
        )
        surreal_metadata = metadata(
            [
                package(
                    surreal_id,
                    "jacs-surrealdb",
                    "0.1.19",
                    "Apache-2.0",
                    source=None,
                ),
                jacs,
                shared,
                package(unique_id, "surreal-only", "2.0.0", "MPL-2.0"),
            ],
            workspace_members=[surreal_id],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = prepare_notice(repo)
            result = self.run_script(repo, [root_metadata, surreal_metadata])
            self.assertEqual(result.returncode, 0, result.stderr)
            text = output.read_text()
            self.assertIn("Third-party packages: 2", text)
            self.assertIn("shared 1.0.0", text)
            self.assertIn("surreal-only 2.0.0", text)
            self.assertNotIn("jacs 0.11.4", text)
            self.assertNotIn("jacs-surrealdb 0.1.19", text)

    def test_only_resolved_packages_are_noticed(self) -> None:
        used_id = "registry+index#used@1.0.0"
        unused_id = "registry+index#unused@9.0.0"
        value = metadata(
            [
                package(used_id, "used", "1.0.0", "MIT"),
                package(unused_id, "unused", "9.0.0", None),
            ],
            workspace_members=[],
            resolved_ids=[used_id],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = prepare_notice(repo)
            result = self.run_script(repo, value)
            self.assertEqual(result.returncode, 0, result.stderr)
            text = output.read_text()
            self.assertIn("used 1.0.0", text)
            self.assertNotIn("unused 9.0.0", text)

    def test_missing_license_metadata_fails_without_rewriting(self) -> None:
        dependency_id = "registry+index#unlicensed@1.2.3"
        value = metadata(
            [package(dependency_id, "unlicensed", "1.2.3", "")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = prepare_notice(repo)
            before = notice_template()
            result = self.run_script(repo, value)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unlicensed 1.2.3", result.stderr)
            self.assertIn("missing Cargo license metadata", result.stderr)
            self.assertEqual(output.read_bytes(), before)

    def test_license_file_metadata_embeds_exact_text_once(self) -> None:
        dependency_id = "registry+index#file-licensed@1.2.3"
        license_text = (
            "Example Source License 1.0\r\n\r\nExact redistribution terms.\r\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            package_root = repo / "registry" / "file-licensed-1.2.3"
            package_root.mkdir(parents=True)
            manifest_path = package_root / "Cargo.toml"
            manifest_path.write_text(
                "[package]\nname = 'file-licensed'\n", encoding="utf-8"
            )
            (package_root / "LICENSE").write_bytes(license_text.encode())
            value = metadata(
                [
                    package(
                        dependency_id,
                        "file-licensed",
                        "1.2.3",
                        None,
                        license_file="LICENSE",
                        manifest_path=str(manifest_path),
                    )
                ],
                workspace_members=[],
            )
            output = prepare_notice(repo)

            result = self.run_script(repo, value)

            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = output.read_text(encoding="utf-8")
            digest = hashlib.sha256(license_text.encode()).hexdigest()
            self.assertIn(f"Cargo license file SHA-256: {digest}", rendered)
            self.assertIn("Cargo-deny normalized XXH32: 0x5e6e5286", rendered)
            self.assertIn("License source path: LICENSE", rendered)
            normalized_text = license_text.replace("\r\n", "\n").rstrip()
            self.assertEqual(rendered.count(normalized_text), 1)
            self.assertNotIn(b"\r", output.read_bytes())

    def test_reviewed_clarification_embeds_source_for_metadata_licensed_package(
        self,
    ) -> None:
        dependency_id = "registry+index#metadata-licensed@1.2.3"
        license_text = (
            "Example Source License 1.0\r\n\r\nExact redistribution terms.\r\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            package_root = repo / "registry" / "metadata-licensed-1.2.3"
            package_root.mkdir(parents=True)
            manifest_path = package_root / "Cargo.toml"
            manifest_path.write_text("[package]\nname = 'metadata-licensed'\n")
            (package_root / "LICENSE").write_bytes(license_text.encode())
            clarification_path = repo / "clarifications.toml"
            clarification_path.write_text(f"""[[reviewed]]
names = ["metadata-licensed"]
expression = "Apache-2.0"
path = "LICENSE"
cargo-deny-hash = 0x5e6e5286
sha256 = "{hashlib.sha256(license_text.encode()).hexdigest()}"
""")
            value = metadata(
                [
                    package(
                        dependency_id,
                        "metadata-licensed",
                        "1.2.3",
                        "Apache-2.0",
                        manifest_path=str(manifest_path),
                    )
                ],
                workspace_members=[],
            )
            output = prepare_notice(repo)

            result = self.run_script(
                repo, value, clarifications_file=clarification_path
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = output.read_text()
            self.assertIn("Cargo-deny normalized XXH32: 0x5e6e5286", rendered)
            self.assertIn("metadata-licensed 1.2.3", rendered)

    def test_root_notice_symlink_is_rejected(self) -> None:
        value = metadata([], workspace_members=[])
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            target = repo / "real-notice"
            target.write_bytes(notice_template())
            output = repo / "THIRD-PARTY-NOTICES"
            try:
                output.symlink_to(target.name)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")

            result = self.run_script(repo, value, "--check")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink", result.stderr.lower())

    def test_symlinked_custom_output_parent_is_rejected_for_check_and_write(
        self,
    ) -> None:
        dependency_id = "registry+index#dependency@1.0.0"
        value = metadata(
            [package(dependency_id, "dependency", "1.0.0", "MIT")],
            workspace_members=[],
        )
        updated_id = "registry+index#dependency@2.0.0"
        updated_value = metadata(
            [package(updated_id, "dependency", "2.0.0", "MIT")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            output = prepare_notice(repo)
            generated = self.run_script(repo, value)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            before = output.read_bytes()

            linked_repo = root / "linked-repo"
            try:
                linked_repo.symlink_to(repo.name, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")

            for mode in ("--check", "--write"):
                with self.subTest(mode=mode):
                    requested_value = value if mode == "--check" else updated_value
                    result = self.run_script(
                        repo,
                        requested_value,
                        mode,
                        output=linked_repo / "THIRD-PARTY-NOTICES",
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("symlink", result.stderr.lower())
                    self.assertEqual(output.read_bytes(), before)

    @unittest.skipIf(
        sys.platform == "win32", "secure dirfd operations are unavailable on Windows"
    )
    def test_check_fails_closed_if_copy_parent_is_swapped_before_read(self) -> None:
        dependency_id = "registry+index#dependency@1.0.0"
        value = metadata(
            [package(dependency_id, "dependency", "1.0.0", "MIT")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = prepare_notice(repo)
            generated = self.run_script(repo, value)
            self.assertEqual(generated.returncode, 0, generated.stderr)

            original_parent = repo / "jacs"
            original_identity = original_parent.stat()
            moved_parent = repo / "jacs-held"
            replacement_parent = repo / "jacs-replacement"
            replacement_parent.mkdir()
            replacement_copy = replacement_parent / "THIRD-PARTY-NOTICES"
            replacement_copy.write_bytes(output.read_bytes())
            triggered = False
            real_open = os.open

            def racing_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal triggered
                if (
                    not triggered
                    and path == "THIRD-PARTY-NOTICES"
                    and dir_fd is not None
                ):
                    parent_identity = os.fstat(dir_fd)
                    if (
                        parent_identity.st_dev == original_identity.st_dev
                        and parent_identity.st_ino == original_identity.st_ino
                    ):
                        original_parent.rename(moved_parent)
                        replacement_parent.rename(original_parent)
                        triggered = True
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(notices.os, "open", side_effect=racing_open):
                with self.assertRaisesRegex(
                    notices.NoticeError, "parent changed during secure operation"
                ):
                    notices.update_notices(value, output=output, check=True)

            self.assertTrue(triggered)
            self.assertEqual(
                (original_parent / "THIRD-PARTY-NOTICES").read_bytes(),
                output.read_bytes(),
            )

    @unittest.skipIf(
        sys.platform == "win32", "secure dirfd operations are unavailable on Windows"
    )
    def test_write_does_not_follow_copy_parent_swapped_during_atomic_replace(
        self,
    ) -> None:
        dependency_id = "registry+index#dependency@1.0.0"
        value = metadata(
            [package(dependency_id, "dependency", "1.0.0", "MIT")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = prepare_notice(repo)
            generated = self.run_script(repo, value)
            self.assertEqual(generated.returncode, 0, generated.stderr)

            original_parent = repo / "jacs"
            original_copy = original_parent / "THIRD-PARTY-NOTICES"
            original_copy.write_bytes(b"stale notice\n")
            original_identity = original_parent.stat()
            moved_parent = repo / "jacs-held"
            replacement_parent = repo / "jacs-replacement"
            replacement_parent.mkdir()
            replacement_copy = replacement_parent / "THIRD-PARTY-NOTICES"
            replacement_copy.write_bytes(b"attacker-controlled notice\n")
            triggered = False
            real_open = os.open

            def racing_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal triggered
                if (
                    not triggered
                    and isinstance(path, str)
                    and path.startswith(".THIRD-PARTY-NOTICES.")
                    and flags & os.O_CREAT
                    and dir_fd is not None
                ):
                    parent_identity = os.fstat(dir_fd)
                    if (
                        parent_identity.st_dev == original_identity.st_dev
                        and parent_identity.st_ino == original_identity.st_ino
                    ):
                        original_parent.rename(moved_parent)
                        replacement_parent.rename(original_parent)
                        triggered = True
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(notices.os, "open", side_effect=racing_open):
                with self.assertRaisesRegex(
                    notices.NoticeError, "parent changed during secure operation"
                ):
                    notices.update_notices(value, output=output, check=False)

            self.assertTrue(triggered)
            self.assertEqual(
                (original_parent / "THIRD-PARTY-NOTICES").read_bytes(),
                b"attacker-controlled notice\n",
            )
            self.assertEqual(
                (moved_parent / "THIRD-PARTY-NOTICES").read_bytes(),
                output.read_bytes(),
            )

    def test_atomic_writes_preserve_modes_and_create_missing_copy_as_0644(
        self,
    ) -> None:
        first_id = "registry+index#dependency@1.0.0"
        first_value = metadata(
            [package(first_id, "dependency", "1.0.0", "MIT")],
            workspace_members=[],
        )
        second_id = "registry+index#dependency@2.0.0"
        second_value = metadata(
            [package(second_id, "dependency", "2.0.0", "MIT")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = prepare_notice(repo)
            generated = self.run_script(repo, first_value)
            self.assertEqual(generated.returncode, 0, generated.stderr)

            preserved_copy = repo / "jacs" / "THIRD-PARTY-NOTICES"
            missing_copy = repo / "jacs-core" / "THIRD-PARTY-NOTICES"
            output.chmod(0o640)
            preserved_copy.chmod(0o600)
            missing_copy.unlink()

            rewritten = self.run_script(repo, second_value)

            self.assertEqual(rewritten.returncode, 0, rewritten.stderr)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(preserved_copy.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(missing_copy.stat().st_mode), 0o644)
            self.assertEqual(preserved_copy.read_bytes(), output.read_bytes())
            self.assertEqual(missing_copy.read_bytes(), output.read_bytes())
            self.assertFalse(
                any(repo.rglob(".THIRD-PARTY-NOTICES.*.tmp")),
                "atomic notice writes must not leave temporary files",
            )

    def test_unsupported_platform_fails_closed_without_rewriting(self) -> None:
        value = metadata([], workspace_members=[])
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = prepare_notice(repo)
            before = output.read_bytes()

            with mock.patch.object(
                notices, "_SECURE_DIRFD_OPERATIONS_SUPPORTED", False
            ):
                with self.assertRaisesRegex(
                    notices.NoticeError, "refusing an unsafe portable fallback"
                ):
                    notices.update_notices(value, output=output, check=False)

            self.assertEqual(output.read_bytes(), before)

    def test_required_copy_parent_symlink_is_rejected(self) -> None:
        dependency_id = "registry+index#dependency@1.0.0"
        value = metadata(
            [package(dependency_id, "dependency", "1.0.0", "MIT")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            prepare_notice(repo)
            linked_parent = repo / "jacs"
            (linked_parent / "THIRD-PARTY-NOTICES").unlink()
            linked_parent.rmdir()
            target_parent = repo / "outside-copy-parent"
            target_parent.mkdir()
            target_copy = target_parent / "THIRD-PARTY-NOTICES"
            target_copy.write_text("must not change\n")
            try:
                linked_parent.symlink_to(target_parent.name, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")

            result = self.run_script(repo, value)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink", result.stderr.lower())
            self.assertEqual(target_copy.read_text(), "must not change\n")

    def test_license_file_must_stay_within_package_root(self) -> None:
        dependency_id = "registry+index#unsafe-license@1.0.0"
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            package_root = repo / "registry" / "unsafe-license-1.0.0"
            package_root.mkdir(parents=True)
            manifest_path = package_root / "Cargo.toml"
            manifest_path.write_text(
                "[package]\nname = 'unsafe-license'\n", encoding="utf-8"
            )
            (repo / "outside-license").write_text("outside terms\n", encoding="utf-8")
            value = metadata(
                [
                    package(
                        dependency_id,
                        "unsafe-license",
                        "1.0.0",
                        None,
                        license_file="../../outside-license",
                        manifest_path=str(manifest_path),
                    )
                ],
                workspace_members=[],
            )
            output = prepare_notice(repo)
            before = output.read_bytes()

            result = self.run_script(repo, value)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("escapes package root", result.stderr)
            self.assertEqual(output.read_bytes(), before)

    def test_check_rejects_stale_inventory_then_accepts_generated_inventory(
        self,
    ) -> None:
        dependency_id = "registry+index#dependency@4.5.6"
        value = metadata(
            [package(dependency_id, "dependency", "4.5.6", "BSD-3-Clause")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            prepare_notice(repo)

            stale = self.run_script(repo, value, "--check")
            self.assertNotEqual(stale.returncode, 0)
            self.assertIn("stale", stale.stderr.lower())

            generated = self.run_script(repo, value)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            fresh = self.run_script(repo, value, "--check")
            self.assertEqual(fresh.returncode, 0, fresh.stderr)

    def test_write_creates_and_check_verifies_python_and_node_copies(self) -> None:
        dependency_id = "registry+index#dependency@1.0.0"
        value = metadata(
            [package(dependency_id, "dependency", "1.0.0", "MIT")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = prepare_notice(repo)
            generated = self.run_script(repo, value)
            self.assertEqual(generated.returncode, 0, generated.stderr)

            for package_dir in REQUIRED_BINDING_DIRS:
                copy = repo / package_dir / "THIRD-PARTY-NOTICES"
                self.assertEqual(copy.read_bytes(), output.read_bytes())
            self.assertEqual(self.run_script(repo, value, "--check").returncode, 0)

            (repo / "jacspy" / "THIRD-PARTY-NOTICES").write_text("stale copy\n")
            mismatch = self.run_script(repo, value, "--check")
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertIn("jacspy/THIRD-PARTY-NOTICES", mismatch.stderr)
            self.assertIn("does not exactly match", mismatch.stderr)

    @unittest.skipIf(
        sys.platform == "win32", "symlink creation may require elevated privileges"
    )
    def test_check_rejects_byte_identical_required_copy_symlink(self) -> None:
        dependency_id = "registry+index#dependency@1.0.0"
        value = metadata(
            [package(dependency_id, "dependency", "1.0.0", "MIT")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = prepare_notice(repo)
            generated = self.run_script(repo, value)
            self.assertEqual(generated.returncode, 0, generated.stderr)

            copy = repo / REQUIRED_CRATE_DIRS[0] / "THIRD-PARTY-NOTICES"
            copy.unlink()
            copy.symlink_to(output)
            self.assertTrue(copy.is_symlink())
            self.assertEqual(copy.read_bytes(), output.read_bytes())

            result = self.run_script(repo, value, "--check")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("required notice copy is not a regular file", result.stderr)
            self.assertIn(
                f"{REQUIRED_CRATE_DIRS[0]}/THIRD-PARTY-NOTICES", result.stderr
            )

    @unittest.skipIf(
        sys.platform == "win32", "symlink creation may require elevated privileges"
    )
    def test_write_replaces_byte_identical_required_copy_symlink(self) -> None:
        dependency_id = "registry+index#dependency@1.0.0"
        value = metadata(
            [package(dependency_id, "dependency", "1.0.0", "MIT")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            output = prepare_notice(repo)
            generated = self.run_script(repo, value)
            self.assertEqual(generated.returncode, 0, generated.stderr)

            copy = repo / REQUIRED_CRATE_DIRS[0] / "THIRD-PARTY-NOTICES"
            copy.unlink()
            copy.symlink_to(output)
            self.assertTrue(copy.is_symlink())
            self.assertEqual(copy.read_bytes(), output.read_bytes())
            expected = output.read_bytes()

            rewritten = self.run_script(repo, value)

            self.assertEqual(rewritten.returncode, 0, rewritten.stderr)
            self.assertFalse(copy.is_symlink())
            self.assertTrue(stat.S_ISREG(copy.lstat().st_mode))
            self.assertEqual(output.read_bytes(), expected)
            self.assertEqual(copy.read_bytes(), expected)
            self.assertEqual(self.run_script(repo, value, "--check").returncode, 0)

    def test_check_requires_every_publishable_crate_copy(self) -> None:
        dependency_id = "registry+index#dependency@1.0.0"
        value = metadata(
            [package(dependency_id, "dependency", "1.0.0", "MIT")],
            workspace_members=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            prepare_notice(repo)
            self.assertEqual(self.run_script(repo, value).returncode, 0)
            missing = repo / REQUIRED_CRATE_DIRS[-1] / "THIRD-PARTY-NOTICES"
            missing.unlink()
            result = self.run_script(repo, value, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                f"{REQUIRED_CRATE_DIRS[-1]}/THIRD-PARTY-NOTICES", result.stderr
            )
            self.assertIn("required notice copy is missing", result.stderr)

    def test_missing_markers_fail_without_rewriting(self) -> None:
        value = metadata([], workspace_members=[])
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            before = b"legal text without generated markers\n"
            output = prepare_notice(repo, before)
            result = self.run_script(repo, value)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("generated inventory markers", result.stderr)
            self.assertEqual(output.read_bytes(), before)

    def test_makefile_and_security_workflow_block_stale_notices(self) -> None:
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn(
            "third-party-notices:\n\t@python3 scripts/third_party_notices.py --write",
            makefile,
        )
        self.assertIn(
            "check-third-party-notices:\n\t@python3 scripts/third_party_notices.py --check",
            makefile,
        )
        release_preflight = next(
            line
            for line in makefile.splitlines()
            if line.startswith("release-preflight:")
        )
        self.assertIn("check-third-party-notices", release_preflight)

        security = (ROOT / ".github" / "workflows" / "security.yml").read_text()
        self.assertIn("Check THIRD-PARTY-NOTICES freshness", security)
        self.assertIn("python3 scripts/third_party_notices.py --check", security)


if __name__ == "__main__":
    unittest.main()
