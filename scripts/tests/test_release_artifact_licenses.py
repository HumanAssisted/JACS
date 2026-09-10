from __future__ import annotations

import importlib.util
import io
import tarfile
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "check_release_artifact_licenses.py"
SPEC = importlib.util.spec_from_file_location(
    "check_release_artifact_licenses", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
artifact_licenses = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact_licenses)


LICENSE = b"canonical project license\n"
NOTICES = b"current third-party notices\n"


def make_tar(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def make_zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)


class ReleaseArtifactLicenseTests(unittest.TestCase):
    def test_tar_and_zip_require_exact_root_license_and_notices(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for extension, builder in (("tar.gz", make_tar), ("zip", make_zip)):
                with self.subTest(extension=extension):
                    archive = root / f"candidate.{extension}"
                    builder(
                        archive,
                        [
                            ("jacs-cli", b"binary"),
                            ("LICENSE-APACHE", LICENSE),
                            ("THIRD-PARTY-NOTICES", NOTICES),
                        ],
                    )
                    self.assertEqual(
                        artifact_licenses.archive_errors(archive, LICENSE, NOTICES),
                        [],
                    )

    def test_missing_mismatched_nested_and_duplicate_files_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            cases = {
                "missing": [
                    ("jacs-cli", b"binary"),
                    ("LICENSE-APACHE", LICENSE),
                ],
                "mismatch": [
                    ("jacs-cli", b"binary"),
                    ("LICENSE-APACHE", b"different"),
                    ("THIRD-PARTY-NOTICES", NOTICES),
                ],
                "nested": [
                    ("jacs-cli", b"binary"),
                    ("docs/LICENSE-APACHE", LICENSE),
                    ("docs/THIRD-PARTY-NOTICES", NOTICES),
                ],
                "duplicate": [
                    ("jacs-cli", b"binary"),
                    ("LICENSE-APACHE", LICENSE),
                    ("LICENSE-APACHE", LICENSE),
                    ("THIRD-PARTY-NOTICES", NOTICES),
                ],
            }
            for name, entries in cases.items():
                with self.subTest(case=name):
                    archive = root / f"{name}.tar.gz"
                    make_tar(archive, entries)
                    self.assertNotEqual(
                        artifact_licenses.archive_errors(archive, LICENSE, NOTICES),
                        [],
                    )

    def test_cli_release_packages_and_verifies_both_files_on_every_os(self) -> None:
        workflow = (ROOT / ".github/workflows/release-cli.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'tar czf "${CLI_ASSET_NAME}.tar.gz" jacs-cli LICENSE-APACHE THIRD-PARTY-NOTICES',
            workflow,
        )
        self.assertIn(
            'Compress-Archive -Path "jacs-cli.exe", "LICENSE-APACHE", "THIRD-PARTY-NOTICES"',
            workflow,
        )
        self.assertGreaterEqual(
            workflow.count("scripts/check_release_artifact_licenses.py"), 2
        )
        for staged_file in (
            "LICENSE-APACHE",
            "THIRD-PARTY-NOTICES",
            "scripts/check_release_artifact_licenses.py",
            "scripts/smoke-cli-installers.py",
            "jacspy/pyproject.toml",
            "jacspy/python/jacs/cli_runner.py",
            "jacsnpm/package.json",
            "jacsnpm/scripts/install-cli.js",
            "jacsnpm/bin/jacs-cli.js",
        ):
            with self.subTest(staged_file=staged_file):
                self.assertIn(f'$prefix/{staged_file}', workflow)

    def test_go_release_distributes_and_attests_license_and_notices(self) -> None:
        workflow = (ROOT / ".github/workflows/release-jacsgo.yml").read_text(
            encoding="utf-8"
        )
        verifier = (
            ROOT / "scripts/verify_github_release_attestations.py"
        ).read_text(encoding="utf-8")

        self.assertIn("cp LICENSE-APACHE artifacts/LICENSE-APACHE", workflow)
        self.assertIn(
            "cp THIRD-PARTY-NOTICES artifacts/THIRD-PARTY-NOTICES", workflow
        )
        # The prepared artifact directory is uploaded, attested, and published
        # as one exact bundle, so the staged notice files follow every binary.
        self.assertGreaterEqual(workflow.count("artifacts/*"), 3)
        self.assertIn('"LICENSE-APACHE"', verifier)
        self.assertIn('"THIRD-PARTY-NOTICES"', verifier)


if __name__ == "__main__":
    unittest.main()
