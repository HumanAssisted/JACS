from __future__ import annotations

import importlib.util
import json
import shutil
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "check_project_license.py"
SPEC = importlib.util.spec_from_file_location("check_project_license", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
license_check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(license_check)


CONTRACT_FILES = (
    "LICENSE", "LICENSE-APACHE", "Cargo.toml",
    "archive/native/jacspy/pyproject.toml",
    "jacs-wasm/scripts/finalize-pkg.sh",
    *license_check.EXACT_LICENSE_COPIES,
    *license_check.NODE_MANIFESTS,
)


def make_consistent_fixture(destination: Path) -> None:
    files = set(CONTRACT_FILES)
    pending = [Path("Cargo.toml")]
    visited = set()
    while pending:
        manifest = pending.pop()
        if manifest in visited:
            continue
        visited.add(manifest)
        files.add(manifest.as_posix())
        table = tomllib.loads((ROOT / manifest).read_text()).get("workspace", {})
        for field in ("members", "exclude"):
            pending.extend(manifest.parent / entry / "Cargo.toml" for entry in table.get(field, []))
    for relative in files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


class ProjectLicenseContractTests(unittest.TestCase):
    def test_current_repository_uses_consistent_apache_terms(self) -> None:
        self.assertEqual(license_check.check_project_license(ROOT), [])

    def test_consistent_project_and_package_claims_pass(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            make_consistent_fixture(root)

            self.assertEqual(license_check.check_project_license(root), [])

    def test_non_apache_package_manifest_claim_fails(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            make_consistent_fixture(root)
            manifest = root / "archive/native/jacsnpm/package.json"
            package = json.loads(manifest.read_text(encoding="utf-8"))
            package["license"] = "MIT"
            manifest.write_text(json.dumps(package), encoding="utf-8")

            errors = license_check.check_project_license(root)

        self.assertIn(
            "archive/native/jacsnpm/package.json declares license 'MIT'; expected 'Apache-2.0'",
            errors,
        )

    def test_noncanonical_package_license_copy_fails(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            make_consistent_fixture(root)
            (root / "archive/native/jacsnpm/LICENSE").write_text("different terms\n", encoding="utf-8")

            errors = license_check.check_project_license(root)

        self.assertTrue(
            any(
                "archive/native/jacsnpm/LICENSE" in error and "does not match" in error
                for error in errors
            ),
            errors,
        )

    def test_cargo_package_license_claim_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            make_consistent_fixture(root)
            manifest = root / "jacs-core/Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    'license = "Apache-2.0"', 'license = "MIT"', 1
                ),
                encoding="utf-8",
            )

            errors = license_check.check_project_license(root)

        self.assertIn(
            "jacs-core/Cargo.toml declares package license 'MIT'; expected 'Apache-2.0'",
            errors,
        )

    def test_archive_workspace_uses_its_own_license_scope(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            make_consistent_fixture(root)
            manifest = root / "archive/native/Cargo.toml"
            manifest.write_text(manifest.read_text().replace('license = "Apache-2.0"', 'license = "MIT"', 1))
            errors = license_check.check_project_license(root)
        self.assertTrue(any("archive/native/Cargo.toml declares workspace package license 'MIT'" in error for error in errors), errors)
        self.assertTrue(any("archive/native/jacs-redb/Cargo.toml inherits workspace license 'MIT'" in error for error in errors), errors)

    def test_excluded_standalone_archive_package_is_checked(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            make_consistent_fixture(root)
            manifest = root / "archive/native/jacs-surrealdb/Cargo.toml"
            manifest.write_text(manifest.read_text().replace('license = "Apache-2.0"', 'license = "MIT"', 1))
            errors = license_check.check_project_license(root)
        self.assertIn("archive/native/jacs-surrealdb/Cargo.toml declares package license 'MIT'; expected 'Apache-2.0'", errors)

    def test_missing_python_license_file_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            make_consistent_fixture(root)
            (root / "archive/native/jacspy/LICENSE-APACHE").unlink()

            errors = license_check.check_project_license(root)

        self.assertTrue(
            any("archive/native/jacspy/LICENSE-APACHE is missing" in error for error in errors),
            errors,
        )

    def test_wasm_finalizer_must_copy_the_canonical_license(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            make_consistent_fixture(root)
            finalizer = root / "jacs-wasm/scripts/finalize-pkg.sh"
            finalizer.write_text(
                finalizer.read_text(encoding="utf-8").replace(
                    'LICENSE_SOURCE="${JACS_WASM_DIR}/../LICENSE-APACHE"',
                    'LICENSE_SOURCE="${JACS_WASM_DIR}/LICENSE"',
                    1,
                ),
                encoding="utf-8",
            )

            errors = license_check.check_project_license(root)

        self.assertIn(
            "jacs-wasm/scripts/finalize-pkg.sh must source ../LICENSE-APACHE",
            errors,
        )

    def test_cli_accepts_current_tree_without_printing_license_contents(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = license_check.main(["--root", str(ROOT)])

        self.assertEqual(status, 0)
        self.assertIn("license claims are consistent", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn("right to Sell the Software", stderr.getvalue())

    def test_release_preflight_and_security_ci_run_the_checker(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        release_preflight = makefile.split("release-preflight:", 1)[1].split("\n\n", 1)[
            0
        ]
        security = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")

        self.assertIn("check", release_preflight.splitlines()[0].split())
        check_dependencies = next(line for line in makefile.splitlines() if line.startswith("check:"))
        self.assertIn("check-project-license", check_dependencies.split())
        self.assertIn("python3 scripts/check_project_license.py", makefile)
        self.assertIn("python3 scripts/check_project_license.py", security)


if __name__ == "__main__":
    unittest.main()
