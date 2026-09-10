from __future__ import annotations

import importlib.util
import hashlib
import json
import tomllib
import unittest
import urllib.error
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "crates_release_gate.py"

MAIN_CRATES = {
    "jacs-core": "jacs-core/Cargo.toml",
    "jacs-media": "jacs-media/Cargo.toml",
    "jacs": "jacs/Cargo.toml",
    "jacs-binding-core": "binding-core/Cargo.toml",
    "jacs-mcp": "jacs-mcp/Cargo.toml",
    "jacs-cli": "jacs-cli/Cargo.toml",
}
STORAGE_CRATES = {
    "jacs-duckdb": "jacs-duckdb/Cargo.toml",
    "jacs-redb": "jacs-redb/Cargo.toml",
    "jacs-surrealdb": "jacs-surrealdb/Cargo.toml",
    "jacs-postgresql": "jacs-postgresql/Cargo.toml",
}
PUBLISHABLE_CRATES = MAIN_CRATES | STORAGE_CRATES
IGNORED_MANIFEST_PARTS = {
    ".git",
    ".venv",
    "node_modules",
    "target",
    "vendor",
}
PACKAGE_LEGAL_FILES = (
    "LICENSE-APACHE",
    "THIRD-PARTY-NOTICES",
)


def load_module():
    spec = importlib.util.spec_from_file_location("crates_release_gate", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load crates release gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_manifest(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def rust_package_manifests() -> dict[str, tuple[str, dict]]:
    packages = {}
    for path in ROOT.rglob("Cargo.toml"):
        relative = path.relative_to(ROOT)
        if relative == Path("Cargo.toml") or any(
            part in IGNORED_MANIFEST_PARTS for part in relative.parts
        ):
            continue
        document = read_manifest(path)
        package = document.get("package")
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if not isinstance(name, str):
            raise AssertionError(f"{relative} has no string package.name")
        if name in packages:
            raise AssertionError(f"duplicate Rust package name: {name}")
        packages[name] = (relative.as_posix(), document)
    return packages


def resolved_license(document: dict, workspace: dict) -> object:
    claim = document["package"].get("license")
    if isinstance(claim, dict) and claim.get("workspace") is True:
        return workspace["workspace"]["package"].get("license")
    return claim


class FakeResponse:
    def __init__(self, payload: object, *, content_length: str | None = None):
        self.body = json.dumps(payload).encode()
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]


class CratesReleaseGateTests(unittest.TestCase):
    def test_publishable_crate_list_is_explicit_and_fail_closed(self) -> None:
        packages = rust_package_manifests()
        observed_publishable = {
            name: path
            for name, (path, document) in packages.items()
            if document["package"].get("publish") is not False
        }

        self.assertEqual(observed_publishable, PUBLISHABLE_CRATES)
        self.assertEqual(tuple(load_module().ALLOWED_CRATES), tuple(PUBLISHABLE_CRATES))

        for name, (_path, document) in packages.items():
            if name not in PUBLISHABLE_CRATES:
                with self.subTest(crate=name):
                    self.assertIs(document["package"].get("publish"), False)

    def test_publishable_crates_ship_exact_project_license_and_notices(self) -> None:
        workspace = read_manifest(ROOT / "Cargo.toml")
        canonical = {
            filename: (ROOT / filename).read_bytes() for filename in PACKAGE_LEGAL_FILES
        }

        for name, manifest_relative in PUBLISHABLE_CRATES.items():
            with self.subTest(crate=name):
                manifest = ROOT / manifest_relative
                document = read_manifest(manifest)
                package = document["package"]
                self.assertEqual(resolved_license(document, workspace), "Apache-2.0")

                package_root = manifest.parent
                for filename, expected in canonical.items():
                    packaged_copy = package_root / filename
                    self.assertTrue(
                        packaged_copy.is_file(),
                        f"{manifest_relative}: missing package copy {filename}",
                    )
                    self.assertEqual(
                        packaged_copy.read_bytes(),
                        expected,
                        f"{packaged_copy.relative_to(ROOT)} differs from {filename}",
                    )

                include = package.get("include")
                exclude = package.get("exclude")
                if include is not None:
                    for filename in PACKAGE_LEGAL_FILES:
                        self.assertIn(filename, include)
                elif exclude is not None:
                    self.fail(
                        f"{manifest_relative}: explicit exclusions require an "
                        "include allowlist containing the legal files"
                    )

    def test_exact_endpoint_and_response_identity_are_required(self) -> None:
        module = load_module()
        requests = []

        def open_url(request, *, timeout: int):
            self.assertEqual(timeout, 7)
            requests.append(request)
            return FakeResponse(
                {
                    "version": {
                        "crate": "jacs-core",
                        "num": "0.11.4",
                        "checksum": "a" * 64,
                    }
                },
                content_length="65",
            )

        self.assertTrue(
            module.probe_exact_version(
                "jacs-core",
                "0.11.4",
                open_url=open_url,
                timeout_seconds=7,
                attempts=1,
            )
        )
        self.assertEqual(
            requests[0].full_url,
            "https://crates.io/api/v1/crates/jacs-core/0.11.4",
        )
        self.assertIn("application/json", requests[0].headers["Accept"])

    def test_only_exact_404_means_not_published(self) -> None:
        module = load_module()

        def missing(request, *, timeout: int):
            del timeout
            raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)

        self.assertFalse(
            module.probe_exact_version("jacs", "0.11.4", open_url=missing, attempts=1)
        )

        for status in (400, 403, 429, 500):
            with self.subTest(status=status):

                def failed(request, *, timeout: int, status=status):
                    del timeout
                    raise urllib.error.HTTPError(
                        request.full_url, status, "failed", {}, None
                    )

                with self.assertRaises(module.ReleaseGateError):
                    module.probe_exact_version(
                        "jacs", "0.11.4", open_url=failed, attempts=1
                    )

    def test_transient_transport_failure_retries_with_a_bound(self) -> None:
        module = load_module()
        calls = 0

        def flaky(request, *, timeout: int):
            nonlocal calls
            del request, timeout
            calls += 1
            if calls < 3:
                raise urllib.error.URLError("temporary")
            return FakeResponse(
                {
                    "version": {
                        "crate": "jacs",
                        "num": "0.11.4",
                        "checksum": "a" * 64,
                    }
                }
            )

        self.assertTrue(
            module.probe_exact_version(
                "jacs",
                "0.11.4",
                open_url=flaky,
                attempts=3,
                delay_seconds=0,
            )
        )
        self.assertEqual(calls, 3)

    def test_malformed_oversized_or_mismatched_metadata_fails_closed(self) -> None:
        module = load_module()
        cases = (
            FakeResponse(
                {
                    "version": {
                        "crate": "other",
                        "num": "0.11.4",
                        "checksum": "a" * 64,
                    }
                }
            ),
            FakeResponse(
                {
                    "version": {
                        "crate": "jacs",
                        "num": "9.9.9",
                        "checksum": "a" * 64,
                    }
                }
            ),
            FakeResponse(
                {
                    "version": {
                        "crate": "jacs",
                        "num": "0.11.4",
                        "checksum": "not-a-checksum",
                    }
                }
            ),
            FakeResponse([], content_length="99999999"),
        )
        for response in cases:
            with self.subTest(body=response.body[:40]):
                with self.assertRaises((module.ReleaseGateError, ValueError)):
                    module.probe_exact_version(
                        "jacs",
                        "0.11.4",
                        open_url=lambda request, timeout, response=response: response,
                        attempts=1,
                    )

    def test_wait_accepts_only_eventual_exact_version(self) -> None:
        module = load_module()
        probes = iter((False, False, True))
        self.assertTrue(
            module.wait_for_version(
                "jacs-cli",
                "0.11.4",
                attempts=3,
                delay_seconds=0,
                probe=lambda *_args, **_kwargs: next(probes),
            )
        )
        with self.assertRaises(module.ReleaseGateError):
            module.wait_for_version(
                "jacs-cli",
                "0.11.4",
                attempts=2,
                delay_seconds=0,
                probe=lambda *_args, **_kwargs: False,
            )

    def test_invalid_crate_and_version_are_rejected_before_network(self) -> None:
        module = load_module()
        for crate, version in (("../../oops", "0.11.4"), ("jacs", "01.2.3")):
            with self.subTest(crate=crate, version=version):
                with self.assertRaises(ValueError):
                    module.probe_exact_version(
                        crate,
                        version,
                        open_url=lambda *_args, **_kwargs: self.fail("network called"),
                    )

    def test_exact_registry_checksum_must_match_candidate_archive(self) -> None:
        module = load_module()
        body = b"immutable crate candidate"
        expected = hashlib.sha256(body).hexdigest()
        with TemporaryDirectory() as directory:
            archive = Path(directory) / "jacs-0.11.4.crate"
            archive.write_bytes(body)
            self.assertEqual(
                module.verify_archive_checksum(
                    "jacs",
                    "0.11.4",
                    archive,
                    fetch_checksum=lambda *_args, **_kwargs: expected,
                ),
                expected,
            )
            with self.assertRaisesRegex(module.ReleaseGateError, "checksum mismatch"):
                module.verify_archive_checksum(
                    "jacs",
                    "0.11.4",
                    archive,
                    fetch_checksum=lambda *_args, **_kwargs: "b" * 64,
                )

    def test_release_workflow_uses_shared_exact_gate_for_all_six_crates(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release-crate.yml").read_text()
        self.assertNotIn("max_version", workflow)
        self.assertNotIn("https://crates.io/api/v1/crates/", workflow)
        self.assertEqual(workflow.count("scripts/crates_release_gate.py check"), 6)
        self.assertEqual(workflow.count("scripts/crates_release_gate.py wait"), 6)
        self.assertIn("scripts/crates_release_gate.py verify", workflow)
        for crate in (
            "jacs-core",
            "jacs-media",
            "jacs",
            "jacs-binding-core",
            "jacs-mcp",
            "jacs-cli",
        ):
            self.assertIn(f"--crate {crate}", workflow)

    def test_storage_release_uses_shared_exact_gate_and_checksum_verifier(self) -> None:
        workflow = (
            ROOT / ".github/workflows/release-storage-crate.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("max_version", workflow)
        self.assertIn("scripts/crates_release_gate.py check", workflow)
        self.assertIn("scripts/crates_release_gate.py wait", workflow)
        self.assertIn("scripts/crates_release_gate.py verify", workflow)


if __name__ == "__main__":
    unittest.main()
