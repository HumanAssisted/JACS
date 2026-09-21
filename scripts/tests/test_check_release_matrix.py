from __future__ import annotations

import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock
from pathlib import Path
import copy
import json
import urllib.error


SCRIPT = Path(__file__).resolve().parents[1] / "check-release-matrix.py"
SPEC = importlib.util.spec_from_file_location("check_release_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_matrix)


class SourceVersionAlignmentTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sources = {
            **{relative: name for name, relative in release_matrix.CRATE_MANIFESTS.items()},
            "jacs-wasm/package.template.json": "@hai.ai/jacs-wasm (npm)",
            "archive/native/jacsnpm/package.json": "@hai.ai/jacs (npm)",
            "jacs-mcp/contract/jacs-mcp-contract.json": "jacs-mcp contract",
            "archive/native/jacs-mcp/contract/jacs-mcp-contract.json": "jacs-mcp-compat contract",
            "archive/native/jacspy/pyproject.toml": "jacs (Python)",
            "jacs-mobile/distribution/android/library/build.gradle.kts": "jacs-mobile (Android)",
        }
        for relative in self.sources:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative.endswith("Cargo.toml"):
                path.write_text(f'[package]\nname = "{self.sources[relative]}"\nversion = "1.2.3"\n')
            elif relative.endswith("pyproject.toml"):
                path.write_text('[project]\nname = "jacs"\nversion = "1.2.3"\n')
            elif relative.endswith("build.gradle.kts"):
                path.write_text('group = "ai.hai"\nversion = "1.2.3"\n')
            elif "contract" in relative:
                path.write_text('{"server": {"version": "1.2.3"}}\n')
            elif relative == "archive/native/jacsnpm/package.json":
                path.write_text('{"name": "@hai.ai/jacs", "version": "1.2.3"}\n')
            else:
                path.write_text('{"version": "1.2.3"}\n')
        (self.root / "jacsgo").mkdir()
        (self.root / "jacsgo/go.mod").write_text("module github.com/HumanAssisted/JACS/jacsgo\n")
        self.npm_lock = self.root / "archive/native/jacsnpm/package-lock.json"
        self.npm_lock.write_text(json.dumps({
            "name": "@hai.ai/jacs", "version": "1.2.3", "lockfileVersion": 3,
            "packages": {"": {"name": "@hai.ai/jacs", "version": "1.2.3"}},
        }))
        matrix = {
            "source_version": "1.2.3",
            "artifacts": {
                surface: {"registry": "registry", "version": None,
                          "status": "source-only", "platforms": [], "evidence": "source fixture"}
                for surface in release_matrix.SURFACE_LABELS
            },
        }
        matrix["artifacts"]["crate"]["versions"] = dict.fromkeys(release_matrix.CRATE_MANIFESTS)
        matrix_path = self.root / "shipped-artifacts.json"
        matrix_path.write_text(json.dumps(matrix))
        docs_path = self.root / "release-status.md"
        docs_path.write_text(release_matrix.render_documentation_matrix(matrix))
        patch = mock.patch.multiple(
            release_matrix, ROOT=self.root, MATRIX_PATH=matrix_path,
            DEPLOYMENT_DOC_PATH=docs_path,
        )
        patch.start()
        self.addCleanup(patch.stop)

    def check(self, *args: str):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), mock.patch.object(
            release_matrix, "get_json", side_effect=AssertionError("offline check contacted a registry"),
        ):
            status = release_matrix.main(list(args))
        return status, stdout.getvalue(), stderr.getvalue()

    def test_all_active_package_and_contract_mismatches_fail(self) -> None:
        for relative, label in self.sources.items():
            path = self.root / relative
            original = path.read_text()
            path.write_text(original.replace("1.2.3", "9.9.9"))
            for args in ((), ("--show-versions",)):
                with self.subTest(source=relative, args=args):
                    status, stdout, stderr = self.check(*args)
                    self.assertEqual(status, 1)
                    self.assertIn(f"{label} source version 9.9.9 != matrix source 1.2.3", stderr)
                    self.assertNotIn("OK:", stdout)
            path.write_text(original)

    def test_listing_covers_all_sources_without_changing_files(self) -> None:
        before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        status, stdout, stderr = self.check("--show-versions")
        self.assertEqual(status, 0, stderr)
        for label in (*self.sources.values(), "jacsgo (Go)", "release matrix"):
            self.assertIn(f"  {label:<24} 1.2.3", stdout)
        self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()})

    def test_missing_active_metadata_fails(self) -> None:
        for relative in self.sources:
            with self.subTest(source=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.unlink()
                status, stdout, stderr = self.check()
                self.assertEqual(status, 1)
                self.assertIn("cannot read active source versions", stderr)
                self.assertNotIn("OK:", stdout)
                path.write_bytes(original)

    def test_unpublished_example_versions_do_not_need_to_match(self) -> None:
        path = self.root / "archive/native/jacs/examples/observability/Cargo.toml"
        path.parent.mkdir(parents=True)
        original = '[package]\nname = "jacs-observability-demo"\nversion = "0.10.1"\n'
        path.write_text(original)
        status, stdout, stderr = self.check("--show-versions")
        self.assertEqual(status, 0, stderr)
        self.assertNotIn("jacs-observability-demo", stdout)
        self.assertEqual(path.read_text(), original)

    def test_npm_lock_metadata_must_match_package(self) -> None:
        original = json.loads(self.npm_lock.read_text())
        for target in ("top", "root"):
            for field, value in (("name", "@other/jacs"), ("version", "9.9.9")):
                with self.subTest(target=target, field=field):
                    broken = copy.deepcopy(original)
                    metadata = broken if target == "top" else broken["packages"][""]
                    metadata[field] = value
                    self.npm_lock.write_text(json.dumps(broken))
                    status, stdout, stderr = self.check()
                    self.assertEqual(status, 1)
                    self.assertIn("npm source metadata validation failed", stderr)
                    self.assertNotIn("OK:", stdout)

    def test_ambiguous_or_unsupported_android_versions_fail(self) -> None:
        path = self.root / "jacs-mobile/distribution/android/library/build.gradle.kts"
        for contents in ('', 'version = "1.2.3"\nversion = "9.9.9"\n', 'version = project.property("version")\n'):
            with self.subTest(contents=contents):
                path.write_text(contents)
                status, stdout, stderr = self.check()
                self.assertEqual(status, 1)
                self.assertIn("Android Maven metadata: expected one literal version field", stderr)
                self.assertNotIn("OK:", stdout)


class ReleasePlatformEvidenceTests(unittest.TestCase):
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

    def test_registry_json_fetch_is_size_bounded_and_retries_transport_errors(self) -> None:
        body = json.dumps({"ok": True}).encode()
        responses = iter((urllib.error.URLError("temporary"), self.Response(body)))
        timeouts: list[int] = []

        def open_url(request, timeout: int):
            del request
            timeouts.append(timeout)
            response = next(responses)
            if isinstance(response, BaseException):
                raise response
            return response

        result = release_matrix.get_json(
            "https://registry.npmjs.org/example",
            open_url=open_url,
            attempts=2,
            delay_seconds=0,
            timeout_seconds=9,
            max_bytes=1024,
        )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(timeouts, [9, 9])

    def test_documentation_matrix_is_rendered_from_inventory(self) -> None:
        matrix = {
            "artifacts": {
                surface: {
                    "registry": "registry",
                    "version": "1.2.3",
                    "status": "published",
                    "platforms": ["test target"],
                    "evidence": "runtime smoke passed",
                }
                for surface in release_matrix.SURFACE_LABELS
            }
        }
        rendered = release_matrix.render_documentation_matrix(matrix)
        self.assertIn(release_matrix.DOC_MATRIX_START, rendered)
        self.assertIn("Browser (`@hai.ai/jacs-wasm`)", rendered)
        self.assertIn("Node.js (`@hai.ai/jacs`)", rendered)
        self.assertEqual(rendered.count("runtime smoke passed"), 6)

    def test_deployment_header_matches_inventory_observation_date(self) -> None:
        matrix = json.loads(release_matrix.MATRIX_PATH.read_text())
        deployment = release_matrix.DEPLOYMENT_DOC_PATH.read_text()
        self.assertIn(
            f"observed\n{matrix['observed_at']} against source",
            deployment,
        )

    def test_documentation_matrix_fails_without_evidence(self) -> None:
        matrix = {
            "artifacts": {
                surface: {
                    "registry": "registry",
                    "version": "1.2.3",
                    "status": "published",
                    "platforms": ["test target"],
                    "evidence": "runtime smoke passed",
                }
                for surface in release_matrix.SURFACE_LABELS
            }
        }
        broken = copy.deepcopy(matrix)
        del broken["artifacts"]["wasm"]["evidence"]
        with self.assertRaises(ValueError):
            release_matrix.render_documentation_matrix(broken)

    def test_active_inventory_rejects_archived_surfaces(self) -> None:
        matrix = json.loads(release_matrix.MATRIX_PATH.read_text())
        matrix["artifacts"]["node"] = copy.deepcopy(matrix["artifacts"]["wasm"])
        with self.assertRaisesRegex(ValueError, "active artifact scope"):
            release_matrix.render_documentation_matrix(matrix)

    def test_registry_queries_complete_catalog_and_language_registries(self) -> None:
        urls = []

        def metadata(url, **_options):
            urls.append(url)
            if "crates.io" in url:
                return {"crate": {"max_version": "0.13.0"}}
            if "pypi.org" in url:
                return {"info": {"version": "0.13.0"}}
            if "proxy.golang.org" in url:
                return {"Version": "v0.13.0"}
            return {"version": "0.13.0"}

        with mock.patch.object(release_matrix, "get_json", side_effect=metadata):
            self.assertEqual(
                release_matrix.registry_versions(),
                dict.fromkeys(release_matrix.SURFACE_LABELS, "0.13.0"),
            )
        self.assertEqual(urls, [
            *[f"https://crates.io/api/v1/crates/{crate}" for crate in release_matrix.CRATE_MANIFESTS],
            "https://registry.npmjs.org/@hai.ai%2Fjacs/latest",
            "https://registry.npmjs.org/@hai.ai%2Fjacs-wasm/latest",
            "https://pypi.org/pypi/jacs/json",
            "https://proxy.golang.org/github.com/!human!assisted/!j!a!c!s/jacsgo/@latest",
        ])

    def test_pre_release_registry_observations_preserve_missing_and_different_crates(self) -> None:
        responses = [{"crate": {"max_version": "0.13.0"}}, None,
                     *[{"crate": {"max_version": "0.12.0"}} for _ in range(15)]]
        with mock.patch.object(release_matrix, "get_json", side_effect=responses):
            observed = release_matrix.registry_crate_versions()
        self.assertEqual(observed["jacs-core"], "0.13.0")
        self.assertIsNone(observed["jacs-media"])
        self.assertEqual(observed["jacs-surrealdb"], "0.12.0")

    def test_cli_platforms_map_to_exact_release_assets(self) -> None:
        assets = release_matrix.expected_cli_assets(
            "0.11.4",
            [
                "macOS arm64",
                "Linux x86_64 glibc",
                "Windows x86_64",
            ],
        )
        self.assertEqual(
            assets,
            {
                "jacs-cli-0.11.4-darwin-arm64.tar.gz",
                "jacs-cli-0.11.4-linux-x64.tar.gz",
                "jacs-cli-0.11.4-windows-x64.zip",
            },
        )


    def test_unknown_published_platform_label_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            release_matrix.expected_cli_assets("0.11.4", ["Plan 9 mips"])

    def test_wasm_publication_requires_registry_integrity_and_provenance(self) -> None:
        matrix = {
            "artifacts": {
                surface: {
                    "version": None,
                    "status": "unpublished",
                    "platforms": [],
                }
                for surface in release_matrix.SURFACE_LABELS
            }
        }
        matrix["artifacts"]["wasm"] = {
            "version": "0.11.4",
            "status": "published-current",
            "platforms": ["Browser"],
        }
        registry = {
            "dist": {
                "integrity": "sha512-example",
                "attestations": {"provenance": {"predicateType": "example"}},
            }
        }
        with mock.patch.object(release_matrix, "get_json", return_value=registry):
            failures: list[str] = []
            release_matrix.validate_online_asset_evidence(matrix, failures)
        self.assertEqual(failures, [])

        registry["dist"]["attestations"] = {}
        with mock.patch.object(release_matrix, "get_json", return_value=registry):
            failures = []
            with redirect_stderr(io.StringIO()):
                release_matrix.validate_online_asset_evidence(matrix, failures)
        self.assertEqual(
            failures,
            ["WASM npm release 0.11.4 has no registry provenance attestation"],
        )

    def test_cli_release_requires_exact_checksums_and_sbom_inventory(self) -> None:
        matrix = {
            "artifacts": {
                surface: {
                    "version": None,
                    "status": "unpublished",
                    "platforms": [],
                }
                for surface in release_matrix.SURFACE_LABELS
            }
        }
        matrix["artifacts"]["cli"] = {
            "version": "0.11.4",
            "status": "published-current",
            "platforms": list(release_matrix.CLI_PLATFORM_ASSETS),
        }
        complete_names = release_matrix.expected_github_release_assets(
            "cli/v0.11.4"
        )
        complete_release = {
            "assets": [
                {"name": name, "digest": "sha256:" + "a" * 64}
                for name in sorted(complete_names)
            ]
        }

        with mock.patch.object(
            release_matrix, "get_json", return_value=complete_release
        ):
            failures: list[str] = []
            release_matrix.validate_online_asset_evidence(matrix, failures)
        self.assertEqual(failures, [])

        incomplete_release = copy.deepcopy(complete_release)
        incomplete_release["assets"] = [
            asset
            for asset in incomplete_release["assets"]
            if asset["name"] != "jacs-cli.spdx.json"
        ]
        with mock.patch.object(
            release_matrix, "get_json", return_value=incomplete_release
        ):
            failures = []
            with redirect_stderr(io.StringIO()):
                release_matrix.validate_online_asset_evidence(matrix, failures)
        self.assertIn(
            "CLI GitHub release asset missing: jacs-cli.spdx.json", failures
        )

    def test_native_npm_publication_requires_integrity_and_provenance(self) -> None:
        matrix = {"artifacts": {
            surface: {"version": None, "status": "unpublished", "platforms": []}
            for surface in release_matrix.SURFACE_LABELS
        }}
        matrix["artifacts"]["npm"] = {
            "version": "0.15.0", "status": "published-current", "platforms": ["Node.js"],
        }
        registry = {"dist": {
            "integrity": "sha512-example",
            "attestations": {"provenance": {"predicateType": "example"}},
        }}
        with mock.patch.object(release_matrix, "get_json", return_value=registry) as query:
            failures = []
            release_matrix.validate_online_asset_evidence(matrix, failures)
        self.assertEqual(failures, [])
        query.assert_called_once_with("https://registry.npmjs.org/@hai.ai%2Fjacs/0.15.0")
        for field, message in (("integrity", "integrity digest"), ("attestations", "provenance attestation")):
            with self.subTest(field=field):
                broken = copy.deepcopy(registry)
                del broken["dist"][field]
                with mock.patch.object(release_matrix, "get_json", return_value=broken), redirect_stderr(io.StringIO()):
                    failures = []
                    release_matrix.validate_online_asset_evidence(matrix, failures)
                self.assertEqual(failures, [f"Node npm release 0.15.0 has no registry {message}"])


if __name__ == "__main__":
    unittest.main()
