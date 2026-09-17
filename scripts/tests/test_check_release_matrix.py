from __future__ import annotations

import importlib.util
import io
import unittest
from contextlib import redirect_stderr
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
                for surface in ("crate", "cli", "wasm")
            }
        }
        rendered = release_matrix.render_documentation_matrix(matrix)
        self.assertIn(release_matrix.DOC_MATRIX_START, rendered)
        self.assertIn("Browser (`@jacs/wasm`)", rendered)
        self.assertEqual(rendered.count("runtime smoke passed"), 3)

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
                for surface in ("crate", "cli", "wasm")
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

    def test_registry_queries_all_three_crates_and_browser_package(self) -> None:
        urls = []

        def metadata(url, **_options):
            urls.append(url)
            if "crates.io" in url:
                return {"crate": {"max_version": "0.13.0"}}
            return {"version": "0.13.0"}

        with mock.patch.object(release_matrix, "get_json", side_effect=metadata):
            self.assertEqual(
                release_matrix.registry_versions(),
                {"crate": "0.13.0", "cli": "0.13.0", "wasm": "0.13.0"},
            )
        self.assertEqual(urls, [
            "https://crates.io/api/v1/crates/jacs-core",
            "https://crates.io/api/v1/crates/jacs-mcp",
            "https://crates.io/api/v1/crates/jacs-cli",
            "https://registry.npmjs.org/@jacs%2Fwasm/latest",
        ])

    def test_disagreeing_crate_versions_fail_closed(self) -> None:
        responses = [
            {"crate": {"max_version": "0.13.0"}},
            {"crate": {"max_version": "0.12.0"}},
            {"crate": {"max_version": "0.13.0"}},
        ]
        with mock.patch.object(release_matrix, "get_json", side_effect=responses):
            with self.assertRaisesRegex(ValueError, "different recorded registry"):
                release_matrix.registry_versions()

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
                for surface in ("crate", "cli", "wasm")
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
                for surface in ("crate", "cli", "wasm")
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


if __name__ == "__main__":
    unittest.main()
