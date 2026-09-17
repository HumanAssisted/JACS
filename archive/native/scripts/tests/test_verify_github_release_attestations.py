from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import tempfile
import unittest
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_github_release_attestations.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "verify_github_release_attestations", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def release_metadata(module, tag: str, *, extra: str | None = None):
    spec = module.release_spec(tag)
    names = sorted(spec.expected_assets)
    if extra is not None:
        names.append(extra)
    return {
        "tag_name": tag,
        "draft": False,
        "assets": [
            {
                "name": name,
                "size": len(name.encode()),
                "browser_download_url": (
                    "https://github.com/HumanAssisted/JACS/releases/download/"
                    f"{urllib.parse.quote(tag, safe='')}/"
                    f"{urllib.parse.quote(name, safe='')}"
                ),
            }
            for name in names
        ],
    }


class ReleaseInventoryTests(unittest.TestCase):
    def test_cli_inventory_is_exact_and_complete(self) -> None:
        module = load_module()
        assets = module.release_spec("cli/v0.11.4").expected_assets

        self.assertEqual(len(assets), 12)
        for suffix in (
            "darwin-arm64.tar.gz",
            "darwin-x64.tar.gz",
            "linux-x64.tar.gz",
            "linux-arm64.tar.gz",
            "windows-x64.zip",
        ):
            archive = f"jacs-cli-0.11.4-{suffix}"
            self.assertIn(archive, assets)
            self.assertIn(f"{archive}.sha256", assets)
        self.assertIn("sha256sums.txt", assets)
        self.assertIn("jacs-cli.spdx.json", assets)

    def test_go_inventory_is_exact_and_complete(self) -> None:
        module = load_module()
        assets = module.release_spec("jacsgo/v0.11.4").expected_assets

        self.assertEqual(len(assets), 12)
        for platform in (
            "darwin-arm64.dylib",
            "darwin-amd64.dylib",
            "linux-amd64.so",
            "linux-arm64.so",
        ):
            library = f"jacsgo-v0.11.4-{platform}"
            self.assertIn(library, assets)
            self.assertIn(f"{library}.sha256", assets)
        self.assertIn("jacsgo-v0.11.4-sha256sums.txt", assets)
        self.assertIn("jacsgo.spdx.json", assets)
        self.assertIn("LICENSE-APACHE", assets)
        self.assertIn("THIRD-PARTY-NOTICES", assets)

    def test_rejects_missing_release_asset(self) -> None:
        module = load_module()
        tag = "cli/v0.11.4"
        metadata = release_metadata(module, tag)
        missing = metadata["assets"].pop()["name"]

        with self.assertRaisesRegex(ValueError, rf"missing.*{missing}"):
            module.validate_release_metadata(tag, metadata)

    def test_rejects_extra_release_asset(self) -> None:
        module = load_module()
        tag = "jacsgo/v0.11.4"
        metadata = release_metadata(module, tag, extra="unexpected.bin")

        with self.assertRaisesRegex(ValueError, r"unexpected.*unexpected\.bin"):
            module.validate_release_metadata(tag, metadata)

    def test_rejects_wrong_signer_workflow(self) -> None:
        module = load_module()

        with self.assertRaisesRegex(ValueError, "signer workflow"):
            module.validate_signer_workflow(
                module.release_spec("cli/v0.11.4"),
                "HumanAssisted/JACS/.github/workflows/attacker.yml",
            )

    def test_waits_for_partial_release_but_rejects_unexpected_assets_immediately(
        self,
    ) -> None:
        module = load_module()
        tag = "cli/v0.11.4"
        complete = release_metadata(module, tag)
        partial = json.loads(json.dumps(complete))
        partial["assets"].pop()
        responses = iter((partial, complete))
        calls = 0

        def fetch(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            return next(responses)

        assets = module.fetch_complete_release_assets(
            tag,
            fetch=fetch,
            attempts=2,
            delay_seconds=0,
        )
        self.assertEqual(calls, 2)
        self.assertEqual({asset.name for asset in assets}, module.release_spec(tag).expected_assets)

        calls = 0
        unexpected = release_metadata(module, tag, extra="attacker.bin")

        def fetch_unexpected(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            return unexpected

        with self.assertRaisesRegex(ValueError, "unexpected"):
            module.fetch_complete_release_assets(
                tag,
                fetch=fetch_unexpected,
                attempts=5,
                delay_seconds=0,
            )
        self.assertEqual(calls, 1)

    def test_rejects_non_semver_release_tag(self) -> None:
        module = load_module()

        for tag in ("cli/v01.2.3", "cli/v1.2", "jacsgo/v1.2.3-01", "other/v1.2.3"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "tag"):
                module.release_spec(tag)

    def test_recorded_matrix_selects_only_published_semantic_github_releases(self) -> None:
        module = load_module()
        matrix = {
            "artifacts": {
                "cli": {"version": "0.11.4", "status": "published-current"},
                "go": {
                    "version": "v0.0.0-20260613002535-44c41d103146",
                    "status": "pseudo-version-native-library-required",
                },
            }
        }
        specs = module.recorded_release_specs(matrix)
        self.assertEqual([spec.tag for spec in specs], ["cli/v0.11.4"])

        matrix["artifacts"]["go"] = {
            "version": "v0.11.4",
            "status": "published-current",
        }
        specs = module.recorded_release_specs(matrix)
        self.assertEqual(
            [spec.tag for spec in specs],
            ["cli/v0.11.4", "jacsgo/v0.11.4"],
        )

    def test_matrix_mode_cryptographically_verifies_each_recorded_release(self) -> None:
        module = load_module()
        calls: list[tuple[str, str, dict[str, int]]] = []

        def verify(tag: str, workflow: str, **options: int) -> None:
            calls.append((tag, workflow, options))

        with tempfile.TemporaryDirectory() as directory:
            matrix_path = Path(directory) / "matrix.json"
            matrix_path.write_text(
                json.dumps(
                    {
                        "artifacts": {
                            "cli": {
                                "version": "0.11.4",
                                "status": "published",
                            },
                            "go": {
                                "version": "v0.11.4",
                                "status": "published",
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            module.verify_recorded_releases(
                matrix_path,
                verify=verify,
                verify_options={"attempts": 2, "command_timeout_seconds": 9},
            )

        self.assertEqual([call[0] for call in calls], ["cli/v0.11.4", "jacsgo/v0.11.4"])
        self.assertTrue(all(call[2]["attempts"] == 2 for call in calls))
        self.assertTrue(
            all(call[2]["command_timeout_seconds"] == 9 for call in calls)
        )


class AttestationPolicyTests(unittest.TestCase):
    def test_verifies_every_asset_with_fixed_repository_workflow_and_tag(self) -> None:
        module = load_module()
        tag = "cli/v0.11.4"
        spec = module.release_spec(tag)
        calls: list[tuple[list[str], int]] = []

        def run(command: list[str], timeout_seconds: int):
            calls.append((command, timeout_seconds))
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for name in sorted(spec.expected_assets):
                path = Path(directory) / name
                path.write_bytes(name.encode())
                paths.append(path)
            module.verify_attestations(
                spec,
                paths,
                run=run,
                attempts=1,
                delay_seconds=0,
                command_timeout_seconds=37,
            )

        self.assertEqual(len(calls), 12)
        for command, timeout_seconds in calls:
            self.assertEqual(command[:3], ["gh", "attestation", "verify"])
            self.assertIn("--repo", command)
            self.assertEqual(command[command.index("--repo") + 1], "HumanAssisted/JACS")
            self.assertEqual(
                command[command.index("--signer-workflow") + 1],
                "HumanAssisted/JACS/.github/workflows/release-cli.yml",
            )
            self.assertEqual(
                command[command.index("--source-ref") + 1],
                "refs/tags/cli/v0.11.4",
            )
            self.assertIn("--deny-self-hosted-runners", command)
            self.assertEqual(timeout_seconds, 37)

    def test_retries_a_failed_attestation_then_succeeds(self) -> None:
        module = load_module()
        spec = module.release_spec("cli/v0.11.4")
        calls = 0

        def run(command: list[str], timeout_seconds: int):
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(command, 1 if calls == 1 else 0)

        with tempfile.TemporaryDirectory() as directory:
            asset = Path(directory) / sorted(spec.expected_assets)[0]
            asset.write_bytes(b"asset")
            module.verify_attestations(
                spec,
                [asset],
                run=run,
                attempts=2,
                delay_seconds=0,
                command_timeout_seconds=10,
            )

        self.assertEqual(calls, 2)


class ReleaseChecksumTests(unittest.TestCase):
    @staticmethod
    def materialize(module, spec, directory: Path) -> list[Path]:
        payloads = sorted(spec.payload_assets)
        entries: list[str] = []
        for name in payloads:
            body = f"payload:{name}".encode()
            (directory / name).write_bytes(body)
            digest = hashlib.sha256(body).hexdigest()
            line = f"{digest}  {name}\n"
            (directory / f"{name}.sha256").write_text(line, encoding="ascii")
            entries.append(line)
        (directory / spec.checksum_manifest).write_text(
            "".join(entries), encoding="ascii"
        )
        sbom = "jacs-cli.spdx.json" if spec.tag.startswith("cli/") else "jacsgo.spdx.json"
        (directory / sbom).write_text('{"spdxVersion":"SPDX-2.3"}\n')
        for name in spec.expected_assets:
            path = directory / name
            if not path.exists():
                path.write_text(f"release metadata:{name}\n", encoding="utf-8")
        return [directory / name for name in sorted(spec.expected_assets)]

    def test_checksum_manifests_bind_every_release_payload(self) -> None:
        module = load_module()
        for tag in ("cli/v0.11.4", "jacsgo/v0.11.4"):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                spec = module.release_spec(tag)
                paths = self.materialize(module, spec, root)
                module.verify_release_checksums(spec, paths)

                payload = root / sorted(spec.payload_assets)[0]
                payload.write_bytes(b"corrupted after manifest generation")
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                    module.verify_release_checksums(spec, paths)

    def test_checksum_manifest_rejects_missing_or_unexpected_entries(self) -> None:
        module = load_module()
        spec = module.release_spec("cli/v0.11.4")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self.materialize(module, spec, root)
            manifest = root / spec.checksum_manifest
            manifest.write_text(manifest.read_text().splitlines()[0] + "\n")
            with self.assertRaisesRegex(RuntimeError, "inventory mismatch"):
                module.verify_release_checksums(spec, paths)

    def test_fails_after_attestation_retry_exhaustion(self) -> None:
        module = load_module()
        spec = module.release_spec("jacsgo/v0.11.4")
        calls = 0

        def fail(command: list[str], timeout_seconds: int):
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess(command, 1)

        with tempfile.TemporaryDirectory() as directory:
            asset = Path(directory) / sorted(spec.expected_assets)[0]
            asset.write_bytes(b"asset")
            with self.assertRaisesRegex(RuntimeError, asset.name):
                module.verify_attestations(
                    spec,
                    [asset],
                    run=fail,
                    attempts=3,
                    delay_seconds=0,
                    command_timeout_seconds=10,
                )

        self.assertEqual(calls, 3)

    def test_command_timeout_is_retried_and_reported(self) -> None:
        module = load_module()
        spec = module.release_spec("cli/v0.11.4")
        calls = 0

        def time_out(command: list[str], timeout_seconds: int):
            nonlocal calls
            calls += 1
            raise subprocess.TimeoutExpired(command, timeout_seconds)

        with tempfile.TemporaryDirectory() as directory:
            asset = Path(directory) / sorted(spec.expected_assets)[0]
            asset.write_bytes(b"asset")
            with self.assertRaisesRegex(RuntimeError, r"timed out.*2 attempt"):
                module.verify_attestations(
                    spec,
                    [asset],
                    run=time_out,
                    attempts=2,
                    delay_seconds=0,
                    command_timeout_seconds=9,
                )

        self.assertEqual(calls, 2)


class BoundedDownloadTests(unittest.TestCase):
    class Response:
        def __init__(self, body: bytes):
            self.body = body
            self.offset = 0
            self.headers = {"Content-Length": str(len(body))}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self, size: int = -1) -> bytes:
            if size < 0:
                size = len(self.body) - self.offset
            chunk = self.body[self.offset : self.offset + size]
            self.offset += len(chunk)
            return chunk

    def test_download_stops_when_body_exceeds_declared_asset_size(self) -> None:
        module = load_module()
        tag = "cli/v0.11.4"
        metadata = release_metadata(module, tag)
        metadata["assets"][0]["size"] = 3
        asset = module.validate_release_metadata(
            tag,
            metadata,
            max_asset_bytes=1024,
            max_total_bytes=1024 * 1024,
        )[0]

        def open_url(request, timeout: int):
            return self.Response(b"four")

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / asset.name
            with self.assertRaisesRegex(ValueError, "declared size"):
                module.download_asset(
                    asset,
                    destination,
                    open_url=open_url,
                    timeout_seconds=5,
                    attempts=1,
                    delay_seconds=0,
                )
            self.assertFalse(destination.exists())

    def test_rejects_declared_inventory_over_total_limit_before_download(self) -> None:
        module = load_module()
        tag = "jacsgo/v0.11.4"
        metadata = release_metadata(module, tag)

        with self.assertRaisesRegex(ValueError, "total download size"):
            module.validate_release_metadata(
                tag,
                metadata,
                max_asset_bytes=1024,
                max_total_bytes=1,
            )


if __name__ == "__main__":
    unittest.main()
