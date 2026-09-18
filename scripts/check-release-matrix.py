#!/usr/bin/env python3
"""Validate source version alignment and the observed public registry matrix.

The checked-in matrix is evidence, not a promise that all packages are current.
Use --online to detect registry drift and --require-parity after a coordinated
release to require every primary package to match the source version.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from http_policy import open_no_redirect
    from verify_github_release_attestations import release_spec as _release_spec
except ModuleNotFoundError:  # Imported as scripts.check_release_matrix in tests.
    from scripts.http_policy import open_no_redirect
    from scripts.verify_github_release_attestations import (
        release_spec as _release_spec,
    )


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "release" / "shipped-artifacts.json"
DEPLOYMENT_DOC_PATH = ROOT / "docs" / "release-status.md"
USER_AGENT = "jacs-release-matrix/1 (+https://github.com/HumanAssisted/JACS)"
REGISTRY_JSON_LIMIT_BYTES = 8 * 1024 * 1024
DOC_MATRIX_START = "<!-- BEGIN GENERATED SHIPPED ARTIFACT MATRIX -->"
DOC_MATRIX_END = "<!-- END GENERATED SHIPPED ARTIFACT MATRIX -->"

CLI_PLATFORM_ASSETS = {
    "macOS arm64": ("darwin-arm64", "tar.gz"),
    "macOS x86_64": ("darwin-x64", "tar.gz"),
    "Linux x86_64 glibc": ("linux-x64", "tar.gz"),
    "Linux arm64 glibc": ("linux-arm64", "tar.gz"),
    "Windows x86_64": ("windows-x64", "zip"),
}


SURFACE_LABELS = {
    "crate": "Rust (`jacs-core`, `jacs-mcp`, `jacs-cli`)",
    "cli": "CLI (`jacs-cli`)",
    "wasm": "Browser (`@jacs/wasm`)",
}


def render_documentation_matrix(matrix: dict) -> str:
    """Render the shipped-artifact table from the canonical JSON inventory."""
    lines = [
        DOC_MATRIX_START,
        "| Surface | Shipped version/status | Prebuilt targets | CI/runtime evidence and limits |",
        "|---|---|---|---|",
    ]
    artifacts = matrix["artifacts"]
    if set(artifacts) != set(SURFACE_LABELS):
        raise ValueError("active artifact scope must be exactly crate, cli and wasm")
    for surface in SURFACE_LABELS:
        artifact = artifacts[surface]
        version = artifact["version"]
        version_text = "unpublished" if version is None else f"`{version}`"
        status = artifact["status"].replace("-", " ")
        targets = "; ".join(artifact["platforms"])
        evidence = artifact.get("evidence")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError(f"{surface} artifact is missing documentation evidence")
        cells = [
            SURFACE_LABELS[surface],
            f"{artifact['registry']} {version_text}; {status}",
            targets,
            evidence.strip(),
        ]
        if any("|" in cell or "\n" in cell for cell in cells):
            raise ValueError(f"{surface} documentation cell contains unsupported Markdown syntax")
        lines.append("| " + " | ".join(cells) + " |")
    lines.append(DOC_MATRIX_END)
    return "\n".join(lines)


def replace_documentation_matrix(document: str, rendered: str) -> str:
    if document.count(DOC_MATRIX_START) != 1 or document.count(DOC_MATRIX_END) != 1:
        raise ValueError("deployment documentation must contain exactly one generated matrix block")
    start = document.index(DOC_MATRIX_START)
    end = document.index(DOC_MATRIX_END, start) + len(DOC_MATRIX_END)
    return document[:start] + rendered + document[end:]


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def source_versions() -> dict[str, str]:
    return {
        "crate": load_toml(ROOT / "jacs-core" / "Cargo.toml")["package"]["version"],
        "cli": load_toml(ROOT / "jacs-cli" / "Cargo.toml")["package"]["version"],
        "wasm": load_toml(ROOT / "jacs-wasm" / "Cargo.toml")["package"]["version"],
    }


def get_json(
    url: str,
    *,
    missing_is_none: bool = False,
    open_url=open_no_redirect,
    attempts: int = 3,
    delay_seconds: int = 2,
    timeout_seconds: int = 20,
    max_bytes: int = REGISTRY_JSON_LIMIT_BYTES,
) -> dict | None:
    if attempts < 1 or delay_seconds < 0 or timeout_seconds < 1 or max_bytes < 1:
        raise ValueError("registry bounds/attempts must be positive and delay non-negative")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            with open_url(request, timeout=timeout_seconds) as response:
                raw_length = response.headers.get("Content-Length")
                if raw_length is not None:
                    try:
                        length = int(raw_length)
                    except (TypeError, ValueError) as error:
                        raise ValueError(
                            "registry response has an invalid Content-Length"
                        ) from error
                    if length < 0 or length > max_bytes:
                        raise ValueError("registry response exceeds the JSON size limit")
                body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ValueError("registry response exceeds the JSON size limit")
            parsed = json.loads(body)
            if not isinstance(parsed, dict):
                raise ValueError("registry response must be a JSON object")
            return parsed
        except urllib.error.HTTPError as error:
            if missing_is_none and error.code == 404:
                return None
            if error.code not in {408, 429} and not 500 <= error.code < 600:
                raise
            last_error = error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
        if attempt < attempts and delay_seconds:
            time.sleep(delay_seconds)
    raise RuntimeError(
        f"registry request failed after {attempts} attempts: {last_error}"
    ) from last_error


def registry_versions() -> dict[str, str | None]:
    crates = {}
    for package in ("jacs-core", "jacs-mcp", "jacs-cli"):
        metadata = get_json(
            f"https://crates.io/api/v1/crates/{package}", missing_is_none=True
        )
        crates[package] = None if metadata is None else metadata["crate"]["max_version"]
    if len(set(crates.values())) != 1:
        raise ValueError(f"active crates have different recorded registry versions: {crates}")
    wasm = get_json(
        "https://registry.npmjs.org/@jacs%2Fwasm/latest", missing_is_none=True
    )
    return {
        "crate": crates["jacs-core"],
        "cli": crates["jacs-cli"],
        "wasm": None if wasm is None else wasm["version"],
    }


def expected_cli_assets(version: str, platforms: list[str]) -> set[str]:
    assets: set[str] = set()
    for platform in platforms:
        try:
            suffix, extension = CLI_PLATFORM_ASSETS[platform]
        except KeyError as error:
            raise ValueError(f"unknown CLI platform label {platform!r}") from error
        assets.add(f"jacs-cli-{version}-{suffix}.{extension}")
    return assets


def expected_github_release_assets(tag: str) -> set[str]:
    """Use the attestation verifier's inventory as the single source of truth."""

    return set(_release_spec(tag).expected_assets)


def npm_release_with_provenance(
    package_path: str,
    version: str,
    label: str,
    failures: list[str],
) -> dict:
    metadata = get_json(f"https://registry.npmjs.org/{package_path}/{version}")
    dist = metadata.get("dist", {})
    if not dist.get("integrity"):
        fail(f"{label} release {version} has no registry integrity digest", failures)
    if not dist.get("attestations", {}).get("provenance"):
        fail(f"{label} release {version} has no registry provenance attestation", failures)
    return metadata


def validate_online_asset_evidence(matrix: dict, failures: list[str]) -> None:
    artifacts = matrix["artifacts"]

    cli = artifacts["cli"]
    cli_version = cli["version"]
    if cli_version is not None and cli["status"].startswith("published"):
        tag = urllib.parse.quote(f"cli/v{cli_version}", safe="")
        release = get_json(
            f"https://api.github.com/repos/HumanAssisted/JACS/releases/tags/{tag}"
        )
        release_assets = {asset["name"]: asset for asset in release["assets"]}
        try:
            # Validate documentation labels and the complete public inventory.
            expected_cli_assets(cli_version, cli["platforms"])
            expected = expected_github_release_assets(f"cli/v{cli_version}")
        except ValueError as error:
            fail(str(error), failures)
            expected = set()
        for asset_name in sorted(expected - release_assets.keys()):
            fail(f"CLI GitHub release asset missing: {asset_name}", failures)
        for asset_name in sorted(release_assets.keys() - expected):
            fail(f"CLI GitHub release asset unexpected: {asset_name}", failures)
        for asset_name in sorted(expected & release_assets.keys()):
            digest = release_assets[asset_name].get("digest")
            if not isinstance(digest, str) or re.fullmatch(
                r"sha256:[0-9a-f]{64}", digest
            ) is None:
                fail(f"CLI asset {asset_name} has no GitHub SHA-256 digest", failures)

    wasm = artifacts["wasm"]
    wasm_version = wasm["version"]
    if wasm_version is not None and wasm["status"].startswith("published"):
        npm_release_with_provenance(
            "@jacs%2Fwasm", wasm_version, "WASM npm", failures
        )


def fail(message: str, failures: list[str]) -> None:
    failures.append(message)
    print(f"ERROR: {message}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--online", action="store_true", help="query public registries")
    parser.add_argument(
        "--require-parity",
        action="store_true",
        help="require every primary registry package to equal source_version",
    )
    parser.add_argument(
        "--write-docs",
        action="store_true",
        help="refresh the generated deployment matrix from shipped-artifacts.json",
    )
    args = parser.parse_args()
    if args.require_parity:
        args.online = True

    matrix = json.loads(MATRIX_PATH.read_text())
    declared = matrix["source_version"]
    failures: list[str] = []

    try:
        rendered_docs = render_documentation_matrix(matrix)
        current_docs = DEPLOYMENT_DOC_PATH.read_text()
        expected_docs = replace_documentation_matrix(current_docs, rendered_docs)
        if args.write_docs:
            DEPLOYMENT_DOC_PATH.write_text(expected_docs)
            current_docs = expected_docs
        if current_docs != expected_docs:
            fail(
                "deployment artifact table is stale; run scripts/check-release-matrix.py --write-docs",
                failures,
            )
    except (OSError, ValueError, KeyError, TypeError) as error:
        fail(f"deployment artifact table validation failed: {error}", failures)

    versions = source_versions()
    versions["jacs-mcp"] = load_toml(ROOT / "jacs-mcp" / "Cargo.toml")["package"]["version"]
    for surface, version in versions.items():
        if version != declared:
            fail(f"{surface} source version {version} != matrix source {declared}", failures)

    if args.online:
        try:
            live = registry_versions()
        except (OSError, RuntimeError, ValueError, KeyError) as error:
            fail(f"registry query failed: {error}", failures)
            live = {}

        for surface, live_version in live.items():
            observed = matrix["artifacts"][surface]["version"]
            if live_version != observed:
                fail(
                    f"{surface} registry version {live_version!r} != observed matrix {observed!r}; "
                    "refresh release/shipped-artifacts.json with evidence",
                    failures,
                )
            parity_version = live_version
            if args.require_parity and parity_version != declared:
                fail(
                    f"{surface} registry version {live_version!r} != release {declared!r}",
                    failures,
                )

        try:
            validate_online_asset_evidence(matrix, failures)
        except (OSError, RuntimeError, ValueError, KeyError) as error:
            fail(f"platform asset evidence query failed: {error}", failures)

    if failures:
        return 1
    mode = "registry parity" if args.require_parity else "release matrix"
    print(f"OK: {mode} validated for source {declared}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
