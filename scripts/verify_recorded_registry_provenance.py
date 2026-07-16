#!/usr/bin/env python3
"""Cryptographically reverify recorded PyPI and npm releases."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

try:
    from release_tag import validate_semver
    import verify_pypi_release_attestations as pypi_verifier
except ModuleNotFoundError:  # Imported through the scripts namespace in tests.
    from scripts.release_tag import validate_semver
    from scripts import verify_pypi_release_attestations as pypi_verifier


MATRIX_LIMIT_BYTES = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 300
DIAGNOSTIC_LIMIT_CHARS = 4096
NPM_PACKAGES = {
    "@hai.ai/jacs": Path("@hai.ai") / "jacs",
    "@jacs/wasm": Path("@jacs") / "wasm",
}


def _run_command(
    command: list[str], cwd: Path, timeout_seconds: int
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "npm_config_audit": "false",
            "npm_config_fund": "false",
            "npm_config_ignore_scripts": "true",
            "npm_config_update_notifier": "false",
        }
    )
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )


def _require_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode == 0:
        return
    diagnostic = (result.stderr or result.stdout or "").strip()
    diagnostic = diagnostic[-DIAGNOSTIC_LIMIT_CHARS:]
    suffix = f": {diagnostic}" if diagnostic else ""
    raise RuntimeError(f"{label} failed with status {result.returncode}{suffix}")


def recorded_registry_releases(matrix: object) -> list[tuple[str, str, str]]:
    if not isinstance(matrix, dict) or not isinstance(matrix.get("artifacts"), dict):
        raise ValueError("shipped-artifact matrix must contain an artifacts object")
    artifacts = matrix["artifacts"]
    releases: list[tuple[str, str, str]] = []
    for surface, package in (
        ("python", "jacs"),
        ("node", "@hai.ai/jacs"),
        ("wasm", "@jacs/wasm"),
    ):
        artifact = artifacts.get(surface)
        if not isinstance(artifact, dict):
            raise ValueError(f"shipped-artifact matrix is missing {surface!r}")
        version = artifact.get("version")
        status = artifact.get("status")
        if version is None or not isinstance(status, str) or not status.startswith(
            "published"
        ):
            continue
        if not isinstance(version, str):
            raise ValueError(f"published {surface} version must be a string")
        validate_semver(version)
        releases.append((surface, package, version))
    return releases


def verify_npm_release(
    package: str,
    version: str,
    *,
    run: Callable[
        [list[str], Path, int], subprocess.CompletedProcess[str]
    ] = _run_command,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
) -> None:
    try:
        package_path = NPM_PACKAGES[package]
    except KeyError as error:
        raise ValueError(f"unsupported npm package: {package!r}") from error
    validate_semver(version)
    if timeout_seconds < 1:
        raise ValueError("npm verification timeout must be positive")

    with tempfile.TemporaryDirectory(prefix="jacs-npm-provenance-") as directory:
        project = Path(directory)
        (project / "package.json").write_text(
            '{"name":"jacs-provenance-verifier","private":true,"version":"1.0.0"}\n',
            encoding="utf-8",
        )
        install = run(
            [
                "npm",
                "install",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--",
                f"{package}@{version}",
            ],
            project,
            timeout_seconds,
        )
        _require_success(install, f"installing {package}@{version}")

        manifest_path = project / "node_modules" / package_path / "package.json"
        try:
            installed = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"installed {package}@{version} has no readable package manifest"
            ) from error
        if installed.get("name") != package or installed.get("version") != version:
            raise RuntimeError(
                f"installed npm package identity mismatch for {package}@{version}"
            )

        audit = run(
            ["npm", "audit", "signatures"],
            project,
            timeout_seconds,
        )
        _require_success(audit, f"npm signature audit for {package}@{version}")


def verify_pypi_release(version: str) -> None:
    metadata = pypi_verifier.fetch_metadata(version)
    pypi_verifier.verify_release(version, metadata)


def _load_matrix(path: Path) -> object:
    with path.open("rb") as matrix_file:
        body = matrix_file.read(MATRIX_LIMIT_BYTES + 1)
    if len(body) > MATRIX_LIMIT_BYTES:
        raise ValueError("shipped-artifact matrix exceeds the size limit")
    return json.loads(body)


def verify_recorded_releases(
    matrix_path: Path,
    *,
    verify_pypi: Callable[[str], None] = verify_pypi_release,
    verify_npm: Callable[[str, str], None] = verify_npm_release,
) -> None:
    releases = recorded_registry_releases(_load_matrix(matrix_path))
    for surface, package, version in releases:
        if surface == "python":
            verify_pypi(version)
        else:
            verify_npm(package, version)
    print(f"Cryptographically reverified {len(releases)} PyPI/npm release(s).")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", type=Path)
    args = parser.parse_args()
    try:
        verify_recorded_releases(args.matrix)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
