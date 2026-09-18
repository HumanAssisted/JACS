#!/usr/bin/env python3
"""Fail closed when first-party package license claims contradict the project."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path
from typing import Any, Sequence


EXPECTED_SPDX = "Apache-2.0"
CANONICAL_LICENSE = "LICENSE-APACHE"
EXACT_LICENSE_COPIES = (
    "jacs-core/LICENSE-APACHE",
    "jacs-wasm/LICENSE-APACHE",
    "jacs-mobile/LICENSE-APACHE",
    "jacs-mcp/LICENSE-APACHE",
    "jacs-cli/LICENSE-APACHE",
    "archive/native/LICENSE-APACHE",
    "archive/native/jacs/LICENSE",
    "archive/native/jacsnpm/LICENSE",
    "archive/native/jacspy/LICENSE-APACHE",
)
NODE_MANIFESTS = (
    "archive/native/jacsnpm/package.json",
    "jacs-wasm/package.template.json",
)



def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _read_bytes(path: Path, root: Path, errors: list[str]) -> bytes | None:
    label = _relative(path, root)
    try:
        return path.read_bytes()
    except FileNotFoundError:
        errors.append(f"{label} is missing")
    except OSError as error:
        errors.append(f"{label} cannot be read: {error}")
    return None


def _read_text(path: Path, root: Path, errors: list[str]) -> str | None:
    data = _read_bytes(path, root, errors)
    if data is None:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"{_relative(path, root)} is not valid UTF-8")
        return None


def _load_toml(path: Path, root: Path, errors: list[str]) -> dict[str, Any] | None:
    data = _read_bytes(path, root, errors)
    if data is None:
        return None
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        errors.append(f"{_relative(path, root)} is invalid TOML: {error}")
        return None
    if not isinstance(document, dict):
        errors.append(f"{_relative(path, root)} must contain a TOML table")
        return None
    return document


def _load_json(path: Path, root: Path, errors: list[str]) -> dict[str, Any] | None:
    text = _read_text(path, root, errors)
    if text is None:
        return None
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        errors.append(f"{_relative(path, root)} is invalid JSON: {error}")
        return None
    if not isinstance(document, dict):
        errors.append(f"{_relative(path, root)} must contain a JSON object")
        return None
    return document


def _check_exact_copy(
    path: Path,
    canonical: bytes,
    root: Path,
    errors: list[str],
) -> None:
    contents = _read_bytes(path, root, errors)
    if contents is None or contents == canonical:
        return
    expected_digest = hashlib.sha256(canonical).hexdigest()
    actual_digest = hashlib.sha256(contents).hexdigest()
    errors.append(
        f"{_relative(path, root)} does not match canonical {CANONICAL_LICENSE} "
        f"(sha256 {actual_digest} != {expected_digest})"
    )


def _cargo_license_claim(
    manifest: Path,
    document: dict[str, Any],
    workspace_license: str | None,
    root: Path,
    errors: list[str],
) -> None:
    label = _relative(manifest, root)
    package = document.get("package")
    if not isinstance(package, dict):
        errors.append(f"{label} is missing a [package] table")
        return

    claim = package.get("license")
    if claim == EXPECTED_SPDX:
        return
    if isinstance(claim, dict) and claim.get("workspace") is True:
        if workspace_license != EXPECTED_SPDX:
            errors.append(
                f"{label} inherits workspace license {workspace_license!r}; "
                f"expected '{EXPECTED_SPDX}'"
            )
        return
    if claim is None:
        errors.append(
            f"{label} does not declare a package license; expected '{EXPECTED_SPDX}'"
        )
        return
    errors.append(
        f"{label} declares package license {claim!r}; expected '{EXPECTED_SPDX}'"
    )


def _check_cargo_manifests(
    root: Path,
    workspace: dict[str, Any],
    errors: list[str],
) -> None:
    """Validate nested workspaces under their own license inheritance scope.

    Excluded paths may be independent virtual workspaces, not packages. Walk
    their declared members/exclusions without treating their [workspace] table
    as a package or inheriting the active workspace's license into the archive.
    """
    visited: set[Path] = set()

    def visit(manifest: Path, document: dict[str, Any], inherited: str | None) -> None:
        if manifest in visited:
            return
        visited.add(manifest)
        label = _relative(manifest, root)
        table = document.get("workspace")
        package = document.get("package")
        license_claim = inherited
        if isinstance(table, dict):
            metadata = table.get("package", {})
            license_claim = metadata.get("license") if isinstance(metadata, dict) else None
            # A standalone [package] + empty [workspace] can declare its license
            # directly. Virtual workspaces must define their own Apache scope.
            if (license_claim is not None or not isinstance(package, dict)) and license_claim != EXPECTED_SPDX:
                errors.append(
                    f"{label} declares workspace package license {license_claim!r}; "
                    f"expected '{EXPECTED_SPDX}'"
                )
        if isinstance(package, dict):
            _cargo_license_claim(manifest, document, license_claim, root, errors)
        elif not isinstance(table, dict):
            errors.append(f"{label} is missing a [package] or [workspace] table")
        if not isinstance(table, dict):
            return
        for field in ("members", "exclude"):
            entries = table.get(field, [])
            if not isinstance(entries, list) or not all(isinstance(entry, str) for entry in entries):
                errors.append(f"{label} workspace.{field} must be a list of paths")
                continue
            for entry in entries:
                child = manifest.parent / entry / "Cargo.toml"
                child_document = _load_toml(child, root, errors)
                if child_document is not None:
                    visit(child, child_document, license_claim)

    if not isinstance(workspace.get("workspace"), dict):
        errors.append("Cargo.toml is missing a [workspace] table")
    visit(root / "Cargo.toml", workspace, None)


def _check_node_manifest(path: Path, root: Path, errors: list[str]) -> None:
    document = _load_json(path, root, errors)
    if document is None:
        return
    label = _relative(path, root)
    claim = document.get("license")
    if claim != EXPECTED_SPDX:
        errors.append(f"{label} declares license {claim!r}; expected '{EXPECTED_SPDX}'")
    packaged_files = document.get("files")
    if not isinstance(packaged_files, list) or "LICENSE" not in packaged_files:
        errors.append(f"{label} must include LICENSE in its published files")


def _check_python_manifest(root: Path, errors: list[str]) -> None:
    path = root / "archive/native/jacspy/pyproject.toml"
    document = _load_toml(path, root, errors)
    if document is None:
        return
    project = document.get("project")
    if not isinstance(project, dict):
        errors.append("archive/native/jacspy/pyproject.toml is missing a [project] table")
        return
    claim = project.get("license")
    expected = {"file": "LICENSE-APACHE"}
    if claim != expected:
        errors.append(
            "archive/native/jacspy/pyproject.toml must declare project.license.file = 'LICENSE-APACHE'"
        )


def _check_wasm_finalizer(root: Path, errors: list[str]) -> None:
    path = root / "jacs-wasm/scripts/finalize-pkg.sh"
    text = _read_text(path, root, errors)
    if text is None:
        return
    if 'LICENSE_SOURCE="${JACS_WASM_DIR}/../LICENSE-APACHE"' not in text:
        errors.append("jacs-wasm/scripts/finalize-pkg.sh must source ../LICENSE-APACHE")
    if 'cp "${LICENSE_SOURCE}" "${PKG_DIR}/LICENSE"' not in text:
        errors.append(
            "jacs-wasm/scripts/finalize-pkg.sh must copy the canonical license "
            "to the package"
        )


def check_project_license(root: Path) -> list[str]:
    """Return deterministic contract errors without disclosing license contents."""

    root = Path(root).resolve()
    errors: list[str] = []
    canonical_path = root / CANONICAL_LICENSE
    canonical = _read_bytes(canonical_path, root, errors)

    if canonical is not None:
        if not canonical.strip():
            errors.append(f"{CANONICAL_LICENSE} is empty")
        elif b"Apache License" not in canonical or b"Version 2.0" not in canonical:
            errors.append(
                f"{CANONICAL_LICENSE} does not identify the Apache License, Version 2.0"
            )
        for relative in EXACT_LICENSE_COPIES:
            _check_exact_copy(root / relative, canonical, root, errors)

    summary = _read_text(root / "LICENSE", root, errors)
    if summary is not None and (
        EXPECTED_SPDX not in summary or CANONICAL_LICENSE not in summary
    ):
        errors.append(
            f"LICENSE must identify {EXPECTED_SPDX} and point to {CANONICAL_LICENSE}"
        )

    workspace = _load_toml(root / "Cargo.toml", root, errors)
    if workspace is not None:
        _check_cargo_manifests(root, workspace, errors)

    for relative in NODE_MANIFESTS:
        _check_node_manifest(root / relative, root, errors)
    _check_python_manifest(root, errors)
    _check_wasm_finalizer(root, errors)

    return sorted(set(errors))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check first-party project and package license consistency."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the parent of scripts/)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    errors = check_project_license(args.root)
    if errors:
        print("ERROR: project license consistency check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("Project and package license claims are consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
