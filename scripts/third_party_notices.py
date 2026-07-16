#!/usr/bin/env python3
"""Generate and verify JACS's Cargo dependency notice inventory.

The component inventory is marker-bounded so the existing acknowledgments and
full license appendix remain byte-for-byte untouched. By default metadata comes
from the locked, all-feature workspace graph. Tests and offline policy tooling
may supply an already captured Cargo metadata document with ``--metadata-file``.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import stat
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from third_party_license_policy import (
    license_source_hashes,
    load_reviewed_license_clarifications,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "THIRD-PARTY-NOTICES"
DEFAULT_CLARIFICATIONS = ROOT / "scripts/third_party_license_clarifications.toml"
REQUIRED_PACKAGE_COPIES = (
    Path("jacs/THIRD-PARTY-NOTICES"),
    Path("jacs-core/THIRD-PARTY-NOTICES"),
    Path("jacs-media/THIRD-PARTY-NOTICES"),
    Path("binding-core/THIRD-PARTY-NOTICES"),
    Path("jacs-mcp/THIRD-PARTY-NOTICES"),
    Path("jacs-cli/THIRD-PARTY-NOTICES"),
    Path("jacs-duckdb/THIRD-PARTY-NOTICES"),
    Path("jacs-redb/THIRD-PARTY-NOTICES"),
    Path("jacs-surrealdb/THIRD-PARTY-NOTICES"),
    Path("jacs-postgresql/THIRD-PARTY-NOTICES"),
    Path("jacsnpm/THIRD-PARTY-NOTICES"),
    Path("jacspy/THIRD-PARTY-NOTICES"),
    Path("jacspy/python/jacs/THIRD-PARTY-NOTICES"),
)
START_MARKER = "===== BEGIN GENERATED CARGO DEPENDENCY INVENTORY ====="
END_MARKER = "===== END GENERATED CARGO DEPENDENCY INVENTORY ====="
METADATA_COMMAND = (
    "cargo",
    "metadata",
    "--format-version",
    "1",
    "--locked",
    "--all-features",
)
SEPARATE_MANIFESTS = (Path("jacs-surrealdb/Cargo.toml"),)
METADATA_TIMEOUT_SECONDS = 300
MAX_LICENSE_FILE_BYTES = 1024 * 1024


class NoticeError(Exception):
    """A deterministic, user-actionable notice generation failure."""


@dataclass(frozen=True)
class Component:
    package_id: str
    name: str
    version: str
    license_expression: str | None
    project_url: str | None
    license_file_name: str | None = None
    license_file_sha256: str | None = None
    license_file_cargo_deny_hash: int | None = None
    license_file_text: str | None = None


def _required_string(value: Any, *, field: str, package_id: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NoticeError(f"package {package_id!r} has invalid {field} metadata")
    normalized = value.strip()
    if any(character in normalized for character in ("\n", "\r", "\0")):
        raise NoticeError(f"package {package_id!r} has unsafe {field} metadata")
    return normalized


def _optional_string(value: Any, *, field: str, package_id: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise NoticeError(f"package {package_id!r} has invalid {field} metadata")
    if not value.strip():
        return None
    return _required_string(value, field=field, package_id=package_id)


def _load_package_license_file(
    raw_package: dict[str, Any], *, package_id: str
) -> tuple[str, str, int, str]:
    license_file_name = _required_string(
        raw_package.get("license_file"), field="license_file", package_id=package_id
    )
    relative_path = Path(license_file_name)
    if relative_path.is_absolute():
        raise NoticeError(
            f"package {package_id!r} license_file must be relative to its package root"
        )
    manifest_path = Path(
        _required_string(
            raw_package.get("manifest_path"),
            field="manifest_path",
            package_id=package_id,
        )
    )
    try:
        package_root = manifest_path.parent.resolve(strict=True)
        license_path = (package_root / relative_path).resolve(strict=True)
    except OSError as error:
        raise NoticeError(
            f"could not resolve license_file for package {package_id!r}: {error}"
        ) from error
    try:
        license_path.relative_to(package_root)
    except ValueError as error:
        raise NoticeError(
            f"package {package_id!r} license_file escapes package root"
        ) from error
    if license_path.is_symlink() or not license_path.is_file():
        raise NoticeError(f"package {package_id!r} license_file is not a regular file")
    try:
        size = license_path.stat().st_size
        if size > MAX_LICENSE_FILE_BYTES:
            raise NoticeError(
                f"package {package_id!r} license_file exceeds "
                f"{MAX_LICENSE_FILE_BYTES} bytes"
            )
        raw = license_path.read_bytes()
    except OSError as error:
        raise NoticeError(
            f"could not read license_file for package {package_id!r}: {error}"
        ) from error
    if len(raw) > MAX_LICENSE_FILE_BYTES:
        raise NoticeError(
            f"package {package_id!r} license_file exceeds {MAX_LICENSE_FILE_BYTES} bytes"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise NoticeError(
            f"package {package_id!r} license_file is not valid UTF-8: {error}"
        ) from error
    # Keep the generated repository artifact LF-only and free of insignificant
    # line-end padding while hashing the exact upstream bytes above. The source
    # digest remains the provenance check; normalized display text keeps the
    # generated notice compatible with repository whitespace policy.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    if "\0" in text or START_MARKER in text or END_MARKER in text:
        raise NoticeError(
            f"package {package_id!r} license_file contains unsafe notice content"
        )
    cargo_deny_hash, sha256 = license_source_hashes(raw)
    return license_file_name, sha256, cargo_deny_hash, text


def _metadata_components(
    metadata: Any, reviewed: dict[str, dict[str, object]] | None = None
) -> list[Component]:
    if not isinstance(metadata, dict):
        raise NoticeError("Cargo metadata root must be a JSON object")

    packages = metadata.get("packages")
    workspace_members = metadata.get("workspace_members")
    resolve = metadata.get("resolve")
    if not isinstance(packages, list):
        raise NoticeError("Cargo metadata packages must be a JSON array")
    if not isinstance(workspace_members, list) or not all(
        isinstance(package_id, str) for package_id in workspace_members
    ):
        raise NoticeError("Cargo metadata workspace_members must be a string array")
    if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        raise NoticeError("Cargo metadata must contain a resolved dependency graph")

    packages_by_id: dict[str, dict[str, Any]] = {}
    for raw_package in packages:
        if not isinstance(raw_package, dict):
            raise NoticeError("Cargo metadata package entries must be JSON objects")
        package_id = _required_string(
            raw_package.get("id"), field="id", package_id="<unknown>"
        )
        if package_id in packages_by_id:
            raise NoticeError(
                f"Cargo metadata contains duplicate package id {package_id!r}"
            )
        packages_by_id[package_id] = raw_package

    resolved_ids: set[str] = set()
    for node in resolve["nodes"]:
        if not isinstance(node, dict):
            raise NoticeError("Cargo metadata resolve nodes must be JSON objects")
        package_id = _required_string(
            node.get("id"), field="resolve node id", package_id="<unknown>"
        )
        if package_id not in packages_by_id:
            raise NoticeError(
                f"Cargo metadata resolve node {package_id!r} has no package entry"
            )
        resolved_ids.add(package_id)

    first_party_ids = set(workspace_members)
    missing_workspace_entries = sorted(first_party_ids - packages_by_id.keys())
    if missing_workspace_entries:
        raise NoticeError(
            "Cargo metadata workspace member has no package entry: "
            + ", ".join(missing_workspace_entries)
        )

    reviewed = reviewed or {}
    components: list[Component] = []
    missing_licenses: list[str] = []
    for package_id in sorted(resolved_ids - first_party_ids):
        raw_package = packages_by_id[package_id]
        name = _required_string(
            raw_package.get("name"), field="name", package_id=package_id
        )
        version = _required_string(
            raw_package.get("version"), field="version", package_id=package_id
        )
        license_value = raw_package.get("license")
        license_file_value = raw_package.get("license_file")
        license_expression: str | None = None
        license_file_name: str | None = None
        license_file_sha256: str | None = None
        license_file_cargo_deny_hash: int | None = None
        license_file_text: str | None = None
        reviewed_entry = reviewed.get(name)
        if isinstance(license_value, str) and license_value.strip():
            license_expression = _required_string(
                license_value, field="license", package_id=package_id
            )
        elif not (isinstance(license_file_value, str) and license_file_value.strip()):
            missing_licenses.append(f"{name} {version} ({package_id})")
            continue

        if reviewed_entry is not None:
            reviewed_sources = reviewed_entry.get("sources")
            if not isinstance(reviewed_sources, set) or len(reviewed_sources) != 1:
                raise NoticeError(
                    f"reviewed clarification for {name!r} must have exactly one source"
                )
            expected_path, expected_cargo_deny_hash, expected_sha256 = next(
                iter(reviewed_sources)
            )
            if (
                isinstance(license_file_value, str)
                and license_file_value.strip()
                and license_file_value.strip() != expected_path
            ):
                raise NoticeError(
                    f"package {package_id!r} metadata license_file does not match "
                    "the reviewed clarification source"
                )
            reviewed_package = dict(raw_package)
            reviewed_package["license_file"] = expected_path
            (
                license_file_name,
                license_file_sha256,
                license_file_cargo_deny_hash,
                license_file_text,
            ) = _load_package_license_file(reviewed_package, package_id=package_id)
            if (
                license_file_cargo_deny_hash != expected_cargo_deny_hash
                or license_file_sha256 != expected_sha256
            ):
                raise NoticeError(
                    f"package {package_id!r} license source drifted from the reviewed "
                    "cargo-deny/SHA-256 contract"
                )
        elif isinstance(license_file_value, str) and license_file_value.strip():
            (
                license_file_name,
                license_file_sha256,
                license_file_cargo_deny_hash,
                license_file_text,
            ) = _load_package_license_file(raw_package, package_id=package_id)
        repository = _optional_string(
            raw_package.get("repository"), field="repository", package_id=package_id
        )
        homepage = _optional_string(
            raw_package.get("homepage"), field="homepage", package_id=package_id
        )
        source = _optional_string(
            raw_package.get("source"), field="source", package_id=package_id
        )
        components.append(
            Component(
                package_id=package_id,
                name=name,
                version=version,
                license_expression=license_expression,
                project_url=repository or homepage or source,
                license_file_name=license_file_name,
                license_file_sha256=license_file_sha256,
                license_file_cargo_deny_hash=license_file_cargo_deny_hash,
                license_file_text=license_file_text,
            )
        )

    if missing_licenses:
        raise NoticeError(
            "third-party package is missing Cargo license metadata:\n  - "
            + "\n  - ".join(sorted(missing_licenses, key=str.casefold))
        )

    return sorted(
        components,
        key=lambda component: (
            component.name.casefold(),
            component.name,
            component.version,
            component.license_expression or "",
            component.license_file_sha256 or "",
            component.license_file_cargo_deny_hash or 0,
            component.project_url or "",
            component.package_id,
        ),
    )


def _merge_metadata_documents(documents: Sequence[Any]) -> dict[str, Any]:
    """Merge resolved graphs while excluding every graph's first-party IDs."""

    if not documents:
        raise NoticeError("at least one Cargo metadata document is required")
    packages_by_id: dict[str, dict[str, Any]] = {}
    workspace_members: set[str] = set()
    resolved_ids: set[str] = set()
    identity_fields = ("name", "version", "license", "license_file", "source")

    for index, document in enumerate(documents):
        if not isinstance(document, dict):
            raise NoticeError(f"Cargo metadata document {index} must be a JSON object")
        packages = document.get("packages")
        members = document.get("workspace_members")
        resolve = document.get("resolve")
        if not isinstance(packages, list):
            raise NoticeError(
                f"Cargo metadata document {index} packages must be an array"
            )
        if not isinstance(members, list) or not all(
            isinstance(member, str) for member in members
        ):
            raise NoticeError(
                f"Cargo metadata document {index} workspace_members must be a string array"
            )
        if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
            raise NoticeError(
                f"Cargo metadata document {index} must contain resolve.nodes"
            )

        workspace_members.update(members)
        for raw_package in packages:
            if not isinstance(raw_package, dict):
                raise NoticeError("Cargo metadata package entries must be JSON objects")
            package_id = _required_string(
                raw_package.get("id"), field="id", package_id="<unknown>"
            )
            existing = packages_by_id.get(package_id)
            if existing is not None and any(
                existing.get(field) != raw_package.get(field)
                for field in identity_fields
            ):
                raise NoticeError(
                    f"Cargo metadata graphs disagree about package {package_id!r}"
                )
            packages_by_id.setdefault(package_id, raw_package)
        for node in resolve["nodes"]:
            if not isinstance(node, dict):
                raise NoticeError("Cargo metadata resolve nodes must be JSON objects")
            resolved_ids.add(
                _required_string(
                    node.get("id"), field="resolve node id", package_id="<unknown>"
                )
            )

    return {
        "packages": [packages_by_id[key] for key in sorted(packages_by_id)],
        "workspace_members": sorted(workspace_members),
        "resolve": {"nodes": [{"id": key} for key in sorted(resolved_ids)]},
    }


def render_inventory(components: Sequence[Component]) -> str:
    grouped: dict[str, list[Component]] = defaultdict(list)
    file_grouped: dict[tuple[str, int, str, str], list[Component]] = defaultdict(list)
    for component in components:
        if component.license_expression is not None:
            grouped[component.license_expression].append(component)
        if component.license_file_sha256 is not None:
            assert component.license_file_sha256 is not None
            assert component.license_file_cargo_deny_hash is not None
            assert component.license_file_name is not None
            assert component.license_file_text is not None
            file_grouped[
                (
                    component.license_file_sha256,
                    component.license_file_cargo_deny_hash,
                    component.license_file_name,
                    component.license_file_text,
                )
            ].append(component)

    lines = [
        "Generated by scripts/third_party_notices.py.",
        "Source graphs: locked all-feature workspace plus excluded publishable crates.",
        "First-party workspace packages are excluded by exact Cargo package ID.",
        "License expressions are reproduced exactly from Cargo package metadata.",
        "",
        f"Third-party packages: {len(components)}",
        f"License expressions: {len(grouped)}",
        f"Distinct Cargo license files: {len(file_grouped)}",
    ]

    for license_expression in sorted(
        grouped, key=lambda value: (value.casefold(), value)
    ):
        license_components = grouped[license_expression]
        lines.extend(
            [
                "",
                "-------------------------------------------------------------------------------",
                f"License expression: {license_expression}",
                f"Used by {len(license_components)} package(s):",
                "",
            ]
        )
        for component in license_components:
            description = f"  - {component.name} {component.version}"
            if component.project_url:
                description += f" ({component.project_url})"
            lines.append(description)

    for (
        digest,
        cargo_deny_hash,
        license_file_name,
        license_text,
    ), license_components in sorted(file_grouped.items()):
        lines.extend(
            [
                "",
                "-------------------------------------------------------------------------------",
                f"Cargo license file SHA-256: {digest}",
                f"Cargo-deny normalized XXH32: 0x{cargo_deny_hash:08x}",
                f"License source path: {license_file_name}",
                f"Used by {len(license_components)} package(s):",
                "",
            ]
        )
        for component in license_components:
            description = f"  - {component.name} {component.version}"
            if component.project_url:
                description += f" ({component.project_url})"
            lines.append(description)
        lines.extend(
            [
                "",
                "License text (the SHA-256 above identifies the source bytes):",
                "",
                license_text,
            ]
        )

    return "\n".join(lines) + "\n"


def _replace_inventory(document: str, inventory: str) -> str:
    if document.count(START_MARKER) != 1 or document.count(END_MARKER) != 1:
        raise NoticeError(
            "THIRD-PARTY-NOTICES must contain exactly one pair of generated inventory markers"
        )
    start = document.index(START_MARKER)
    end = document.index(END_MARKER)
    if end <= start:
        raise NoticeError(
            "THIRD-PARTY-NOTICES generated inventory markers are out of order"
        )
    if start > 0 and document[start - 1] != "\n":
        raise NoticeError("THIRD-PARTY-NOTICES start marker must occupy its own line")
    after_start = start + len(START_MARKER)
    if after_start >= len(document) or document[after_start] not in ("\n", "\r"):
        raise NoticeError("THIRD-PARTY-NOTICES start marker must occupy its own line")
    start_content = document.find("\n", after_start)
    if start_content < 0:
        raise NoticeError("THIRD-PARTY-NOTICES start marker has no line ending")
    start_content += 1
    if end == 0 or document[end - 1] != "\n":
        raise NoticeError("THIRD-PARTY-NOTICES end marker must occupy its own line")
    after_end = end + len(END_MARKER)
    if after_end < len(document) and document[after_end] not in ("\n", "\r"):
        raise NoticeError("THIRD-PARTY-NOTICES end marker must occupy its own line")
    return document[:start_content] + inventory + document[end:]


def _read_utf8(path: Path) -> tuple[bytes, str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise NoticeError(f"could not read {path}: {error}") from error
    try:
        return raw, raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise NoticeError(f"{path} is not valid UTF-8: {error}") from error


def _load_metadata_file(path: Path) -> Any:
    _, text = _read_utf8(path)
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise NoticeError(f"invalid Cargo metadata JSON in {path}: {error}") from error


def _run_cargo_metadata(repo_root: Path, manifest: Path | None = None) -> Any:
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    try:
        command = list(METADATA_COMMAND)
        if manifest is not None:
            command.extend(("--manifest-path", str(manifest)))
        completed = subprocess.run(
            command,
            cwd=repo_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=METADATA_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as error:
        raise NoticeError(
            "cargo is required to generate THIRD-PARTY-NOTICES"
        ) from error
    except subprocess.TimeoutExpired as error:
        raise NoticeError(
            f"cargo metadata exceeded {METADATA_TIMEOUT_SECONDS} seconds"
        ) from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
        raise NoticeError(f"cargo metadata failed:\n{detail}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise NoticeError(f"cargo metadata returned invalid JSON: {error}") from error


def _secure_dirfd_operations_supported() -> bool:
    required_dirfd_functions = (os.open, os.stat, os.rename, os.unlink)
    return (
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and all(function in os.supports_dir_fd for function in required_dirfd_functions)
        and os.stat in os.supports_follow_symlinks
    )


_SECURE_DIRFD_OPERATIONS_SUPPORTED = _secure_dirfd_operations_supported()


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


class _SecureNoticeTree:
    """Race-resistant access anchored to a held repository directory descriptor."""

    def __init__(self, output: Path) -> None:
        if not _SECURE_DIRFD_OPERATIONS_SUPPORTED:
            raise NoticeError(
                "secure notice filesystem operations require POSIX dirfd and "
                "O_NOFOLLOW support; refusing an unsafe portable fallback"
            )
        self.output = output
        self.root_path = output.parent
        self.output_name = output.name
        self.root_fd = -1

        try:
            initial_root = os.stat(self.root_path, follow_symlinks=False)
        except OSError as error:
            raise NoticeError(
                f"could not inspect notice output parent {self.root_path}: {error}"
            ) from error
        if stat.S_ISLNK(initial_root.st_mode):
            raise NoticeError(
                f"refusing to use symlinked notice output parent {self.root_path}"
            )
        if not stat.S_ISDIR(initial_root.st_mode):
            raise NoticeError(
                f"notice output parent is not a directory: {self.root_path}"
            )

        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        root_fd = -1
        try:
            root_fd = os.open(self.root_path, directory_flags)
            opened_root = os.fstat(root_fd)
        except OSError as error:
            if root_fd >= 0:
                os.close(root_fd)
            raise NoticeError(
                f"could not securely open notice output parent {self.root_path}: {error}"
            ) from error
        if not _same_file_identity(initial_root, opened_root):
            os.close(root_fd)
            raise NoticeError(
                f"notice output parent changed during secure operation: {self.root_path}"
            )
        self.root_fd = root_fd
        self.root_identity = opened_root

    def __enter__(self) -> _SecureNoticeTree:
        return self

    def __exit__(self, *_args: object) -> None:
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1

    def _assert_root_bound(self) -> None:
        try:
            current_root = os.stat(self.root_path, follow_symlinks=False)
        except OSError as error:
            raise NoticeError(
                f"notice output parent changed during secure operation: "
                f"{self.root_path}: {error}"
            ) from error
        if not stat.S_ISDIR(current_root.st_mode) or not _same_file_identity(
            self.root_identity, current_root
        ):
            raise NoticeError(
                f"notice output parent changed during secure operation: {self.root_path}"
            )

    @staticmethod
    def _validate_relative_path(relative_path: Path) -> None:
        if (
            relative_path.is_absolute()
            or not relative_path.name
            or any(part in ("", ".", "..") for part in relative_path.parts)
        ):
            raise NoticeError(f"unsafe required notice copy path {relative_path}")

    def _open_relative_parent_unchecked(self, relative_path: Path) -> int:
        self._validate_relative_path(relative_path)
        parent_fd = os.dup(self.root_fd)
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            for part in relative_path.parts[:-1]:
                next_fd = os.open(part, directory_flags, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
            return parent_fd
        except BaseException:
            os.close(parent_fd)
            raise

    def _open_relative_parent(self, relative_path: Path) -> int:
        self._assert_root_bound()
        try:
            parent_fd = self._open_relative_parent_unchecked(relative_path)
        except OSError as error:
            parent = relative_path.parent.as_posix()
            raise NoticeError(
                "required notice copy has a missing, non-directory, or symlinked "
                f"parent {parent}: {error}"
            ) from error
        try:
            self._assert_relative_parent_bound(relative_path, parent_fd)
        except BaseException:
            os.close(parent_fd)
            raise
        return parent_fd

    def _assert_relative_parent_bound(
        self, relative_path: Path, expected_parent_fd: int
    ) -> None:
        self._assert_root_bound()
        try:
            current_parent_fd = self._open_relative_parent_unchecked(relative_path)
        except OSError as error:
            raise NoticeError(
                "required notice copy parent changed during secure operation: "
                f"{relative_path.parent.as_posix()}: {error}"
            ) from error
        try:
            expected_parent = os.fstat(expected_parent_fd)
            current_parent = os.fstat(current_parent_fd)
        finally:
            os.close(current_parent_fd)
        if not _same_file_identity(expected_parent, current_parent):
            raise NoticeError(
                "required notice copy parent changed during secure operation: "
                f"{relative_path.parent.as_posix()}"
            )

    @contextlib.contextmanager
    def _relative_parent(self, relative_path: Path):
        parent_fd = self._open_relative_parent(relative_path)
        try:
            yield parent_fd
        finally:
            os.close(parent_fd)

    @staticmethod
    def _read_open_file(descriptor: int, display_path: Path) -> bytes:
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise NoticeError(
                    f"required notice copy is not a regular file: {display_path}"
                )
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
        except OSError as error:
            raise NoticeError(f"could not read {display_path}: {error}") from error

    @staticmethod
    def _entry_mode(parent_fd: int, name: str) -> int | None:
        try:
            return os.stat(name, dir_fd=parent_fd, follow_symlinks=False).st_mode
        except FileNotFoundError:
            return None

    @staticmethod
    def _open_regular_file(parent_fd: int, name: str, display_path: Path) -> int:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            raise
        except OSError as error:
            mode = _SecureNoticeTree._entry_mode(parent_fd, name)
            if mode is not None and not stat.S_ISREG(mode):
                raise NoticeError(
                    f"required notice copy is not a regular file: {display_path}"
                ) from error
            raise NoticeError(
                f"could not securely open {display_path}: {error}"
            ) from error
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            os.close(descriptor)
            raise NoticeError(
                f"required notice copy is not a regular file: {display_path}"
            )
        return descriptor

    @staticmethod
    def _atomic_write_at(
        parent_fd: int, name: str, content: bytes, mode: int, display_path: Path
    ) -> None:
        temporary_name: str | None = None
        descriptor = -1
        create_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            for _attempt in range(32):
                candidate = f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
                try:
                    descriptor = os.open(
                        candidate, create_flags, 0o600, dir_fd=parent_fd
                    )
                    temporary_name = candidate
                    break
                except FileExistsError:
                    continue
            if temporary_name is None:
                raise NoticeError(
                    f"could not allocate an atomic temporary file for {display_path}"
                )

            remaining = memoryview(content)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short write while creating notice file")
                remaining = remaining[written:]
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.rename(
                temporary_name,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            temporary_name = None
        except NoticeError:
            raise
        except OSError as error:
            raise NoticeError(
                f"could not atomically write {display_path}: {error}"
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass

    def read_root_utf8(self) -> tuple[bytes, str]:
        self._assert_root_bound()
        try:
            descriptor = self._open_regular_file(
                self.root_fd, self.output_name, self.output
            )
        except FileNotFoundError as error:
            raise NoticeError(f"could not read {self.output}: {error}") from error
        except NoticeError as error:
            mode = self._entry_mode(self.root_fd, self.output_name)
            if mode is not None and stat.S_ISLNK(mode):
                raise NoticeError(
                    f"refusing to use symlink root notice {self.output}"
                ) from error
            raise
        try:
            raw = self._read_open_file(descriptor, self.output)
        finally:
            os.close(descriptor)
        self._assert_root_bound()
        try:
            return raw, raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise NoticeError(f"{self.output} is not valid UTF-8: {error}") from error

    def write_root(self, content: bytes) -> None:
        self._assert_root_bound()
        mode = self._entry_mode(self.root_fd, self.output_name)
        if mode is not None and not stat.S_ISREG(mode):
            raise NoticeError(f"refusing to replace symlink root notice {self.output}")
        preserved_mode = 0o644 if mode is None else stat.S_IMODE(mode)
        self._atomic_write_at(
            self.root_fd,
            self.output_name,
            content,
            preserved_mode,
            self.output,
        )
        self._assert_root_bound()

    def read_copy(self, relative_path: Path) -> bytes | None:
        display_path = self.root_path / relative_path
        with self._relative_parent(relative_path) as parent_fd:
            try:
                descriptor = self._open_regular_file(
                    parent_fd, relative_path.name, display_path
                )
            except FileNotFoundError:
                self._assert_relative_parent_bound(relative_path, parent_fd)
                return None
            try:
                raw = self._read_open_file(descriptor, display_path)
            finally:
                os.close(descriptor)
            self._assert_relative_parent_bound(relative_path, parent_fd)
            return raw

    def synchronize_copy(self, relative_path: Path, expected: bytes) -> None:
        display_path = self.root_path / relative_path
        with self._relative_parent(relative_path) as parent_fd:
            replace_symlink = False
            try:
                descriptor = self._open_regular_file(
                    parent_fd, relative_path.name, display_path
                )
            except FileNotFoundError:
                current = None
                preserved_mode = 0o644
            except NoticeError:
                mode = self._entry_mode(parent_fd, relative_path.name)
                if mode is None or not stat.S_ISLNK(mode):
                    raise
                current = None
                preserved_mode = 0o644
                replace_symlink = True
            else:
                try:
                    opened = os.fstat(descriptor)
                    preserved_mode = stat.S_IMODE(opened.st_mode)
                    current = self._read_open_file(descriptor, display_path)
                finally:
                    os.close(descriptor)
            self._assert_relative_parent_bound(relative_path, parent_fd)

            if replace_symlink or current != expected:
                self._atomic_write_at(
                    parent_fd,
                    relative_path.name,
                    expected,
                    preserved_mode,
                    display_path,
                )
                self._assert_relative_parent_bound(relative_path, parent_fd)

            final_descriptor = self._open_regular_file(
                parent_fd, relative_path.name, display_path
            )
            os.close(final_descriptor)
            self._assert_relative_parent_bound(relative_path, parent_fd)


def _verify_package_copies(tree: _SecureNoticeTree, expected: bytes) -> None:
    missing: list[str] = []
    mismatches: list[str] = []
    for relative_path in REQUIRED_PACKAGE_COPIES:
        actual = tree.read_copy(relative_path)
        if actual is None:
            missing.append(relative_path.as_posix())
        elif actual != expected:
            mismatches.append(relative_path.as_posix())
    if missing:
        raise NoticeError(
            "required notice copy is missing:\n  - " + "\n  - ".join(missing)
        )
    if mismatches:
        raise NoticeError(
            "package notice copy does not exactly match THIRD-PARTY-NOTICES:\n  - "
            + "\n  - ".join(mismatches)
        )


def _synchronize_package_copies(tree: _SecureNoticeTree, expected: bytes) -> None:
    for relative_path in REQUIRED_PACKAGE_COPIES:
        tree.synchronize_copy(relative_path, expected)


def update_notices(
    metadata: Any,
    *,
    output: Path,
    check: bool,
    reviewed: dict[str, dict[str, object]] | None = None,
) -> int:
    documents = metadata if isinstance(metadata, (list, tuple)) else [metadata]
    components = _metadata_components(
        _merge_metadata_documents(documents), reviewed=reviewed
    )
    inventory = render_inventory(components)
    with _SecureNoticeTree(output) as tree:
        current_bytes, current_text = tree.read_root_utf8()
        expected_text = _replace_inventory(current_text, inventory)
        expected_bytes = expected_text.encode("utf-8")

        if check:
            if current_bytes != expected_bytes:
                raise NoticeError(
                    f"{output} is stale; "
                    "run python3 scripts/third_party_notices.py --write"
                )
            _verify_package_copies(tree, expected_bytes)
            print(
                "THIRD-PARTY-NOTICES is current: "
                f"{len(components)} third-party package(s)"
            )
            return 0

        if current_bytes != expected_bytes:
            tree.write_root(expected_bytes)
            print(f"updated {output}: {len(components)} third-party package(s)")
        else:
            print(f"unchanged {output}: {len(components)} third-party package(s)")
        _synchronize_package_copies(tree, expected_bytes)
        return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--metadata-file",
        action="append",
        type=Path,
        help="read one or more captured Cargo metadata documents instead of invoking Cargo",
    )
    parser.add_argument(
        "--clarifications-file",
        type=Path,
        default=DEFAULT_CLARIFICATIONS,
        help=(
            "reviewed cargo-deny clarification source contract "
            f"(default: {DEFAULT_CLARIFICATIONS})"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"notice file to update or check (default: {DEFAULT_OUTPUT})",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--write",
        action="store_true",
        help="regenerate the root notice inventory and synchronize every package copy",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="fail unless the generated inventory and any present package copies are exact",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        output = args.output.absolute()
        repo_root = output.parent
        try:
            reviewed = load_reviewed_license_clarifications(args.clarifications_file)
        except (OSError, ValueError) as error:
            raise NoticeError(
                f"could not load reviewed license clarifications: {error}"
            ) from error
        if args.metadata_file is not None:
            metadata = [_load_metadata_file(path) for path in args.metadata_file]
        else:
            metadata = [_run_cargo_metadata(repo_root)]
            metadata.extend(
                _run_cargo_metadata(repo_root, repo_root / manifest)
                for manifest in SEPARATE_MANIFESTS
            )
        return update_notices(
            metadata,
            output=output,
            check=args.check,
            reviewed=reviewed,
        )
    except NoticeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
