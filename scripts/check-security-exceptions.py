#!/usr/bin/env python3
"""Fail closed when temporary advisory assumptions or deadlines drift."""

from __future__ import annotations

import datetime as dt
import re
import sys
import tomllib
from pathlib import Path

try:
    from third_party_license_policy import load_reviewed_license_clarifications
except ModuleNotFoundError:  # Imported through the scripts namespace in tests.
    from scripts.third_party_license_policy import (
        load_reviewed_license_clarifications,
    )


ROOT = Path(__file__).resolve().parents[1]
ADVISORY_PATTERN = re.compile(
    r"(?:(?:RUSTSEC|PYSEC)-\d{4}-\d{3,4}|GHSA-[a-z0-9]{4}(?:-[a-z0-9]{4}){2})"
)
WORKFLOW_IGNORE_PATTERN = re.compile(
    r"--ignore(?:-vuln)?\s+((?:(?:RUSTSEC|PYSEC)-\d{4}-\d{3,4}|GHSA-[a-z0-9]{4}(?:-[a-z0-9]{4}){2}))"
)
NOTICE_SHA256_PATTERN = re.compile(
    r"^Cargo license file SHA-256: ([0-9a-f]{64})$", re.MULTILINE
)
NOTICE_CARGO_DENY_HASH_PATTERN = re.compile(
    r"^Cargo-deny normalized XXH32: 0x([0-9a-f]{8})$", re.MULTILINE
)
NOTICE_LICENSE_FILE_PATTERN = re.compile(
    r"^License source path: ([^\r\n]+)$", re.MULTILINE
)
NOTICE_PACKAGE_PATTERN = re.compile(r"^  - ([A-Za-z0-9_-]+) [^\r\n]+$", re.MULTILINE)

BLOCKING_IGNORES = {
    "RUSTSEC-2023-0071",
    "PYSEC-2026-311",
    "GHSA-f4j7-r4q5-qw2c",
}
DOCUMENTED_EXCEPTIONS = BLOCKING_IGNORES | {
    "RUSTSEC-2023-0089",
    "RUSTSEC-2025-0141",
}
CARGO_DENY_IGNORES = {
    advisory for advisory in DOCUMENTED_EXCEPTIONS if advisory.startswith("RUSTSEC-")
}


def dependency_name(dependency: str | dict) -> str:
    if isinstance(dependency, dict):
        return str(dependency["name"])
    # Cargo.lock disambiguates duplicate versions as `name version`; package
    # names themselves never contain whitespace.
    return dependency.split()[0]


def lock_parents(path: Path, dependency: str) -> set[str]:
    with path.open("rb") as handle:
        lock = tomllib.load(handle)
    return {
        package["name"]
        for package in lock.get("package", [])
        if any(
            dependency_name(candidate) == dependency
            for candidate in package.get("dependencies", [])
        )
    }


def documented_deadlines(markdown: str) -> dict[str, dt.date]:
    deadlines: dict[str, dt.date] = {}
    for line in markdown.splitlines():
        advisories = ADVISORY_PATTERN.findall(line)
        if not advisories:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells:
            continue
        try:
            deadline = dt.date.fromisoformat(cells[-1])
        except ValueError:
            continue
        for advisory in advisories:
            deadlines[advisory] = deadline
    return deadlines


def require_unexpired(
    deadlines: dict[str, dt.date],
    required: set[str],
    *,
    today: dt.date | None = None,
) -> None:
    today = today or dt.date.today()
    missing = required - deadlines.keys()
    if missing:
        raise ValueError(
            "security exceptions lack documented review deadlines: "
            + ", ".join(sorted(missing))
        )
    expired = {
        advisory: deadlines[advisory]
        for advisory in required
        if deadlines[advisory] < today
    }
    if expired:
        details = ", ".join(
            f"{advisory} ({deadline.isoformat()})"
            for advisory, deadline in sorted(expired.items())
        )
        raise ValueError(f"security exception review deadline expired: {details}")


def require_exact_parents(path: Path, dependency: str, expected: set[str]) -> None:
    actual = lock_parents(path, dependency)
    if actual != expected:
        raise ValueError(
            f"{path.relative_to(ROOT)} reachability for {dependency!r} changed: "
            f"expected parents {sorted(expected)}, got {sorted(actual)}"
        )


def require_all_features_cargo_deny(text: str, source: str) -> None:
    """Reject cargo-deny workflow commands that omit optional feature graphs."""

    for line_number, line in enumerate(text.splitlines(), start=1):
        command = line.strip()
        if command.startswith("#") or "cargo deny" not in command:
            continue
        if " check " in f" {command} " and "--all-features" not in command:
            raise ValueError(
                f"{source}:{line_number} cargo-deny must audit all features"
            )


def notice_license_sources(
    notice_text: str,
) -> dict[str, set[tuple[str, int, str]]]:
    """Map file-licensed packages to the exact path/hash rendered in notices."""

    sources: dict[str, set[tuple[str, int, str]]] = {}
    separator = "-------------------------------------------------------------------------------"
    for block in notice_text.split(separator):
        if "Cargo license file SHA-256:" not in block:
            continue
        sha256_match = NOTICE_SHA256_PATTERN.search(block)
        if sha256_match is None:
            raise ValueError("generated notice has an invalid Cargo license SHA-256")
        hash_match = NOTICE_CARGO_DENY_HASH_PATTERN.search(block)
        path_match = NOTICE_LICENSE_FILE_PATTERN.search(block)
        if hash_match is None or path_match is None:
            raise ValueError(
                "generated notice license source lacks cargo-deny path/hash coverage"
            )
        package_section = block.split("License text (", maxsplit=1)[0]
        package_names = NOTICE_PACKAGE_PATTERN.findall(package_section)
        if not package_names:
            raise ValueError("generated notice license source has no package")
        source = (
            path_match.group(1),
            int(hash_match.group(1), 16),
            sha256_match.group(1),
        )
        for package_name in package_names:
            sources.setdefault(package_name, set()).add(source)
    return sources


def require_source_bound_license_clarifications(
    clarifications: list[dict],
    notice_text: str,
    reviewed: dict[str, dict[str, object]],
) -> None:
    """Bind cargo-deny names/expressions/sources to reviewed strong digests."""

    notice_sources = notice_license_sources(notice_text)
    clarifications_by_name: dict[str, dict] = {}
    for clarification in clarifications:
        name = clarification.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("cargo-deny clarification has an invalid name")
        if name in clarifications_by_name:
            raise ValueError(f"cargo-deny clarification {name!r} is duplicated")
        clarifications_by_name[name] = clarification

    if set(clarifications_by_name) != set(reviewed):
        raise ValueError(
            "cargo-deny clarification name set differs from reviewed contract: "
            f"configured {sorted(clarifications_by_name)}, reviewed {sorted(reviewed)}"
        )

    for name, clarification in clarifications_by_name.items():
        reviewed_entry = reviewed[name]
        reviewed_expression = reviewed_entry.get("expression")
        if clarification.get("expression") != reviewed_expression:
            raise ValueError(
                f"cargo-deny clarification {name!r} differs from reviewed expression "
                f"{reviewed_expression!r}"
            )
        license_files = clarification.get("license-files")
        if not isinstance(license_files, list) or not license_files:
            raise ValueError(
                f"cargo-deny clarification {name!r} must have non-empty license-files"
            )
        configured_sources: set[tuple[str, int]] = set()
        for license_file in license_files:
            if not isinstance(license_file, dict) or set(license_file) != {
                "path",
                "hash",
            }:
                raise ValueError(
                    f"cargo-deny clarification {name!r} license-files must contain "
                    "only path and hash"
                )
            path = license_file["path"]
            digest = license_file["hash"]
            if not isinstance(path, str) or not path:
                raise ValueError(
                    f"cargo-deny clarification {name!r} has an invalid license path"
                )
            if (
                isinstance(digest, bool)
                or not isinstance(digest, int)
                or not 0 <= digest <= 0xFFFFFFFF
            ):
                raise ValueError(
                    f"cargo-deny clarification {name!r} has an invalid license hash"
                )
            source = (path, digest)
            if source in configured_sources:
                raise ValueError(
                    f"cargo-deny clarification {name!r} repeats a license source"
                )
            configured_sources.add(source)

        reviewed_sources = reviewed_entry.get("sources")
        if not isinstance(reviewed_sources, set) or not reviewed_sources:
            raise ValueError(f"reviewed clarification {name!r} has no license sources")
        reviewed_cargo_sources = {
            (path, digest) for path, digest, _sha256 in reviewed_sources
        }
        if configured_sources != reviewed_cargo_sources:
            raise ValueError(
                f"cargo-deny clarification {name!r} notice source mismatch: "
                f"expected {sorted(reviewed_cargo_sources)}, "
                f"got {sorted(configured_sources)}"
            )
        if notice_sources.get(name) != reviewed_sources:
            raise ValueError(
                f"cargo-deny clarification {name!r} notice source mismatch: "
                f"expected {sorted(reviewed_sources)}, "
                f"got {sorted(notice_sources.get(name, set()))}"
            )


def require_object_store_s3_isolation(manifest: dict) -> None:
    """Require cloud XML parsing to stay behind JACS's explicit `s3` feature."""

    dependency_tables = []
    root_dependency = manifest.get("dependencies", {}).get("object_store")
    if root_dependency is not None:
        dependency_tables.append(root_dependency)
    for target in manifest.get("target", {}).values():
        target_dependency = target.get("dependencies", {}).get("object_store")
        if target_dependency is not None:
            dependency_tables.append(target_dependency)

    if len(dependency_tables) != 1 or not isinstance(dependency_tables[0], dict):
        raise ValueError("jacs object_store dependency must use an explicit table")
    dependency = dependency_tables[0]
    if dependency.get("default-features") is not False:
        raise ValueError("jacs object_store must disable default features")

    base_features = dependency.get("features", [])
    if base_features != ["fs"]:
        raise ValueError(
            "jacs object_store base features must be exactly ['fs']; "
            f"got {base_features!r}"
        )

    features = manifest.get("features", {})
    default_features = features.get("default", [])
    if "s3" in default_features:
        raise ValueError("s3 must not appear in the default feature set")
    if features.get("s3") != ["object_store/aws"]:
        raise ValueError("the s3 feature must enable exactly ['object_store/aws']")
    if features.get("s3-tests") != ["s3"]:
        raise ValueError("s3-tests must transitively enable the s3 feature")


def main() -> int:
    try:
        audit_text = (ROOT / "SECURITY_AUDIT.md").read_text()
        deadlines = documented_deadlines(audit_text)
        require_unexpired(deadlines, DOCUMENTED_EXCEPTIONS)

        workflow_text = (ROOT / ".github/workflows/security.yml").read_text()
        workflow_ignores = set(WORKFLOW_IGNORE_PATTERN.findall(workflow_text))
        if workflow_ignores != BLOCKING_IGNORES:
            raise ValueError(
                "security workflow ignore set drifted: "
                f"expected {sorted(BLOCKING_IGNORES)}, got {sorted(workflow_ignores)}"
            )
        require_all_features_cargo_deny(workflow_text, ".github/workflows/security.yml")
        rust_workflow_text = (ROOT / ".github/workflows/rust.yml").read_text()
        require_all_features_cargo_deny(
            rust_workflow_text, ".github/workflows/rust.yml"
        )

        with (ROOT / "deny.toml").open("rb") as handle:
            deny = tomllib.load(handle)
        deny_ignores = set(deny.get("advisories", {}).get("ignore", []))
        if deny_ignores != CARGO_DENY_IGNORES:
            raise ValueError(
                "cargo-deny ignore set drifted: "
                f"expected {sorted(CARGO_DENY_IGNORES)}, got {sorted(deny_ignores)}"
            )
        require_source_bound_license_clarifications(
            deny.get("licenses", {}).get("clarify", []),
            (ROOT / "THIRD-PARTY-NOTICES").read_text(encoding="utf-8"),
            load_reviewed_license_clarifications(
                ROOT / "scripts/third_party_license_clarifications.toml"
            ),
        )

        with (ROOT / "jacs/Cargo.toml").open("rb") as handle:
            jacs_manifest = tomllib.load(handle)
        require_object_store_s3_isolation(jacs_manifest)

        # These parent sets are the machine-checked reachability assumptions
        # behind the human dispositions in SECURITY_AUDIT.md. Any new parent
        # is a new exposure and blocks CI until reviewed explicitly.
        require_exact_parents(ROOT / "Cargo.lock", "quick-xml", {"object_store"})
        # Standalone-lock exceptions must never silently broaden into the
        # primary workspace graph merely because deny.toml is shared.
        for standalone_only in (
            "rsa",
            "atomic-polyfill",
            "bincode",
        ):
            require_exact_parents(ROOT / "Cargo.lock", standalone_only, set())
        require_exact_parents(
            ROOT / "jacs-surrealdb/Cargo.lock", "rsa", {"jsonwebtoken"}
        )
        require_exact_parents(
            ROOT / "jacs-surrealdb/Cargo.lock", "atomic-polyfill", {"heapless"}
        )
        require_exact_parents(
            ROOT / "jacs-surrealdb/Cargo.lock", "bincode", {"surrealmx"}
        )
        require_exact_parents(ROOT / "jacspy/uv.lock", "chromadb", {"crewai"})
    except (OSError, KeyError, tomllib.TOMLDecodeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        "OK: advisory deadlines, ignore sets, source-bound license clarifications, "
        "optional S3 isolation, and reachability assumptions validated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
