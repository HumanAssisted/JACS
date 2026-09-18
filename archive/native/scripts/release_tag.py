#!/usr/bin/env python3
"""Parse release tags without evaluating tag-derived text in a shell."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


SURFACE_PREFIXES = {
    "crate": "refs/tags/crate/v",
    "cli": "refs/tags/cli/v",
    "npm": "refs/tags/npm/v",
    "pypi": "refs/tags/pypi/v",
    "wasm": "refs/tags/wasm-v",
    "jacsgo": "refs/tags/jacsgo/v",
}
STORAGE_CRATES = (
    "jacs-duckdb",
    "jacs-redb",
    "jacs-surrealdb",
    "jacs-postgresql",
)

# SemVer 2.0.0. Numeric identifiers cannot contain leading zeroes; pre-release
# and build identifiers must be non-empty and may contain only ASCII SemVer
# characters. Keeping this validation here gives every release workflow the
# same trust boundary.
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def validate_semver(version: str) -> str:
    if SEMVER.fullmatch(version) is None:
        raise ValueError(f"release version is not strict SemVer 2.0.0: {version!r}")
    return version


def parse_release_ref(surface: str, ref: str) -> dict[str, str]:
    """Return validated output fields for an exact release-tag reference."""

    if surface == "storage":
        match = re.fullmatch(
            rf"refs/tags/crate/({'|'.join(map(re.escape, STORAGE_CRATES))})/v(.+)",
            ref,
        )
        if match is None:
            allowed = ", ".join(STORAGE_CRATES)
            raise ValueError(
                "storage release ref must name an allowed crate "
                f"({allowed}) and use crate/<crate>/v<semver>"
            )
        crate, version = match.groups()
        return {"crate": crate, "version": validate_semver(version)}

    try:
        prefix = SURFACE_PREFIXES[surface]
    except KeyError as error:
        raise ValueError(f"unknown release surface: {surface!r}") from error

    if not ref.startswith(prefix):
        raise ValueError(f"release ref must start with {prefix!r}")
    version = ref[len(prefix) :]
    return {"version": validate_semver(version)}


def write_github_outputs(path: Path, outputs: dict[str, str]) -> None:
    """Append validated single-line outputs to GitHub's managed output file."""

    for key, value in outputs.items():
        if "\n" in key or "\n" in value or "\r" in key or "\r" in value:
            raise ValueError("GitHub output keys and values must be single-line")
    with path.open("a", encoding="utf-8") as output:
        for key, value in outputs.items():
            output.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--surface",
        required=True,
        choices=(*SURFACE_PREFIXES, "storage"),
        help="release workflow whose exact tag grammar should be applied",
    )
    args = parser.parse_args(argv)

    ref = os.environ.get("GITHUB_REF")
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not ref:
        parser.error("GITHUB_REF is required")
    if not output_path:
        parser.error("GITHUB_OUTPUT is required")

    try:
        outputs = parse_release_ref(args.surface, ref)
        write_github_outputs(Path(output_path), outputs)
    except (OSError, ValueError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 2

    details = ", ".join(f"{key}={value}" for key, value in outputs.items())
    print(f"Validated {args.surface} release tag: {details}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
