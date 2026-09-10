#!/usr/bin/env python3
"""Validate npm package metadata required by trusted publishing."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


EXPECTED_REPOSITORY_URL = "https://github.com/HumanAssisted/JACS"


def package_errors(path: Path) -> list[str]:
    """Return stable trusted-publisher metadata errors for one package file."""

    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"could not read package metadata: {error}"]

    repository = package.get("repository")
    repository_url = (
        repository.get("url") if isinstance(repository, dict) else repository
    )
    errors: list[str] = []
    if repository_url != EXPECTED_REPOSITORY_URL:
        errors.append(
            "repository.url must exactly match the npm trusted publisher: "
            f"expected {EXPECTED_REPOSITORY_URL!r}, got {repository_url!r}"
        )
    if isinstance(repository, dict) and repository.get("type") != "git":
        errors.append("repository.type must be 'git'")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="+", type=Path)
    args = parser.parse_args(argv)

    failed = False
    for package in args.packages:
        errors = package_errors(package)
        if errors:
            failed = True
            for error in errors:
                print(f"ERROR: {package}: {error}", file=sys.stderr)
        else:
            print(f"OK: {package}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
