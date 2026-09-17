#!/usr/bin/env python3
"""Require canonical first- and third-party notices in release archives."""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from collections.abc import Sequence
from pathlib import Path


REQUIRED_ENTRIES = ("LICENSE-APACHE", "THIRD-PARTY-NOTICES")
MAX_NOTICE_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000


def _expected_bytes(license_bytes: bytes, notices_bytes: bytes) -> dict[str, bytes]:
    return {
        "LICENSE-APACHE": license_bytes,
        "THIRD-PARTY-NOTICES": notices_bytes,
    }


def _tar_entries(path: Path) -> tuple[dict[str, list[bytes]], list[str]]:
    values = {name: [] for name in REQUIRED_ENTRIES}
    errors: list[str] = []
    try:
        with tarfile.open(path, "r:*") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_ENTRIES:
                return values, [
                    f"archive has {len(members)} entries; maximum is {MAX_ARCHIVE_ENTRIES}"
                ]
            for member in members:
                if member.name not in values:
                    continue
                if not member.isfile():
                    errors.append(f"{member.name} must be a regular file")
                    continue
                if member.size > MAX_NOTICE_BYTES:
                    errors.append(
                        f"{member.name} exceeds {MAX_NOTICE_BYTES} bytes"
                    )
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    errors.append(f"could not read {member.name}")
                    continue
                values[member.name].append(stream.read(MAX_NOTICE_BYTES + 1))
    except (OSError, tarfile.TarError) as error:
        errors.append(f"could not read tar archive: {error}")
    return values, errors


def _zip_entries(path: Path) -> tuple[dict[str, list[bytes]], list[str]]:
    values = {name: [] for name in REQUIRED_ENTRIES}
    errors: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_ENTRIES:
                return values, [
                    f"archive has {len(members)} entries; maximum is {MAX_ARCHIVE_ENTRIES}"
                ]
            for member in members:
                if member.filename not in values:
                    continue
                if member.is_dir():
                    errors.append(f"{member.filename} must be a regular file")
                    continue
                if member.file_size > MAX_NOTICE_BYTES:
                    errors.append(
                        f"{member.filename} exceeds {MAX_NOTICE_BYTES} bytes"
                    )
                    continue
                with archive.open(member) as stream:
                    values[member.filename].append(stream.read(MAX_NOTICE_BYTES + 1))
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        errors.append(f"could not read zip archive: {error}")
    return values, errors


def archive_errors(
    path: Path, license_bytes: bytes, notices_bytes: bytes
) -> list[str]:
    """Return archive-composition errors without exposing notice contents."""

    if path.name.endswith(".tar.gz") or path.suffix in {".tgz", ".tar"}:
        values, errors = _tar_entries(path)
    elif path.suffix == ".zip":
        values, errors = _zip_entries(path)
    else:
        return [f"unsupported archive format: {path.name}"]

    for name, expected in _expected_bytes(license_bytes, notices_bytes).items():
        found = values[name]
        if not found:
            errors.append(f"archive is missing root {name}")
        elif len(found) != 1:
            errors.append(f"archive contains {len(found)} root {name} entries")
        elif found[0] != expected:
            errors.append(f"archive {name} does not match repository canonical file")
    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path)
    parser.add_argument("--license", required=True, type=Path)
    parser.add_argument("--notices", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        license_bytes = args.license.read_bytes()
        notices_bytes = args.notices.read_bytes()
    except OSError as error:
        print(f"release license check failed: {error}", file=sys.stderr)
        return 1

    failed = False
    for archive in args.archives:
        errors = archive_errors(archive, license_bytes, notices_bytes)
        for error in errors:
            print(f"{archive}: {error}", file=sys.stderr)
        failed = failed or bool(errors)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
