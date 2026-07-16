#!/usr/bin/env python3
"""Fail-closed exact-version gate for the ordered crates.io release workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from http_policy import open_no_redirect
    from release_tag import validate_semver
except ModuleNotFoundError:  # Imported through the scripts namespace in tests.
    from scripts.http_policy import open_no_redirect
    from scripts.release_tag import validate_semver


ALLOWED_CRATES = (
    "jacs-core",
    "jacs-media",
    "jacs",
    "jacs-binding-core",
    "jacs-mcp",
    "jacs-cli",
    "jacs-duckdb",
    "jacs-redb",
    "jacs-surrealdb",
    "jacs-postgresql",
)
CRATES_API = "https://crates.io/api/v1/crates"
METADATA_LIMIT = 1024 * 1024
MAX_CRATE_BYTES = 512 * 1024 * 1024
NOT_PUBLISHED_EXIT = 3


class ReleaseGateError(RuntimeError):
    """The registry did not provide authoritative exact-version evidence."""


def _positive_integer(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    if not raw.isdigit() or int(raw) < 1:
        raise ValueError(f"{name} must be a positive integer")
    return int(raw)


def _non_negative_integer(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    if not raw.isdigit():
        raise ValueError(f"{name} must be a non-negative integer")
    return int(raw)


def _validate_identity(crate: str, version: str) -> None:
    if crate not in ALLOWED_CRATES:
        allowed = ", ".join(ALLOWED_CRATES)
        raise ValueError(f"crate must be one of: {allowed}")
    validate_semver(version)


def _metadata_from_response(response: Any, crate: str, version: str) -> str:
    status = getattr(response, "status", 200)
    if status != 200:
        raise ReleaseGateError(
            f"crates.io exact-version probe returned unexpected HTTP {status}"
        )
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            length = int(declared)
        except (TypeError, ValueError) as error:
            raise ReleaseGateError(
                "crates.io metadata has an invalid Content-Length"
            ) from error
        if length < 0 or length > METADATA_LIMIT:
            raise ReleaseGateError("crates.io metadata exceeds the size limit")

    body = response.read(METADATA_LIMIT + 1)
    if len(body) > METADATA_LIMIT:
        raise ReleaseGateError("crates.io metadata exceeds the size limit")
    try:
        metadata = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseGateError("crates.io returned malformed JSON metadata") from error
    if not isinstance(metadata, dict):
        raise ReleaseGateError("crates.io metadata must be an object")
    release = metadata.get("version")
    if not isinstance(release, dict):
        raise ReleaseGateError("crates.io metadata has no version object")
    if release.get("crate") != crate or release.get("num") != version:
        raise ReleaseGateError(
            "crates.io metadata does not match the requested crate and version"
        )
    checksum = release.get("checksum")
    if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
        raise ReleaseGateError("crates.io metadata has no valid SHA-256 checksum")
    return checksum


def fetch_exact_version_checksum(
    crate: str,
    version: str,
    *,
    open_url: Callable[..., Any] = open_no_redirect,
    timeout_seconds: int = 20,
    attempts: int = 3,
    delay_seconds: int = 2,
) -> str | None:
    """Return the exact registry checksum, or None only for an exact 404."""

    _validate_identity(crate, version)
    if timeout_seconds < 1 or attempts < 1 or delay_seconds < 0:
        raise ValueError(
            "timeout_seconds and attempts must be positive; delay_seconds non-negative"
        )
    request = urllib.request.Request(
        f"{CRATES_API}/{crate}/{version}",
        headers={
            "Accept": "application/json",
            "User-Agent": "jacs-release-gate/1",
        },
    )
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            with open_url(request, timeout=timeout_seconds) as response:
                return _metadata_from_response(response, crate, version)
        except urllib.error.HTTPError as error:
            try:
                if error.code == 404:
                    return None
                last_error = error
                retryable = error.code == 429 or 500 <= error.code <= 599
                if not retryable or attempt == attempts:
                    raise ReleaseGateError(
                        "crates.io exact-version probe failed closed with "
                        f"HTTP {error.code}"
                    ) from error
            finally:
                error.close()
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
            if attempt == attempts:
                raise ReleaseGateError(
                    "crates.io exact-version probe failed closed after "
                    f"{attempts} attempts: {error}"
                ) from error
        if delay_seconds:
            time.sleep(delay_seconds)
    raise ReleaseGateError(
        f"crates.io exact-version probe failed closed: {last_error}"
    )


def probe_exact_version(
    crate: str,
    version: str,
    *,
    open_url: Callable[..., Any] = open_no_redirect,
    timeout_seconds: int = 20,
    attempts: int = 3,
    delay_seconds: int = 2,
) -> bool:
    """Return True for an exact 200, False only for an authoritative 404."""

    return (
        fetch_exact_version_checksum(
            crate,
            version,
            open_url=open_url,
            timeout_seconds=timeout_seconds,
            attempts=attempts,
            delay_seconds=delay_seconds,
        )
        is not None
    )


def require_exact_version_checksum(
    crate: str,
    version: str,
    **options: Any,
) -> str:
    checksum = fetch_exact_version_checksum(crate, version, **options)
    if checksum is None:
        raise ReleaseGateError(f"{crate} {version} is not published on crates.io")
    return checksum


def verify_archive_checksum(
    crate: str,
    version: str,
    archive: Path,
    *,
    fetch_checksum: Callable[..., str] = require_exact_version_checksum,
    timeout_seconds: int = 20,
    attempts: int = 3,
    delay_seconds: int = 2,
) -> str:
    """Require the reviewed candidate bytes to match crates.io metadata."""

    _validate_identity(crate, version)
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("crate candidate must be a regular non-symlink file")
    size = archive.stat().st_size
    if size < 1 or size > MAX_CRATE_BYTES:
        raise ValueError("crate candidate size is outside the allowed bounds")

    digest = hashlib.sha256()
    with archive.open("rb") as candidate:
        while chunk := candidate.read(64 * 1024):
            digest.update(chunk)
    actual = digest.hexdigest()
    expected = fetch_checksum(
        crate,
        version,
        timeout_seconds=timeout_seconds,
        attempts=attempts,
        delay_seconds=delay_seconds,
    )
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ReleaseGateError("crates.io returned an invalid checksum")
    if actual != expected:
        raise ReleaseGateError(
            f"candidate/registry checksum mismatch for {crate} {version}"
        )
    return actual


def wait_for_version(
    crate: str,
    version: str,
    *,
    attempts: int = 60,
    delay_seconds: int = 15,
    probe: Callable[..., bool] = probe_exact_version,
    probe_attempts: int = 3,
    timeout_seconds: int = 20,
) -> bool:
    """Wait for crates.io indexing while treating uncertainty as an error."""

    _validate_identity(crate, version)
    if attempts < 1 or delay_seconds < 0:
        raise ValueError("attempts must be positive and delay_seconds non-negative")
    for attempt in range(1, attempts + 1):
        if probe(
            crate,
            version,
            attempts=probe_attempts,
            delay_seconds=delay_seconds if attempts == 1 else 0,
            timeout_seconds=timeout_seconds,
        ):
            print(f"{crate} {version} is available on crates.io")
            return True
        if attempt < attempts:
            print(
                f"{crate} {version} not indexed yet "
                f"(attempt {attempt}/{attempts})"
            )
            if delay_seconds:
                time.sleep(delay_seconds)
    raise ReleaseGateError(
        f"timed out waiting for {crate} {version} to appear on crates.io"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("check", "wait", "verify"):
        child = subparsers.add_parser(command)
        child.add_argument("--crate", required=True, choices=ALLOWED_CRATES)
        child.add_argument("--version", required=True)
        if command == "verify":
            child.add_argument("--archive", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    http_attempts = _positive_integer("JACS_CRATES_HTTP_ATTEMPTS", 3)
    http_delay = _non_negative_integer("JACS_CRATES_HTTP_DELAY_SECONDS", 2)
    http_timeout = _positive_integer("JACS_CRATES_HTTP_TIMEOUT_SECONDS", 20)
    try:
        if args.command == "check":
            exists = probe_exact_version(
                args.crate,
                args.version,
                attempts=http_attempts,
                delay_seconds=http_delay,
                timeout_seconds=http_timeout,
            )
            if exists:
                print(f"{args.crate} {args.version} already exists on crates.io")
                return 0
            print(f"{args.crate} {args.version} is not published on crates.io")
            return NOT_PUBLISHED_EXIT

        if args.command == "wait":
            wait_for_version(
                args.crate,
                args.version,
                attempts=_positive_integer("JACS_CRATES_WAIT_ATTEMPTS", 60),
                delay_seconds=_non_negative_integer(
                    "JACS_CRATES_WAIT_DELAY_SECONDS", 15
                ),
                probe_attempts=http_attempts,
                timeout_seconds=http_timeout,
            )
        else:
            checksum = verify_archive_checksum(
                args.crate,
                args.version,
                args.archive,
                attempts=http_attempts,
                delay_seconds=http_delay,
                timeout_seconds=http_timeout,
            )
            print(f"Verified {args.crate} {args.version} registry SHA-256 {checksum}")
    except (ReleaseGateError, ValueError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
