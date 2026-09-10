#!/usr/bin/env python3
"""Verify every file in one JACS PyPI release against its PEP 740 provenance."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

try:
    from http_policy import open_no_redirect
    from release_tag import validate_semver
except ModuleNotFoundError:  # Imported through the scripts namespace in tests.
    from scripts.http_policy import open_no_redirect
    from scripts.release_tag import validate_semver


PROJECT = "jacs"
EXPECTED_REPOSITORY = "https://github.com/HumanAssisted/JACS"
PYPI_JSON_LIMIT = 4 * 1024 * 1024


def _run_command(
    command: list[str], timeout_seconds: int
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        text=True,
        timeout=timeout_seconds,
    )


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


def fetch_metadata(
    version: str,
    *,
    open_url: Callable[..., Any] = open_no_redirect,
    attempts: int = 3,
    delay_seconds: int = 2,
    timeout_seconds: int = 20,
) -> dict[str, Any]:
    validate_semver(version)
    if attempts < 1 or delay_seconds < 0 or timeout_seconds < 1:
        raise ValueError("timeouts/attempts must be positive and delay non-negative")
    url = f"https://pypi.org/pypi/{PROJECT}/{version}/json"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "jacs-release-verifier/1"},
    )
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            with open_url(request, timeout=timeout_seconds) as response:
                declared_length = response.headers.get("Content-Length")
                if declared_length is not None:
                    try:
                        length = int(declared_length)
                    except (TypeError, ValueError) as error:
                        raise ValueError(
                            "PyPI metadata has an invalid Content-Length"
                        ) from error
                    if length < 0 or length > PYPI_JSON_LIMIT:
                        raise ValueError(
                            "PyPI metadata exceeds the configured size limit"
                        )
                body = response.read(PYPI_JSON_LIMIT + 1)
            if len(body) > PYPI_JSON_LIMIT:
                raise ValueError("PyPI metadata exceeds the configured size limit")
            metadata = json.loads(body)
            if not isinstance(metadata, dict):
                raise ValueError("PyPI metadata must be a JSON object")
            return metadata
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
            if attempt < attempts and delay_seconds:
                time.sleep(delay_seconds)
    raise RuntimeError(
        f"failed to fetch PyPI metadata after {attempts} attempts: {last_error}"
    ) from last_error


def _validated_distribution(item: object) -> tuple[str, str]:
    if not isinstance(item, dict):
        raise ValueError("PyPI distribution metadata must be an object")
    filename = item.get("filename")
    url = item.get("url")
    if not isinstance(filename, str) or not filename:
        raise ValueError("PyPI distribution has no filename")
    if not isinstance(url, str):
        raise ValueError(f"PyPI distribution {filename!r} has no URL")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "files.pythonhosted.org"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(
            f"PyPI distribution {filename!r} must use https://files.pythonhosted.org"
        )
    if urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1]) != filename:
        raise ValueError(f"PyPI distribution URL does not match filename {filename!r}")
    return filename, url


def verify_release(
    version: str,
    metadata: dict[str, Any],
    *,
    run: Callable[[list[str], int], subprocess.CompletedProcess[str]] = _run_command,
    attempts: int = 12,
    delay_seconds: int = 5,
    timeout_seconds: int = 60,
) -> None:
    validate_semver(version)
    if attempts < 1 or delay_seconds < 0 or timeout_seconds < 1:
        raise ValueError(
            "attempts and timeout_seconds must be positive and delay_seconds non-negative"
        )
    distributions = metadata.get("urls")
    if not isinstance(distributions, list) or not distributions:
        raise ValueError(f"PyPI release {PROJECT}=={version} has no distributions")

    verified = 0
    for item in distributions:
        filename, url = _validated_distribution(item)
        command = [
            "pypi-attestations",
            "verify",
            "pypi",
            "--repository",
            EXPECTED_REPOSITORY,
            url,
        ]
        final_timed_out = False
        for attempt in range(1, attempts + 1):
            try:
                result = run(command, timeout_seconds)
                final_timed_out = False
            except subprocess.TimeoutExpired:
                final_timed_out = True
                result = None
            if result is not None and result.returncode == 0:
                verified += 1
                break
            if attempt < attempts and delay_seconds:
                time.sleep(delay_seconds)
        else:
            outcome = "timed out" if final_timed_out else "failed"
            raise RuntimeError(
                f"PEP 740 provenance verification {outcome} for {filename}"
            )

    print(f"Verified PEP 740 provenance for {verified} PyPI distribution(s).")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="exact JACS PyPI release version")
    args = parser.parse_args()
    attempts = _positive_integer("JACS_PYPI_VERIFY_ATTEMPTS", 12)
    delay_seconds = _non_negative_integer("JACS_PYPI_VERIFY_DELAY_SECONDS", 5)
    timeout_seconds = _positive_integer("JACS_PYPI_VERIFY_TIMEOUT_SECONDS", 60)
    http_attempts = _positive_integer("JACS_PYPI_HTTP_ATTEMPTS", 6)
    http_delay_seconds = _non_negative_integer("JACS_PYPI_HTTP_DELAY_SECONDS", 5)
    http_timeout_seconds = _positive_integer("JACS_PYPI_HTTP_TIMEOUT_SECONDS", 20)
    verify_release(
        args.version,
        fetch_metadata(
            args.version,
            attempts=http_attempts,
            delay_seconds=http_delay_seconds,
            timeout_seconds=http_timeout_seconds,
        ),
        attempts=attempts,
        delay_seconds=delay_seconds,
        timeout_seconds=timeout_seconds,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
