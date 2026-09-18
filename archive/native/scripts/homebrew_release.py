#!/usr/bin/env python3
"""Safely resolve and render the artifacts used by the Homebrew tap workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

try:
    from http_policy import open_no_redirect
    from release_tag import validate_semver
except ModuleNotFoundError:  # Imported through the scripts namespace in tests.
    from scripts.http_policy import open_no_redirect
    from scripts.release_tag import validate_semver


PYPI_ORIGIN = "https://pypi.org"
PYPI_FILES_ORIGIN = "https://files.pythonhosted.org"
CRATES_ORIGIN = "https://static.crates.io"
PYPI_METADATA_LIMIT = 4 * 1024 * 1024
CRATE_ARCHIVE_LIMIT = 32 * 1024 * 1024
SDIST_ARCHIVE_LIMIT = 64 * 1024 * 1024
TEMPLATE_LIMIT = 1024 * 1024
DEFAULT_FETCH_ATTEMPTS = 12
DEFAULT_FETCH_DELAY_SECONDS = 10
DEFAULT_FETCH_TIMEOUT_SECONDS = 15
DEFAULT_TAP_REPOSITORY = "HumanAssisted/homebrew-jacs"
DEFAULT_TAP_BRANCH = "master"
DEFAULT_HAISDK_PACKAGE = "haisdk"

PACKAGE_NAME = re.compile(r"^[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*$")
GITHUB_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
GITHUB_REPOSITORY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$"
)
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
PLACEHOLDER = re.compile(r"__[A-Z][A-Z0-9_]*__")
SDIST_FILENAME = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+-]*(?:\.tar\.gz|\.zip)$"
)
PYPI_PACKAGE_PATH = re.compile(r"^/packages/[A-Za-z0-9._~%+/-]+$")
OUTPUT_KEYS = frozenset(
    {
        "jacs_version",
        "jacs_sha256",
        "haisdk_version",
        "haisdk_sdist_url",
        "haisdk_sha256",
        "haisdk_pypi_package",
        "tap_repository",
        "tap_branch",
    }
)


def _single_line(label: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError(f"{label} must be a single line")
    return value


def validate_version(value: str) -> str:
    """Validate a version through the release workflows' shared SemVer parser."""

    return validate_semver(_single_line("version", value))


def validate_pypi_package(value: str) -> str:
    value = _single_line("PyPI package", value)
    if len(value) > 128 or PACKAGE_NAME.fullmatch(value) is None:
        raise ValueError(
            "PyPI package must be 1-128 ASCII letters/digits with single -, _, or . "
            "separators"
        )
    return value


def validate_tap_repository(value: str) -> str:
    value = _single_line("tap repository", value)
    parts = value.split("/")
    if len(parts) != 2:
        raise ValueError("tap repository must be exactly owner/repository")
    owner, repository = parts
    if GITHUB_OWNER.fullmatch(owner) is None:
        raise ValueError("tap repository owner is not a valid GitHub owner")
    if GITHUB_REPOSITORY.fullmatch(repository) is None:
        raise ValueError("tap repository name is not a valid GitHub repository")
    return value


def validate_tap_branch(value: str) -> str:
    """Validate a short branch name using Git's check-ref-format constraints."""

    value = _single_line("tap branch", value)
    if len(value.encode("utf-8")) > 255:
        raise ValueError("tap branch is too long")
    if value.startswith(("-", "/", "refs/")) or value.endswith(("/", ".")):
        raise ValueError("tap branch must be a short branch name, not an option or ref")
    if value == "@" or ".." in value or "//" in value or "@{" in value:
        raise ValueError("tap branch violates Git ref syntax")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("tap branch contains a control character")
    if any(char in " ~^:?*[\\" for char in value):
        raise ValueError("tap branch contains a character forbidden in Git refs")
    for component in value.split("/"):
        if not component or component.startswith(".") or component.endswith(".lock"):
            raise ValueError("tap branch contains a forbidden Git ref component")
    return value


def validate_sha256(value: str, label: str = "SHA-256") -> str:
    value = _single_line(label, value)
    if SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must contain exactly 64 hexadecimal characters")
    return value.lower()


def _validated_https_url(url: str, allowed_origins: set[str]) -> str:
    url = _single_line("artifact URL", url)
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise ValueError("artifact URL is malformed") from error
    if parsed.scheme != "https" or parsed.hostname is None:
        raise ValueError("artifact URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None or port is not None:
        raise ValueError("artifact URL must not contain credentials or a custom port")
    canonical_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, "", "")
    )
    if canonical_url != url:
        raise ValueError("artifact URL must use a canonical single-line form")
    origin = f"https://{parsed.hostname.lower()}"
    if origin not in allowed_origins:
        raise ValueError(f"artifact URL origin {origin!r} is not allowed")
    if parsed.query or parsed.fragment:
        raise ValueError("artifact URL must not contain a query or fragment")
    decoded_path = urllib.parse.unquote(parsed.path)
    if not decoded_path.startswith("/") or "\\" in decoded_path:
        raise ValueError("artifact URL path is malformed")
    segments = decoded_path.split("/")
    if any(segment in {".", ".."} for segment in segments):
        raise ValueError("artifact URL path contains traversal")
    if PLACEHOLDER.search(url):
        raise ValueError("artifact URL contains an unresolved placeholder")
    return url


def fetch_bytes(
    url: str,
    *,
    allowed_origins: set[str],
    max_bytes: int,
    attempts: int = DEFAULT_FETCH_ATTEMPTS,
    timeout_seconds: int = DEFAULT_FETCH_TIMEOUT_SECONDS,
    delay_seconds: int = DEFAULT_FETCH_DELAY_SECONDS,
    opener: Callable[..., Any] = open_no_redirect,
    sleep: Callable[[float], None] = time.sleep,
) -> bytes:
    """Fetch an exact HTTPS URL with retries plus response and time bounds."""

    _validated_https_url(url, allowed_origins)
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    if attempts < 1 or timeout_seconds < 1 or delay_seconds < 0:
        raise ValueError(
            "attempts and timeout_seconds must be positive; delay_seconds cannot be negative"
        )

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream, application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "jacs-homebrew-release/1",
        },
    )
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            with opener(request, timeout=timeout_seconds) as response:
                final_url = response.geturl()
                if final_url != url:
                    raise ValueError(
                        f"artifact request followed an unexpected redirect to {final_url!r}"
                    )
                _validated_https_url(final_url, allowed_origins)
                if getattr(response, "status", 200) != 200:
                    raise OSError(f"artifact endpoint returned HTTP {response.status}")
                declared_length = response.headers.get("Content-Length")
                length: int | None = None
                if declared_length is not None:
                    try:
                        length = int(declared_length)
                    except ValueError as error:
                        raise ValueError("artifact Content-Length is invalid") from error
                    if length < 0 or length > max_bytes:
                        raise ValueError("artifact exceeds the configured size limit")
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise ValueError("artifact exceeds the configured size limit")
                if length is not None and len(body) != length:
                    raise ValueError(
                        "artifact body length does not match Content-Length"
                    )
                return body
        except ValueError:
            raise
        except (OSError, TimeoutError, urllib.error.URLError) as error:
            last_error = error
            if attempt < attempts and delay_seconds:
                sleep(delay_seconds)

    raise RuntimeError(f"artifact fetch failed after {attempts} attempts") from last_error


def _canonical_project_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _validated_sdist_url(url: str, filename: str | None = None) -> tuple[str, str]:
    url = _validated_https_url(url, {PYPI_FILES_ORIGIN})
    parsed = urllib.parse.urlsplit(url)
    if (
        PYPI_PACKAGE_PATH.fullmatch(parsed.path) is None
        or "//" in parsed.path
        or re.search(r"%(?![0-9A-Fa-f]{2})", parsed.path)
    ):
        raise ValueError("PyPI sdist URL must use a safe files package path")
    url_filename = urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1])
    if SDIST_FILENAME.fullmatch(url_filename) is None:
        raise ValueError("PyPI sdist URL filename is unsafe or unsupported")
    if filename is not None and url_filename != filename:
        raise ValueError("PyPI sdist URL does not exactly match its filename")
    return url, url_filename


def validate_sdist(
    item: object,
    *,
    package: str | None = None,
    version: str | None = None,
) -> tuple[str, str, str]:
    """Return a validated PyPI sdist filename, URL, and SHA-256 digest."""

    if not isinstance(item, dict) or item.get("packagetype") != "sdist":
        raise ValueError("PyPI release entry must be an sdist object")
    filename = item.get("filename")
    if not isinstance(filename, str):
        raise ValueError("PyPI sdist filename is missing")
    filename = _single_line("PyPI sdist filename", filename)
    if (
        Path(filename).name != filename
        or "/" in filename
        or "\\" in filename
        or PLACEHOLDER.search(filename)
        or SDIST_FILENAME.fullmatch(filename) is None
    ):
        raise ValueError("PyPI sdist filename is unsafe or unsupported")

    url = item.get("url")
    if not isinstance(url, str):
        raise ValueError("PyPI sdist URL is missing")
    url, _url_filename = _validated_sdist_url(url, filename)

    digests = item.get("digests")
    if not isinstance(digests, dict) or not isinstance(digests.get("sha256"), str):
        raise ValueError("PyPI sdist SHA-256 digest is missing")
    digest = validate_sha256(digests["sha256"], "PyPI sdist SHA-256")

    if package is not None and version is not None:
        package = validate_pypi_package(package)
        version = validate_version(version)
        archive_suffix = ".tar.gz" if filename.endswith(".tar.gz") else ".zip"
        release_suffix = f"-{version}{archive_suffix}"
        if not filename.endswith(release_suffix):
            raise ValueError("PyPI sdist filename does not match the selected version")
        filename_project = filename[: -len(release_suffix)]
        if _canonical_project_name(filename_project) != _canonical_project_name(package):
            raise ValueError("PyPI sdist filename does not match the selected package")
    return filename, url, digest


def verify_sha256(body: bytes, expected: str, label: str) -> str:
    expected = validate_sha256(expected, f"{label} SHA-256")
    observed = hashlib.sha256(body).hexdigest()
    if observed != expected:
        raise ValueError(f"{label} digest does not match the downloaded artifact")
    return observed


def _manifest_version(path: Path) -> str:
    with path.open("rb") as manifest_file:
        manifest = tomllib.load(manifest_file)
    try:
        value = manifest["package"]["version"]
    except (KeyError, TypeError) as error:
        raise ValueError(f"{path} has no package.version") from error
    if not isinstance(value, str):
        raise ValueError(f"{path} package.version must be a string")
    return validate_version(value)


def _resolve_jacs_version(value: str, github_ref: str, manifest_path: Path) -> str:
    if value:
        return validate_version(value)
    if github_ref.startswith("refs/tags/"):
        prefix = "refs/tags/crate/v"
        if not github_ref.startswith(prefix):
            raise ValueError("Homebrew tag release must use refs/tags/crate/v<semver>")
        return validate_version(github_ref[len(prefix) :])
    return _manifest_version(manifest_path)


def _metadata_object(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("PyPI metadata is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValueError("PyPI metadata must be a JSON object")
    return value


def resolve_release(
    *,
    jacs_version_input: str,
    haisdk_version_input: str,
    haisdk_package_input: str,
    tap_repository_input: str,
    tap_branch_input: str,
    github_ref: str,
    manifest_path: Path,
    fetch: Callable[..., bytes] = fetch_bytes,
) -> dict[str, str]:
    """Resolve, download, and verify all values consumed by the tap workflow."""

    jacs_version = _resolve_jacs_version(
        jacs_version_input, github_ref, manifest_path
    )
    haisdk_package = validate_pypi_package(
        haisdk_package_input or DEFAULT_HAISDK_PACKAGE
    )
    tap_repository = validate_tap_repository(
        tap_repository_input or DEFAULT_TAP_REPOSITORY
    )
    tap_branch = validate_tap_branch(tap_branch_input or DEFAULT_TAP_BRANCH)

    metadata_url = f"{PYPI_ORIGIN}/pypi/{haisdk_package}/json"
    metadata = _metadata_object(
        fetch(
            metadata_url,
            allowed_origins={PYPI_ORIGIN},
            max_bytes=PYPI_METADATA_LIMIT,
            attempts=DEFAULT_FETCH_ATTEMPTS,
            timeout_seconds=DEFAULT_FETCH_TIMEOUT_SECONDS,
            delay_seconds=DEFAULT_FETCH_DELAY_SECONDS,
        )
    )
    info = metadata.get("info")
    if not isinstance(info, dict):
        raise ValueError("PyPI metadata has no info object")
    published_name = info.get("name")
    if not isinstance(published_name, str) or (
        _canonical_project_name(published_name)
        != _canonical_project_name(haisdk_package)
    ):
        raise ValueError("PyPI metadata package name does not match the requested package")
    if haisdk_version_input:
        haisdk_version = validate_version(haisdk_version_input)
    else:
        published_version = info.get("version")
        if not isinstance(published_version, str):
            raise ValueError("PyPI metadata has no current version")
        haisdk_version = validate_version(published_version)

    releases = metadata.get("releases")
    if not isinstance(releases, dict):
        raise ValueError("PyPI metadata has no releases object")
    entries = releases.get(haisdk_version)
    if not isinstance(entries, list):
        raise ValueError(f"PyPI has no release metadata for {haisdk_version}")
    sdists = [
        item
        for item in entries
        if isinstance(item, dict) and item.get("packagetype") == "sdist"
    ]
    if len(sdists) != 1:
        raise ValueError(
            f"PyPI release {haisdk_package}=={haisdk_version} must have exactly one sdist"
        )
    _filename, sdist_url, sdist_sha256 = validate_sdist(
        sdists[0], package=haisdk_package, version=haisdk_version
    )

    crate_url = (
        f"{CRATES_ORIGIN}/crates/jacs-cli/jacs-cli-{jacs_version}.crate"
    )
    crate_body = fetch(
        crate_url,
        allowed_origins={CRATES_ORIGIN},
        max_bytes=CRATE_ARCHIVE_LIMIT,
        attempts=DEFAULT_FETCH_ATTEMPTS,
        timeout_seconds=DEFAULT_FETCH_TIMEOUT_SECONDS,
        delay_seconds=DEFAULT_FETCH_DELAY_SECONDS,
    )
    jacs_sha256 = hashlib.sha256(crate_body).hexdigest()

    sdist_body = fetch(
        sdist_url,
        allowed_origins={PYPI_FILES_ORIGIN},
        max_bytes=SDIST_ARCHIVE_LIMIT,
        attempts=DEFAULT_FETCH_ATTEMPTS,
        timeout_seconds=DEFAULT_FETCH_TIMEOUT_SECONDS,
        delay_seconds=DEFAULT_FETCH_DELAY_SECONDS,
    )
    verify_sha256(sdist_body, sdist_sha256, "HAISDK sdist")

    return {
        "jacs_version": jacs_version,
        "jacs_sha256": jacs_sha256,
        "haisdk_version": haisdk_version,
        "haisdk_sdist_url": sdist_url,
        "haisdk_sha256": sdist_sha256,
        "haisdk_pypi_package": haisdk_package,
        "tap_repository": tap_repository,
        "tap_branch": tap_branch,
    }


def _validate_outputs(values: Mapping[str, str]) -> dict[str, str]:
    if set(values) != OUTPUT_KEYS:
        missing = sorted(OUTPUT_KEYS - set(values))
        unexpected = sorted(set(values) - OUTPUT_KEYS)
        raise ValueError(
            f"Homebrew outputs do not match the allowlist; missing={missing}, "
            f"unexpected={unexpected}"
        )
    jacs_version = validate_version(values["jacs_version"])
    jacs_sha256 = validate_sha256(values["jacs_sha256"], "JACS SHA-256")
    haisdk_version = validate_version(values["haisdk_version"])
    haisdk_package = validate_pypi_package(values["haisdk_pypi_package"])
    haisdk_sha256 = validate_sha256(values["haisdk_sha256"], "HAISDK SHA-256")
    haisdk_url, haisdk_filename = _validated_sdist_url(
        values["haisdk_sdist_url"]
    )
    validate_sdist(
        {
            "packagetype": "sdist",
            "filename": haisdk_filename,
            "url": haisdk_url,
            "digests": {"sha256": haisdk_sha256},
        },
        package=haisdk_package,
        version=haisdk_version,
    )
    validated = {
        "jacs_version": jacs_version,
        "jacs_sha256": jacs_sha256,
        "haisdk_version": haisdk_version,
        "haisdk_sdist_url": haisdk_url,
        "haisdk_sha256": haisdk_sha256,
        "haisdk_pypi_package": haisdk_package,
        "tap_repository": validate_tap_repository(values["tap_repository"]),
        "tap_branch": validate_tap_branch(values["tap_branch"]),
    }
    return validated


def write_outputs(path: Path, values: Mapping[str, str]) -> None:
    """Append only the fully validated, fixed Homebrew output allowlist."""

    validated = _validate_outputs(values)
    with path.open("a", encoding="utf-8", newline="\n") as output_file:
        for key in sorted(OUTPUT_KEYS):
            output_file.write(f"{key}={validated[key]}\n")


def render_template(template: str, replacements: Mapping[str, str]) -> str:
    expected = set(replacements)
    observed = set(PLACEHOLDER.findall(template))
    missing = sorted(expected - observed)
    unknown = sorted(observed - expected)
    if missing or unknown:
        raise ValueError(
            f"template placeholders do not match; missing={missing}, unknown={unknown}"
        )
    rendered = template
    for placeholder, replacement in replacements.items():
        _single_line(f"replacement for {placeholder}", replacement)
        if PLACEHOLDER.search(replacement):
            raise ValueError(f"replacement for {placeholder} contains a placeholder")
        rendered = rendered.replace(placeholder, replacement)
    if PLACEHOLDER.search(rendered):
        raise ValueError("rendered template still contains a placeholder")
    return rendered


def _read_template(path: Path) -> str:
    size = path.stat().st_size
    if size > TEMPLATE_LIMIT:
        raise ValueError(f"template {path} exceeds the size limit")
    return path.read_text(encoding="utf-8")


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="\n",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as output_file:
        temporary_path = Path(output_file.name)
        output_file.write(content)
    temporary_path.replace(path)


def render_formulas(
    values: Mapping[str, str],
    *,
    jacs_template: Path,
    haisdk_template: Path,
    output_directory: Path,
) -> None:
    required = {
        "jacs_version",
        "jacs_sha256",
        "haisdk_sdist_url",
        "haisdk_sha256",
    }
    if set(values) != required:
        raise ValueError("formula rendering values do not match the required allowlist")
    jacs_version = validate_version(values["jacs_version"])
    jacs_sha256 = validate_sha256(values["jacs_sha256"], "JACS SHA-256")
    haisdk_url, _haisdk_filename = _validated_sdist_url(
        values["haisdk_sdist_url"]
    )
    haisdk_sha256 = validate_sha256(
        values["haisdk_sha256"], "HAISDK SHA-256"
    )

    jacs_formula = render_template(
        _read_template(jacs_template),
        {
            "__JACS_VERSION__": jacs_version,
            "__JACS_SHA256__": jacs_sha256,
        },
    )
    haisdk_formula = render_template(
        _read_template(haisdk_template),
        {
            "__HAISDK_SDIST_URL__": haisdk_url,
            "__HAISDK_SHA256__": haisdk_sha256,
        },
    )
    _atomic_write(output_directory / "jacs.rb", jacs_formula)
    _atomic_write(output_directory / "haisdk.rb", haisdk_formula)


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        raise ValueError(f"{name} is required")
    return value


def _resolve_command() -> None:
    values = resolve_release(
        jacs_version_input=os.environ.get("JACS_VERSION_INPUT", ""),
        haisdk_version_input=os.environ.get("HAISDK_VERSION_INPUT", ""),
        haisdk_package_input=os.environ.get("HAISDK_PYPI_PACKAGE_INPUT", ""),
        tap_repository_input=os.environ.get("TAP_REPOSITORY_INPUT", ""),
        tap_branch_input=os.environ.get("TAP_BRANCH_INPUT", ""),
        github_ref=os.environ.get("GITHUB_REF", ""),
        manifest_path=Path("jacs/Cargo.toml"),
    )
    write_outputs(Path(_required_environment("GITHUB_OUTPUT")), values)
    print(
        "Resolved validated Homebrew artifacts for "
        f"JACS {values['jacs_version']} and HAISDK {values['haisdk_version']}."
    )


def _render_command() -> None:
    render_formulas(
        {
            "jacs_version": _required_environment("JACS_VERSION"),
            "jacs_sha256": _required_environment("JACS_SHA256"),
            "haisdk_sdist_url": _required_environment("HAISDK_SDIST_URL"),
            "haisdk_sha256": _required_environment("HAISDK_SHA256"),
        },
        jacs_template=Path(".github/homebrew-templates/jacs.rb.tmpl"),
        haisdk_template=Path(".github/homebrew-templates/haisdk.rb.tmpl"),
        output_directory=Path("generated/Formula"),
    )
    print("Rendered validated Homebrew formula files.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("resolve", "render"))
    args = parser.parse_args(argv)
    try:
        if args.command == "resolve":
            _resolve_command()
        else:
            _render_command()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
