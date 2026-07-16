#!/usr/bin/env python3
"""Verify the complete, exact asset inventory for a JACS GitHub release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, NamedTuple

try:
    from release_tag import validate_semver
except ModuleNotFoundError:  # Imported through the scripts namespace in tests.
    from scripts.release_tag import validate_semver


REPOSITORY = "HumanAssisted/JACS"
API_ROOT = f"https://api.github.com/repos/{REPOSITORY}"
METADATA_LIMIT_BYTES = 1024 * 1024
MATRIX_LIMIT_BYTES = 1024 * 1024
DEFAULT_MAX_ASSET_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
DOWNLOAD_CHUNK_BYTES = 64 * 1024
CHECKSUM_MANIFEST_LIMIT_BYTES = 1024 * 1024
COMMAND_DIAGNOSTIC_LIMIT_CHARS = 4096

class ReleaseSpec(NamedTuple):
    tag: str
    version: str
    signer_workflow: str
    expected_assets: frozenset[str]
    payload_assets: frozenset[str]
    checksum_manifest: str


class ReleaseAsset(NamedTuple):
    name: str
    size: int
    download_url: str


class ReleaseNotReadyError(ValueError):
    """The expected release is public but still being assembled."""


OpenUrl = Callable[..., Any]
CommandRunner = Callable[[list[str], int], subprocess.CompletedProcess[str]]


class _SafeGitHubRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep public release downloads on GitHub-controlled HTTPS hosts."""

    def redirect_request(self, request, fp, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        host = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or not (
                host == "github.com"
                or host == "api.github.com"
                or host.endswith(".githubusercontent.com")
            )
        ):
            raise ValueError(f"GitHub release download redirected to disallowed URL: {new_url}")
        return super().redirect_request(request, fp, code, message, headers, new_url)


_URL_OPENER = urllib.request.build_opener(_SafeGitHubRedirectHandler())


def _open_url(request: urllib.request.Request, *, timeout: int):
    return _URL_OPENER.open(request, timeout=timeout)


def _run_command(
    command: list[str], timeout_seconds: int
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        text=True,
        capture_output=True,
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


def _version_from_tag(tag: str, prefix: str) -> str:
    if not tag.startswith(prefix):
        raise ValueError(f"unsupported release tag: {tag!r}")
    version = tag[len(prefix) :]
    try:
        validate_semver(version)
    except ValueError as error:
        raise ValueError(
            f"release tag does not contain strict SemVer: {tag!r}"
        ) from error

    return version


def release_spec(tag: str) -> ReleaseSpec:
    """Derive the only acceptable workflow and asset set for a release tag."""

    if tag.startswith("cli/v"):
        version = _version_from_tag(tag, "cli/v")
        archives = {
            f"jacs-cli-{version}-darwin-arm64.tar.gz",
            f"jacs-cli-{version}-darwin-x64.tar.gz",
            f"jacs-cli-{version}-linux-x64.tar.gz",
            f"jacs-cli-{version}-linux-arm64.tar.gz",
            f"jacs-cli-{version}-windows-x64.zip",
        }
        assets = archives | {f"{archive}.sha256" for archive in archives}
        assets |= {"sha256sums.txt", "jacs-cli.spdx.json"}
        return ReleaseSpec(
            tag,
            version,
            "HumanAssisted/JACS/.github/workflows/release-cli.yml",
            frozenset(assets),
            frozenset(archives),
            "sha256sums.txt",
        )

    if tag.startswith("jacsgo/v"):
        version = _version_from_tag(tag, "jacsgo/v")
        libraries = {
            f"jacsgo-v{version}-darwin-arm64.dylib",
            f"jacsgo-v{version}-darwin-amd64.dylib",
            f"jacsgo-v{version}-linux-amd64.so",
            f"jacsgo-v{version}-linux-arm64.so",
        }
        assets = libraries | {f"{library}.sha256" for library in libraries}
        assets |= {
            f"jacsgo-v{version}-sha256sums.txt",
            "jacsgo.spdx.json",
            "LICENSE-APACHE",
            "THIRD-PARTY-NOTICES",
        }
        return ReleaseSpec(
            tag,
            version,
            "HumanAssisted/JACS/.github/workflows/release-jacsgo.yml",
            frozenset(assets),
            frozenset(libraries),
            f"jacsgo-v{version}-sha256sums.txt",
        )

    raise ValueError(f"unsupported release tag: {tag!r}")


def validate_signer_workflow(spec: ReleaseSpec, signer_workflow: str) -> None:
    if signer_workflow != spec.signer_workflow:
        raise ValueError(
            f"signer workflow for {spec.tag!r} must be {spec.signer_workflow!r}"
        )


def _validate_download_url(tag: str, name: str, url: object) -> str:
    if not isinstance(url, str):
        raise ValueError(f"release asset {name!r} has no download URL")
    parsed = urllib.parse.urlsplit(url)
    prefix = f"/{REPOSITORY}/releases/download/"
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith(prefix)
    ):
        raise ValueError(f"release asset {name!r} has an untrusted download URL")
    release_and_name = parsed.path[len(prefix) :]
    encoded_tag, separator, encoded_name = release_and_name.rpartition("/")
    if (
        not separator
        or urllib.parse.unquote(encoded_tag) != tag
        or urllib.parse.unquote(encoded_name) != name
    ):
        raise ValueError(f"release asset URL does not match tag and filename for {name!r}")
    return url


def validate_release_metadata(
    tag: str,
    metadata: object,
    *,
    max_asset_bytes: int = DEFAULT_MAX_ASSET_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> list[ReleaseAsset]:
    """Reject any release whose public inventory is not exactly the expected set."""

    spec = release_spec(tag)
    if max_asset_bytes < 1 or max_total_bytes < 1:
        raise ValueError("download size limits must be positive")
    if not isinstance(metadata, dict):
        raise ValueError("GitHub release metadata must be a JSON object")
    if metadata.get("tag_name") != tag:
        raise ValueError(f"GitHub release metadata tag does not match {tag!r}")
    if metadata.get("draft") is not False:
        raise ReleaseNotReadyError(f"GitHub release {tag!r} is not public")
    raw_assets = metadata.get("assets")
    if not isinstance(raw_assets, list):
        raise ValueError(f"GitHub release {tag!r} has no asset list")

    names: list[str] = []
    for item in raw_assets:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError("GitHub release asset metadata must include a filename")
        names.append(item["name"])
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"GitHub release contains duplicate assets: {', '.join(duplicates)}")

    observed = set(names)
    missing = sorted(spec.expected_assets - observed)
    unexpected = sorted(observed - spec.expected_assets)
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected: {', '.join(unexpected)}")
        error = f"release asset inventory mismatch ({'; '.join(details)})"
        if missing and not unexpected:
            raise ReleaseNotReadyError(error)
        raise ValueError(error)

    assets: list[ReleaseAsset] = []
    total_size = 0
    for item in raw_assets:
        name = item["name"]
        size = item.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 1:
            raise ValueError(f"release asset {name!r} has an invalid declared size")
        if size > max_asset_bytes:
            raise ValueError(
                f"release asset {name!r} exceeds the per-asset download size limit"
            )
        total_size += size
        if total_size > max_total_bytes:
            raise ValueError("release total download size exceeds the configured limit")
        assets.append(
            ReleaseAsset(
                name,
                size,
                _validate_download_url(tag, name, item.get("browser_download_url")),
            )
        )
    return sorted(assets, key=lambda asset: asset.name)


def _response_length(response: Any) -> int | None:
    raw = response.headers.get("Content-Length")
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError) as error:
        raise ValueError("HTTP response has an invalid Content-Length") from error
    if value < 0:
        raise ValueError("HTTP response has an invalid Content-Length")
    return value


def _read_limited(response: Any, limit: int, description: str) -> bytes:
    declared = _response_length(response)
    if declared is not None and declared > limit:
        raise ValueError(f"{description} exceeds the configured size limit")
    body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError(f"{description} exceeds the configured size limit")
    return body


def fetch_release_metadata(
    tag: str,
    *,
    open_url: OpenUrl = _open_url,
    timeout_seconds: int = 30,
    attempts: int = 3,
    delay_seconds: int = 2,
) -> dict[str, Any]:
    """Fetch bounded release metadata, retrying only transport failures."""

    release_spec(tag)
    if timeout_seconds < 1 or attempts < 1 or delay_seconds < 0:
        raise ValueError("timeouts/attempts must be positive and delay non-negative")
    url = f"{API_ROOT}/releases/tags/{urllib.parse.quote(tag, safe='')}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "jacs-release-attestation-verifier/1",
    }
    token = os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)

    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            with open_url(request, timeout=timeout_seconds) as response:
                body = _read_limited(
                    response, METADATA_LIMIT_BYTES, "GitHub release metadata"
                )
            parsed = json.loads(body)
            if not isinstance(parsed, dict):
                raise ValueError("GitHub release metadata must be a JSON object")
            return parsed
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
            if attempt < attempts and delay_seconds:
                time.sleep(delay_seconds)
    raise RuntimeError(
        f"failed to fetch GitHub release metadata for {tag!r} after {attempts} attempts: "
        f"{last_error}"
    )


def _download_asset_once(
    asset: ReleaseAsset,
    destination: Path,
    *,
    open_url: OpenUrl,
    timeout_seconds: int,
) -> None:
    request = urllib.request.Request(
        asset.download_url,
        headers={
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "jacs-release-attestation-verifier/1",
        },
    )
    partial = destination.with_name(f".{destination.name}.part")
    if destination.exists():
        raise ValueError(f"refusing to overwrite downloaded release asset {destination}")
    partial.unlink(missing_ok=True)
    try:
        with open_url(request, timeout=timeout_seconds) as response:
            content_length = _response_length(response)
            if content_length is not None and content_length != asset.size:
                raise ValueError(
                    f"downloaded {asset.name!r} does not match its release-declared size"
                )
            written = 0
            with partial.open("xb") as output:
                while written <= asset.size:
                    chunk = response.read(
                        min(DOWNLOAD_CHUNK_BYTES, asset.size + 1 - written)
                    )
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > asset.size:
                        raise ValueError(
                            f"downloaded {asset.name!r} exceeds its release-declared size"
                        )
                    output.write(chunk)
            if written != asset.size:
                raise ValueError(
                    f"downloaded {asset.name!r} does not match its release-declared size"
                )
        partial.replace(destination)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def download_asset(
    asset: ReleaseAsset,
    destination: Path,
    *,
    open_url: OpenUrl = _open_url,
    timeout_seconds: int = 30,
    attempts: int = 3,
    delay_seconds: int = 2,
) -> None:
    """Download one asset without ever accepting more than its declared size."""

    if destination.name != asset.name:
        raise ValueError("release asset destination filename must match metadata")
    if timeout_seconds < 1 or attempts < 1 or delay_seconds < 0:
        raise ValueError("timeouts/attempts must be positive and delay non-negative")
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            _download_asset_once(
                asset,
                destination,
                open_url=open_url,
                timeout_seconds=timeout_seconds,
            )
            return
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
            if attempt < attempts and delay_seconds:
                time.sleep(delay_seconds)
    raise RuntimeError(
        f"failed to download {asset.name!r} after {attempts} attempts: {last_error}"
    )


def download_release_assets(
    assets: Iterable[ReleaseAsset],
    directory: Path,
    *,
    open_url: OpenUrl = _open_url,
    timeout_seconds: int = 30,
    attempts: int = 3,
    delay_seconds: int = 2,
) -> list[Path]:
    paths = []
    for asset in assets:
        destination = directory / asset.name
        download_asset(
            asset,
            destination,
            open_url=open_url,
            timeout_seconds=timeout_seconds,
            attempts=attempts,
            delay_seconds=delay_seconds,
        )
        paths.append(destination)
    return paths


def _parse_checksum_manifest(path: Path, expected: frozenset[str]) -> dict[str, str]:
    try:
        with path.open("rb") as manifest:
            body = manifest.read(CHECKSUM_MANIFEST_LIMIT_BYTES + 1)
    except OSError as error:
        raise RuntimeError(f"cannot read checksum manifest {path.name}: {error}") from error
    if len(body) > CHECKSUM_MANIFEST_LIMIT_BYTES:
        raise RuntimeError(f"checksum manifest {path.name} exceeds the size limit")
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"checksum manifest {path.name} is not ASCII") from error

    entries: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,255})",
            line,
        )
        if match is None:
            raise RuntimeError(
                f"checksum manifest {path.name} has an invalid line {line_number}"
            )
        digest, name = match.groups()
        if name in entries:
            raise RuntimeError(
                f"checksum manifest {path.name} repeats {name!r}"
            )
        entries[name] = digest
    observed = frozenset(entries)
    if observed != expected:
        missing = sorted(expected - observed)
        unexpected = sorted(observed - expected)
        raise RuntimeError(
            f"checksum manifest {path.name} inventory mismatch "
            f"(missing={missing!r}, unexpected={unexpected!r})"
        )
    return entries


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as payload:
        while chunk := payload.read(DOWNLOAD_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def verify_release_checksums(spec: ReleaseSpec, paths: Iterable[Path]) -> None:
    """Prove both checksum forms bind every downloaded binary/library byte."""

    by_name: dict[str, Path] = {}
    for path in paths:
        if path.name in by_name:
            raise RuntimeError(f"downloaded release inventory repeats {path.name!r}")
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"release asset is not a regular file: {path}")
        by_name[path.name] = path
    if frozenset(by_name) != spec.expected_assets:
        raise RuntimeError("downloaded release inventory changed before checksum validation")

    aggregate = _parse_checksum_manifest(
        by_name[spec.checksum_manifest], spec.payload_assets
    )
    for payload_name in sorted(spec.payload_assets):
        per_asset = _parse_checksum_manifest(
            by_name[f"{payload_name}.sha256"], frozenset({payload_name})
        )
        actual = _sha256(by_name[payload_name])
        if aggregate[payload_name] != actual or per_asset[payload_name] != actual:
            raise RuntimeError(f"checksum mismatch for release asset {payload_name}")


def fetch_complete_release_assets(
    tag: str,
    *,
    fetch: Callable[..., dict[str, Any]] = fetch_release_metadata,
    timeout_seconds: int = 30,
    attempts: int = 3,
    delay_seconds: int = 2,
    max_asset_bytes: int = DEFAULT_MAX_ASSET_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> list[ReleaseAsset]:
    """Wait for a public release snapshot whose exact inventory is complete."""

    if attempts < 1 or timeout_seconds < 1 or delay_seconds < 0:
        raise ValueError("timeouts/attempts must be positive and delay non-negative")
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            metadata = fetch(
                tag,
                timeout_seconds=timeout_seconds,
                attempts=1,
                delay_seconds=0,
            )
            return validate_release_metadata(
                tag,
                metadata,
                max_asset_bytes=max_asset_bytes,
                max_total_bytes=max_total_bytes,
            )
        except (ReleaseNotReadyError, RuntimeError) as error:
            last_error = error
            if attempt < attempts and delay_seconds:
                time.sleep(delay_seconds)
    raise RuntimeError(
        f"GitHub release {tag!r} did not become complete after {attempts} attempts: "
        f"{last_error}"
    ) from last_error


def verify_attestations(
    spec: ReleaseSpec,
    paths: Iterable[Path],
    *,
    run: CommandRunner = _run_command,
    attempts: int = 12,
    delay_seconds: int = 5,
    command_timeout_seconds: int = 60,
) -> None:
    """Verify each local asset under one fixed GitHub provenance policy."""

    if attempts < 1 or command_timeout_seconds < 1 or delay_seconds < 0:
        raise ValueError("timeouts/attempts must be positive and delay non-negative")
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"release asset is not a regular file: {path}")
        command = [
            "gh",
            "attestation",
            "verify",
            str(path),
            "--repo",
            REPOSITORY,
            "--signer-workflow",
            spec.signer_workflow,
            "--source-ref",
            f"refs/tags/{spec.tag}",
            "--deny-self-hosted-runners",
        ]
        timed_out = 0
        last_error: BaseException | None = None
        for attempt in range(1, attempts + 1):
            try:
                result = run(command, command_timeout_seconds)
                if result.returncode == 0:
                    break
                diagnostic = (result.stderr or result.stdout or "").strip()
                diagnostic = diagnostic[-COMMAND_DIAGNOSTIC_LIMIT_CHARS:]
                suffix = f": {diagnostic}" if diagnostic else ""
                last_error = RuntimeError(
                    f"gh exited with status {result.returncode}{suffix}"
                )
            except subprocess.TimeoutExpired as error:
                timed_out += 1
                last_error = error
            except OSError as error:
                last_error = error
            if attempt < attempts and delay_seconds:
                time.sleep(delay_seconds)
        else:
            if timed_out == attempts:
                raise RuntimeError(
                    f"attestation verification for {path.name} timed out after "
                    f"{attempts} attempts"
                ) from last_error
            raise RuntimeError(
                f"attestation verification failed for {path.name} after "
                f"{attempts} attempts: {last_error}"
            ) from last_error


def verify_release(
    tag: str,
    signer_workflow: str,
    *,
    attempts: int = 12,
    delay_seconds: int = 5,
    command_timeout_seconds: int = 60,
    http_timeout_seconds: int = 30,
    metadata_attempts: int | None = None,
    max_asset_bytes: int = DEFAULT_MAX_ASSET_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> None:
    spec = release_spec(tag)
    validate_signer_workflow(spec, signer_workflow)
    assets = fetch_complete_release_assets(
        tag,
        timeout_seconds=http_timeout_seconds,
        attempts=attempts if metadata_attempts is None else metadata_attempts,
        delay_seconds=delay_seconds,
        max_asset_bytes=max_asset_bytes,
        max_total_bytes=max_total_bytes,
    )
    with tempfile.TemporaryDirectory(prefix="jacs-release-attestations-") as raw_dir:
        directory = Path(raw_dir)
        paths = download_release_assets(
            assets,
            directory,
            timeout_seconds=http_timeout_seconds,
            attempts=attempts,
            delay_seconds=delay_seconds,
        )
        downloaded = {path.name for path in directory.iterdir() if path.is_file()}
        if downloaded != spec.expected_assets:
            raise RuntimeError("downloaded release inventory changed before verification")
        verify_release_checksums(spec, paths)
        verify_attestations(
            spec,
            paths,
            attempts=attempts,
            delay_seconds=delay_seconds,
            command_timeout_seconds=command_timeout_seconds,
        )
    print(
        f"Verified {len(spec.expected_assets)} exact public release asset "
        f"attestation(s) for {tag}."
    )


def recorded_release_specs(matrix: object) -> list[ReleaseSpec]:
    """Select published CLI/Go releases recorded by the shipped matrix."""

    if not isinstance(matrix, dict) or not isinstance(matrix.get("artifacts"), dict):
        raise ValueError("shipped-artifact matrix must contain an artifacts object")
    artifacts = matrix["artifacts"]
    specs: list[ReleaseSpec] = []
    for surface, prefix in (("cli", "cli/v"), ("go", "jacsgo/v")):
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
        specs.append(release_spec(f"{prefix}{version.removeprefix('v')}"))
    return specs


def verify_recorded_releases(
    matrix_path: Path,
    *,
    verify: Callable[..., None] = verify_release,
    verify_options: dict[str, int] | None = None,
) -> None:
    """Reverify every GitHub release represented as published in the matrix."""

    try:
        with matrix_path.open("rb") as matrix_file:
            body = matrix_file.read(MATRIX_LIMIT_BYTES + 1)
    except OSError as error:
        raise ValueError(f"cannot read shipped-artifact matrix: {error}") from error
    if len(body) > MATRIX_LIMIT_BYTES:
        raise ValueError("shipped-artifact matrix exceeds the configured size limit")
    try:
        matrix = json.loads(body)
    except json.JSONDecodeError as error:
        raise ValueError("shipped-artifact matrix is not valid JSON") from error

    specs = recorded_release_specs(matrix)
    options = {} if verify_options is None else dict(verify_options)
    for spec in specs:
        verify(spec.tag, spec.signer_workflow, **options)
    print(f"Cryptographically reverified {len(specs)} recorded GitHub release(s).")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "release_tag",
        nargs="?",
        help="exact cli/vX.Y.Z or jacsgo/vX.Y.Z tag",
    )
    parser.add_argument(
        "signer_workflow",
        nargs="?",
        help="expected repository workflow identity",
    )
    parser.add_argument(
        "--matrix",
        type=Path,
        help="reverify every published CLI/Go release recorded in this matrix",
    )
    args = parser.parse_args()
    if args.matrix is not None:
        if args.release_tag is not None or args.signer_workflow is not None:
            parser.error("--matrix cannot be combined with release_tag/signer_workflow")
    elif args.release_tag is None or args.signer_workflow is None:
        parser.error("release_tag and signer_workflow are required without --matrix")

    attempts = _positive_integer("JACS_ATTESTATION_VERIFY_ATTEMPTS", 12)
    options = {
        "attempts": attempts,
        "delay_seconds": _non_negative_integer(
            "JACS_ATTESTATION_VERIFY_DELAY_SECONDS", 5
        ),
        "command_timeout_seconds": _positive_integer(
            "JACS_ATTESTATION_COMMAND_TIMEOUT_SECONDS", 60
        ),
        "http_timeout_seconds": _positive_integer(
            "JACS_RELEASE_HTTP_TIMEOUT_SECONDS", 30
        ),
        "metadata_attempts": _positive_integer(
            "JACS_RELEASE_METADATA_ATTEMPTS", attempts
        ),
        "max_asset_bytes": _positive_integer(
            "JACS_RELEASE_MAX_ASSET_BYTES", DEFAULT_MAX_ASSET_BYTES
        ),
        "max_total_bytes": _positive_integer(
            "JACS_RELEASE_MAX_TOTAL_BYTES", DEFAULT_MAX_TOTAL_BYTES
        ),
    }
    try:
        if args.matrix is not None:
            verify_recorded_releases(
                args.matrix,
                verify_options=options,
            )
        else:
            verify_release(args.release_tag, args.signer_workflow, **options)
    except (ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
