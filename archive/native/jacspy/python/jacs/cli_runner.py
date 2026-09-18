"""
CLI launcher for the JACS binary.

Downloads a prebuilt jacs CLI binary on first use and caches it.
If the download fails, prints fallback instructions (cargo install).
"""

import gzip
import hashlib
import os
import platform
import posixpath
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

REPO = "HumanAssisted/JACS"
MAX_REDIRECTS = 5
CONNECT_TIMEOUT_SECONDS = 15.0
TOTAL_TIMEOUT_SECONDS = 60.0
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_CHECKSUM_BYTES = 1024 * 1024
MAX_EXTRACTED_BYTES = 256 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 1024
MAX_TAR_METADATA_BYTES = 2 * 1024 * 1024
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024
DOWNLOAD_CHUNK_BYTES = 64 * 1024
_HTTPS_DOWNLOAD_HOSTS = ("github.com", ".githubusercontent.com")
_HTTP_LOOPBACK_HOSTS = frozenset(("localhost", "127.0.0.1", "::1"))
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_ZIP_EOCD_BYTES = 22
_ZIP_MAX_COMMENT_BYTES = 65535
_ZIP_CENTRAL_DIRECTORY_HEADER_BYTES = 46


def _read_repo_version():
    """Best-effort fallback for source checkouts without installed metadata."""
    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    try:
        contents = pyproject_path.read_text(encoding="utf-8")
    except OSError:
        return None

    match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', contents, re.MULTILINE)
    return match.group(1) if match else None


def _get_version():
    """Read version from the installed package metadata."""
    try:
        from importlib.metadata import version

        return version("jacs")
    except Exception:
        repo_version = _read_repo_version()
        return repo_version or "unknown"


def _linux_libc_family():
    """Return the best available Linux libc family without spawning a process."""
    try:
        libc_name = platform.libc_ver()[0].strip().lower()
    except (AttributeError, OSError):
        libc_name = ""
    if "musl" in libc_name:
        return "musl"

    for variable in ("HOST_GNU_TYPE", "MULTIARCH"):
        configured = str(sysconfig.get_config_var(variable) or "").lower()
        if "musl" in configured:
            return "musl"

    # Some musl Python builds do not expose the libc in either API. Alpine is
    # unambiguously musl and this file is stable across its supported releases.
    if Path("/etc/alpine-release").is_file():
        return "musl"
    return libc_name or "unknown"


def _unsupported_platform_reason():
    if platform.system().lower() == "linux" and _linux_libc_family() == "musl":
        return (
            "No prebuilt JACS CLI asset is published for Linux musl; "
            "build it with cargo install jacs-cli"
        )
    return "No prebuilt JACS CLI asset is published for this OS/architecture"


def _platform_key():
    system = platform.system().lower()
    machine = platform.machine().lower()

    arch_map = {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    arch = arch_map.get(machine)
    if not arch:
        return None

    os_map = {
        "darwin": "darwin",
        "linux": "linux",
        "windows": "windows",
    }
    os_name = os_map.get(system)
    if not os_name:
        return None
    if os_name == "linux" and _linux_libc_family() == "musl":
        return None

    return f"{os_name}-{arch}"


def _cache_dir():
    """Cache directory for the CLI binary."""
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        base = Path(xdg)
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Caches"
    elif platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path.home() / ".cache"
    return base / "jacs" / "bin"


def _bin_name():
    return "jacs-cli.exe" if platform.system() == "Windows" else "jacs-cli"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep redirect policy in this module instead of urllib's permissive default."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_URL_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def _is_allowed_download_url(raw_url):
    """Allow release hosts and exact textual loopback hosts used by local tests."""
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        port = parsed.port
    except (TypeError, ValueError):
        return False

    if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
        return False

    host = parsed.hostname.lower()
    if parsed.scheme == "https":
        if port not in (None, 443):
            return False
        return host == _HTTPS_DOWNLOAD_HOSTS[0] or host.endswith(
            _HTTPS_DOWNLOAD_HOSTS[1]
        )

    # HTTP is intentionally limited to exact textual loopback spellings.  This
    # supports deterministic tests without permitting alternate numeric forms,
    # DNS names that resolve privately, or suffix tricks such as localhost.evil.
    return parsed.scheme == "http" and host in _HTTP_LOOPBACK_HOSTS


def _release_base(version):
    """Return the pinned GitHub release base or an explicitly safe staging URL."""
    canonical = f"https://github.com/{REPO}/releases/download/cli/v{version}"
    configured = os.environ.get("JACS_CLI_RELEASE_BASE_URL")
    if configured is None or configured == "":
        return canonical
    candidate = configured.rstrip("/")
    if not candidate or not _is_allowed_download_url(candidate):
        raise ValueError("Refusing unsafe CLI release base override")
    return candidate


def _url_origin(raw_url):
    """Return a normalized (scheme, host, port) tuple for an already-valid URL."""
    parsed = urllib.parse.urlsplit(raw_url)
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    return (scheme, parsed.hostname.lower(), parsed.port or default_port)


def _is_allowed_redirect(initial_url, redirect_url):
    """Keep redirects in the initial URL's remote or loopback trust context."""
    if not _is_allowed_download_url(redirect_url):
        return False

    initial = urllib.parse.urlsplit(initial_url)
    initial_host = initial.hostname.lower()
    initial_is_loopback = (
        initial.scheme.lower() == "http" and initial_host in _HTTP_LOOPBACK_HOSTS
    )
    if initial_is_loopback:
        return _url_origin(initial_url) == _url_origin(redirect_url)

    redirected = urllib.parse.urlsplit(redirect_url)
    return redirected.scheme.lower() == "https"


def _open_url(url, timeout):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": f"jacs-python/{_get_version()}"},
    )
    try:
        return _URL_OPENER.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        # With automatic redirects disabled, urllib represents 3xx responses as
        # HTTPError instances.  Return them so the bounded redirect loop can
        # inspect their Location header; all other statuses stay errors.
        if 300 <= error.code < 400:
            return error
        raise


def _response_status(response):
    status = getattr(response, "status", None)
    if status is None:
        status = getattr(response, "code", None)
    if status is None and hasattr(response, "getcode"):
        status = response.getcode()
    return status


def _header_values(headers, name):
    if hasattr(headers, "get_all"):
        values = headers.get_all(name)
        if values:
            return values
    value = headers.get(name) if headers is not None else None
    return [] if value is None else [value]


def _declared_content_length(headers):
    raw_values = []
    for value in _header_values(headers, "Content-Length"):
        raw_values.extend(part.strip() for part in str(value).split(","))
    if not raw_values:
        return None

    lengths = []
    for value in raw_values:
        if not re.fullmatch(r"[0-9]+", value):
            raise ValueError("Invalid Content-Length on CLI download")
        lengths.append(int(value))
    if len(set(lengths)) != 1:
        raise ValueError("Conflicting Content-Length values on CLI download")
    return lengths[0]


def _remaining_seconds(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("CLI download exceeded total timeout")
    return remaining


def _download(
    url,
    dest,
    max_bytes=MAX_ARCHIVE_BYTES,
    connect_timeout=CONNECT_TIMEOUT_SECONDS,
    total_timeout=TOTAL_TIMEOUT_SECONDS,
):
    """Download an allow-listed URL with bounded redirects, time, and bytes."""
    if max_bytes <= 0 or connect_timeout <= 0 or total_timeout <= 0:
        raise ValueError("CLI download limits must be positive")

    destination = Path(dest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + total_timeout
    initial_url = str(url)
    current_url = initial_url
    redirects = 0
    response = None
    temporary_path = None

    try:
        while True:
            if not _is_allowed_download_url(current_url):
                # Do not echo attacker-controlled userinfo or redirect contents;
                # this exception is surfaced by ensure_cli on stderr.
                raise ValueError("Refusing unsafe CLI download URL")

            remaining = _remaining_seconds(deadline)
            response = _open_url(current_url, min(connect_timeout, remaining))
            status_code = _response_status(response)
            headers = getattr(response, "headers", {})

            if status_code is not None and 300 <= status_code < 400:
                location = headers.get("Location") if headers is not None else None
                response.close()
                response = None
                if not location:
                    raise RuntimeError(
                        f"CLI download redirect omitted Location: {current_url}"
                    )
                if redirects >= MAX_REDIRECTS:
                    raise RuntimeError(
                        f"CLI download exceeded {MAX_REDIRECTS} redirects"
                    )
                redirected_url = urllib.parse.urljoin(current_url, location)
                if not _is_allowed_redirect(initial_url, redirected_url):
                    raise ValueError(
                        "Refusing unsafe CLI download URL: redirect context change"
                    )
                current_url = redirected_url
                redirects += 1
                continue

            if status_code != 200:
                raise RuntimeError(f"HTTP {status_code} for {current_url}")

            declared_length = _declared_content_length(headers)
            if declared_length is not None and declared_length > max_bytes:
                raise ValueError(f"CLI download exceeded {max_bytes} byte limit")

            fd, temporary_name = tempfile.mkstemp(
                prefix=f".{destination.name}.download-", dir=destination.parent
            )
            temporary_path = Path(temporary_name)
            received = 0
            with os.fdopen(fd, "wb") as output:
                while True:
                    _remaining_seconds(deadline)
                    try:
                        chunk = response.read(DOWNLOAD_CHUNK_BYTES)
                    except (socket.timeout, TimeoutError) as error:
                        raise TimeoutError("CLI download timed out while reading") from error
                    _remaining_seconds(deadline)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > max_bytes:
                        raise ValueError(
                            f"CLI download exceeded {max_bytes} byte limit"
                        )
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())

            if declared_length is not None and received != declared_length:
                raise ValueError(
                    "CLI download length did not match declared Content-Length"
                )
            os.replace(temporary_path, destination)
            temporary_path = None
            return current_url
    finally:
        if response is not None:
            response.close()
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


class _ConflictingChecksumError(ValueError):
    """A checksum source named the same asset with different digests."""


def _download_checksum(release_base, asset_url, destination):
    """Download and validate the aggregate checksum, with per-asset fallback."""
    asset_name = PurePosixPath(urllib.parse.urlsplit(asset_url).path).name
    if not asset_name:
        raise ValueError("CLI asset URL did not contain a filename")
    candidates = [
        (f"{release_base}/sha256sums.txt", False),
        (f"{asset_url}.sha256", True),
    ]
    failures = []
    for candidate, allow_bare_digest in candidates:
        try:
            _download(candidate, destination, max_bytes=MAX_CHECKSUM_BYTES)
            _read_expected_sha256(
                destination, asset_name, allow_bare_digest=allow_bare_digest
            )
            return candidate
        except _ConflictingChecksumError:
            Path(destination).unlink(missing_ok=True)
            raise
        except Exception as error:
            failures.append(f"{candidate}: {error}")
            try:
                Path(destination).unlink(missing_ok=True)
            except OSError:
                pass
    raise RuntimeError("; ".join(failures))


def _sha256_file(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _read_expected_sha256(checksum_path, asset_name, allow_bare_digest=True):
    checksum_text = Path(checksum_path).read_text(encoding="utf-8").strip()
    if not checksum_text:
        raise ValueError(f"Checksum file was empty: {checksum_path}")

    lines = [line.strip() for line in checksum_text.splitlines() if line.strip()]
    matching_digests = []
    for line in lines:
        match = re.match(r"^([a-fA-F0-9]{64})\s+\*?(.+)$", line)
        if match:
            digest = match.group(1).lower()
            filename = os.path.basename(match.group(2).strip())
            if filename == asset_name:
                matching_digests.append(digest)
            continue

        match = re.match(r"^SHA256\s*\((.+)\)\s*=\s*([a-fA-F0-9]{64})$", line, re.IGNORECASE)
        if match:
            filename = os.path.basename(match.group(1).strip())
            digest = match.group(2).lower()
            if filename == asset_name:
                matching_digests.append(digest)

    unique_digests = set(matching_digests)
    if len(unique_digests) > 1:
        raise _ConflictingChecksumError(
            f"Conflicting checksums for {asset_name} in {checksum_path}"
        )
    if unique_digests:
        return next(iter(unique_digests))

    if allow_bare_digest and len(lines) == 1:
        match = re.fullmatch(r"[a-fA-F0-9]{64}", lines[0])
        if match:
            return match.group(0).lower()

    raise ValueError(f"Checksum for {asset_name} not found in {checksum_path}")


def _validate_archive_member(name):
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ValueError(f"Unsafe archive member path: {name}")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        raise ValueError(f"Unsafe archive member path: {name}")
    if re.match(r"^[A-Za-z]:", normalized):
        raise ValueError(f"Unsafe archive member path: {name}")
    if ".." in PurePosixPath(normalized).parts:
        raise ValueError(f"Unsafe archive member path: {name}")
    normalized = posixpath.normpath(normalized)
    member_path = PurePosixPath(normalized)
    if normalized in ("", ".", "..") or ".." in member_path.parts:
        raise ValueError(f"Unsafe archive member path: {name}")
    return normalized


def _check_archive_size(archive_path):
    archive_stat = os.lstat(archive_path)
    if not stat.S_ISREG(archive_stat.st_mode):
        raise ValueError("CLI archive must be a regular file")
    if archive_stat.st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"CLI archive exceeded {MAX_ARCHIVE_BYTES} byte limit")


def _find_zip_eocd(archive_path):
    """Find a classic ZIP EOCD without asking zipfile to allocate its index."""
    archive_size = os.lstat(archive_path).st_size
    tail_size = min(archive_size, _ZIP_EOCD_BYTES + _ZIP_MAX_COMMENT_BYTES)
    with open(archive_path, "rb") as archive:
        archive.seek(archive_size - tail_size)
        tail = archive.read(tail_size)

    index = tail.rfind(_ZIP_EOCD_SIGNATURE)
    while index >= 0:
        if len(tail) - index >= _ZIP_EOCD_BYTES:
            fields = struct.unpack_from("<4s4H2IH", tail, index)
            comment_length = fields[-1]
            if index + _ZIP_EOCD_BYTES + comment_length == len(tail):
                return archive_size - tail_size + index, fields
        index = tail.rfind(_ZIP_EOCD_SIGNATURE, 0, index)
    raise ValueError("CLI ZIP archive omitted a valid end-of-central-directory record")


def _preflight_zip_archive(archive_path):
    """Bound and structurally count ZIP metadata before ZipFile builds objects."""
    eocd_offset, fields = _find_zip_eocd(archive_path)
    (
        _signature,
        disk_number,
        central_directory_disk,
        disk_entries,
        total_entries,
        central_directory_size,
        central_directory_offset,
        _comment_length,
    ) = fields

    if disk_number != 0 or central_directory_disk != 0 or disk_entries != total_entries:
        raise ValueError("Multi-disk CLI ZIP archives are not supported")
    if (
        total_entries == 0xFFFF
        or central_directory_size == 0xFFFFFFFF
        or central_directory_offset == 0xFFFFFFFF
    ):
        raise ValueError("ZIP64 CLI archives are not supported")
    if total_entries > MAX_ARCHIVE_MEMBERS:
        raise ValueError(f"Archive exceeded {MAX_ARCHIVE_MEMBERS} member limit")
    if central_directory_size > MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        raise ValueError(
            "Archive central directory exceeded "
            f"{MAX_ZIP_CENTRAL_DIRECTORY_BYTES} byte limit"
        )
    if central_directory_offset + central_directory_size != eocd_offset:
        raise ValueError("CLI ZIP central directory bounds were inconsistent")

    actual_entries = 0
    remaining = central_directory_size
    with open(archive_path, "rb") as archive:
        archive.seek(central_directory_offset)
        while remaining:
            if remaining < _ZIP_CENTRAL_DIRECTORY_HEADER_BYTES:
                raise ValueError("CLI ZIP central directory was truncated")
            header = archive.read(_ZIP_CENTRAL_DIRECTORY_HEADER_BYTES)
            if len(header) != _ZIP_CENTRAL_DIRECTORY_HEADER_BYTES:
                raise ValueError("CLI ZIP central directory was truncated")
            if header[:4] != _ZIP_CENTRAL_DIRECTORY_SIGNATURE:
                raise ValueError("CLI ZIP central directory contained an invalid record")

            name_length, extra_length, comment_length = struct.unpack_from(
                "<3H", header, 28
            )
            variable_length = name_length + extra_length + comment_length
            record_length = _ZIP_CENTRAL_DIRECTORY_HEADER_BYTES + variable_length
            if record_length > remaining:
                raise ValueError("CLI ZIP central directory record exceeded its bounds")

            archive.seek(variable_length, os.SEEK_CUR)
            remaining -= record_length
            actual_entries += 1
            if actual_entries > MAX_ARCHIVE_MEMBERS:
                raise ValueError(
                    f"Archive exceeded {MAX_ARCHIVE_MEMBERS} member limit"
                )

    if actual_entries != total_entries:
        raise ValueError("CLI ZIP member count did not match its directory")


def _copy_limited(source, destination, expected_size):
    if expected_size <= 0 or expected_size > MAX_BINARY_BYTES:
        raise ValueError(f"CLI binary exceeded {MAX_BINARY_BYTES} byte limit")
    copied = 0
    while True:
        chunk = source.read(min(DOWNLOAD_CHUNK_BYTES, MAX_BINARY_BYTES - copied + 1))
        if not chunk:
            break
        copied += len(chunk)
        if copied > MAX_BINARY_BYTES or copied > expected_size:
            raise ValueError(f"CLI binary exceeded {MAX_BINARY_BYTES} byte limit")
        destination.write(chunk)
    if copied != expected_size:
        raise ValueError("CLI binary size did not match archive metadata")


class _BoundedDecompressedReader:
    """Bound gzip expansion, including hidden PAX/GNU tar metadata records."""

    def __init__(self, source, limit):
        self._source = source
        self._limit = limit
        self._read = 0

    def read(self, size=-1):
        remaining_with_probe = self._limit - self._read + 1
        if size is None or size < 0:
            size = remaining_with_probe
        else:
            size = min(size, remaining_with_probe)
        data = self._source.read(size)
        self._read += len(data)
        if self._read > self._limit:
            raise ValueError(
                f"Archive exceeded {MAX_EXTRACTED_BYTES} byte expansion limit"
            )
        return data


def _validate_zip_member(member):
    normalized = _validate_archive_member(member.filename)
    if member.flag_bits & 0x1:
        raise ValueError(f"Encrypted archive member is not allowed: {member.filename}")
    mode = member.external_attr >> 16
    member_type = stat.S_IFMT(mode)
    if member_type == stat.S_IFLNK:
        raise ValueError(f"Archive symlink is not allowed: {member.filename}")
    if not member.is_dir() and member_type not in (0, stat.S_IFREG):
        raise ValueError(f"Unsupported archive member type: {member.filename}")
    return normalized


def _extract_archive_binary(archive_path, dest_dir, binary_name, is_windows):
    _check_archive_size(archive_path)
    dest_path = Path(dest_dir) / binary_name
    total_uncompressed = 0

    if is_windows:
        import zipfile

        _preflight_zip_archive(archive_path)
        with zipfile.ZipFile(archive_path, "r") as zf:
            candidate = None
            members = zf.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ValueError(
                    f"Archive exceeded {MAX_ARCHIVE_MEMBERS} member limit"
                )
            for member in members:
                normalized = _validate_zip_member(member)
                if member.is_dir():
                    continue
                if member.file_size < 0:
                    raise ValueError("Archive member had a negative size")
                total_uncompressed += member.file_size
                if total_uncompressed > MAX_EXTRACTED_BYTES:
                    raise ValueError(
                        f"Archive exceeded {MAX_EXTRACTED_BYTES} byte expansion limit"
                    )
                if PurePosixPath(normalized).name == binary_name:
                    if candidate is not None:
                        raise ValueError(f"Archive contained multiple {binary_name} entries")
                    candidate = member
            if candidate is None:
                raise ValueError("Binary not found in archive.")
            try:
                with zf.open(candidate, "r") as src, open(dest_path, "xb") as dst:
                    _copy_limited(src, dst, candidate.file_size)
            except Exception:
                dest_path.unlink(missing_ok=True)
                raise
    else:
        candidate_found = False
        try:
            with open(archive_path, "rb") as archive_file:
                with gzip.GzipFile(fileobj=archive_file, mode="rb") as decompressed:
                    bounded = _BoundedDecompressedReader(
                        decompressed, MAX_EXTRACTED_BYTES + MAX_TAR_METADATA_BYTES
                    )
                    # Streaming mode ensures gzip expansion is consumed only
                    # through the bounded reader.  The candidate is staged in
                    # the private temporary directory and deleted if any later
                    # member invalidates the archive.
                    with tarfile.open(fileobj=bounded, mode="r|") as tf:
                        member_count = 0
                        for member in tf:
                            member_count += 1
                            if member_count > MAX_ARCHIVE_MEMBERS:
                                raise ValueError(
                                    f"Archive exceeded {MAX_ARCHIVE_MEMBERS} member limit"
                                )
                            normalized = _validate_archive_member(member.name)
                            if member.issym() or member.islnk():
                                raise ValueError(
                                    f"Archive link is not allowed: {member.name}"
                                )
                            if member.isdir():
                                continue
                            if not member.isfile():
                                raise ValueError(
                                    f"Unsupported archive member type: {member.name}"
                                )
                            if member.size < 0:
                                raise ValueError("Archive member had a negative size")
                            total_uncompressed += member.size
                            if total_uncompressed > MAX_EXTRACTED_BYTES:
                                raise ValueError(
                                    f"Archive exceeded {MAX_EXTRACTED_BYTES} byte expansion limit"
                                )
                            if PurePosixPath(normalized).name != binary_name:
                                continue
                            if candidate_found:
                                raise ValueError(
                                    f"Archive contained multiple {binary_name} entries"
                                )
                            candidate_found = True
                            extracted = tf.extractfile(member)
                            if extracted is None:
                                raise ValueError(
                                    "Binary could not be extracted from archive."
                                )
                            with extracted, open(dest_path, "xb") as dst:
                                _copy_limited(extracted, dst, member.size)
            if not candidate_found:
                raise ValueError("Binary not found in archive.")
        except Exception:
            dest_path.unlink(missing_ok=True)
            raise

    return str(dest_path)


def _owned_by_current_user(file_stat):
    return not hasattr(os, "geteuid") or file_stat.st_uid == os.geteuid()


def _absolute_lexical_path(path):
    """Return an absolute path without resolving any symlink component."""
    return Path(os.path.abspath(os.fspath(path)))


def _path_is_at_or_below(root, candidate):
    root_string = os.path.normcase(os.fspath(root))
    candidate_string = os.path.normcase(os.fspath(candidate))
    try:
        return os.path.commonpath((root_string, candidate_string)) == root_string
    except ValueError:
        return False


def _validate_cache_directory_stat(directory_stat, *, protected):
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if getattr(directory_stat, "st_file_attributes", 0) & reparse_attribute:
        raise ValueError("CLI cache path contained a reparse-point component")
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise ValueError("CLI cache path contained a non-directory component")
    if os.name == "nt":
        return

    writable_by_others = directory_stat.st_mode & (
        stat.S_IWGRP | stat.S_IWOTH
    )
    if protected:
        if not _owned_by_current_user(directory_stat):
            raise PermissionError("CLI cache directory is owned by another user")
        if writable_by_others:
            raise PermissionError("CLI cache directory is writable by another user")
        return

    # System-owned ancestors such as / and /private are safe when they are not
    # writable. A sticky system temporary directory is also a valid ancestor,
    # but it may not itself be the configured cache root.
    owner = getattr(directory_stat, "st_uid", None)
    sticky_system_directory = (
        owner == 0
        and bool(directory_stat.st_mode & stat.S_ISVTX)
        and bool(directory_stat.st_mode & stat.S_IWOTH)
    )
    if writable_by_others and not sticky_system_directory:
        raise PermissionError("CLI cache ancestor is writable by another user")
    if not _owned_by_current_user(directory_stat) and owner != 0:
        raise PermissionError("CLI cache ancestor is owned by another user")


def _supports_descriptor_anchored_directories():
    required = (os.open, os.mkdir, os.stat, os.unlink, os.link)
    return (
        os.name != "nt"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and all(operation in os.supports_dir_fd for operation in required)
    )


def _open_safe_cache_directory(cache_root, target, *, create):
    """Open a validated cache directory without following path symlinks.

    On POSIX this returns an open descriptor for ``target``. The fallback
    returns ``None`` after performing the strongest lstat-based checks the
    platform exposes.
    """
    root = _absolute_lexical_path(cache_root)
    target = _absolute_lexical_path(target)
    if not _path_is_at_or_below(root, target):
        raise ValueError("CLI cache target escaped its configured root")

    if not _supports_descriptor_anchored_directories():
        anchor = Path(target.anchor)
        current = anchor
        _validate_cache_directory_stat(
            os.lstat(current), protected=_path_is_at_or_below(root, current)
        )
        for component in target.parts[1:]:
            current /= component
            try:
                component_stat = os.lstat(current)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(current, mode=0o700)
                except FileExistsError:
                    pass
                component_stat = os.lstat(current)
            _validate_cache_directory_stat(
                component_stat, protected=_path_is_at_or_below(root, current)
            )
        return None

    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(target.anchor, directory_flags)
    try:
        current = Path(target.anchor)
        _validate_cache_directory_stat(
            os.fstat(descriptor), protected=_path_is_at_or_below(root, current)
        )
        for component in target.parts[1:]:
            current /= component
            try:
                child_descriptor = os.open(
                    component, directory_flags, dir_fd=descriptor
                )
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    # Another process created the component. Opening and
                    # validating that winner below is the convergence point.
                    pass
                child_descriptor = os.open(
                    component, directory_flags, dir_fd=descriptor
                )
            try:
                _validate_cache_directory_stat(
                    os.fstat(child_descriptor),
                    protected=_path_is_at_or_below(root, current),
                )
            except Exception:
                os.close(child_descriptor)
                raise
            os.close(descriptor)
            descriptor = child_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _ensure_safe_cache_directory(cache_root, target):
    descriptor = _open_safe_cache_directory(cache_root, target, create=True)
    if descriptor is not None:
        os.close(descriptor)


def _safe_cache_directory(path):
    try:
        descriptor = _open_safe_cache_directory(path, path, create=False)
    except (OSError, ValueError):
        return False
    if descriptor is not None:
        os.close(descriptor)
    return True


def _cached_binary_stat_is_safe(cached_stat):
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        getattr(cached_stat, "st_file_attributes", 0) & reparse_attribute
        or not stat.S_ISREG(cached_stat.st_mode)
        or cached_stat.st_size <= 0
        or not _owned_by_current_user(cached_stat)
    ):
        return False
    if os.name == "nt":
        return True
    return not cached_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and bool(
        cached_stat.st_mode & stat.S_IXUSR
    )


def _safe_cached_binary(path, cache_root=None):
    path = _absolute_lexical_path(path)
    root = _absolute_lexical_path(cache_root or path.parent)
    if not _path_is_at_or_below(root, path):
        return False

    try:
        parent_descriptor = _open_safe_cache_directory(
            root, path.parent, create=False
        )
    except (OSError, ValueError):
        return False

    if parent_descriptor is None:
        try:
            return _cached_binary_stat_is_safe(os.lstat(path))
        except OSError:
            return False

    binary_descriptor = None
    try:
        binary_descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        return _cached_binary_stat_is_safe(os.fstat(binary_descriptor))
    except OSError:
        return False
    finally:
        if binary_descriptor is not None:
            os.close(binary_descriptor)
        os.close(parent_descriptor)


def _exclusive_staging_file(parent_descriptor, parent_path, destination_name):
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _ in range(100):
        name = f".{destination_name}.install-{secrets.token_hex(8)}"
        try:
            if parent_descriptor is None:
                return os.open(parent_path / name, flags, 0o600), name
            return os.open(name, flags, 0o600, dir_fd=parent_descriptor), name
        except FileExistsError:
            continue
    raise FileExistsError("Could not allocate an exclusive CLI staging path")


def _install_binary_atomically(
    source, destination, is_windows, cache_root=None
):
    destination = _absolute_lexical_path(destination)
    root = _absolute_lexical_path(cache_root or destination.parent)
    if not _path_is_at_or_below(root, destination):
        raise ValueError("CLI install destination escaped its configured root")

    parent_descriptor = _open_safe_cache_directory(
        root, destination.parent, create=False
    )
    source_descriptor = None
    staging_descriptor = None
    staging_name = None
    try:
        source_flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        source_descriptor = os.open(source, source_flags)
        source_stat = os.fstat(source_descriptor)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError("Extracted CLI binary must be a regular file")

        staging_descriptor, staging_name = _exclusive_staging_file(
            parent_descriptor, destination.parent, destination.name
        )
        source_file = os.fdopen(source_descriptor, "rb")
        source_descriptor = None
        staging_file = os.fdopen(staging_descriptor, "wb")
        staging_descriptor = None
        with source_file as src, staging_file as dst:
            _copy_limited(src, dst, source_stat.st_size)
            dst.flush()
            os.fsync(dst.fileno())
            if not is_windows and hasattr(os, "fchmod"):
                os.fchmod(dst.fileno(), 0o700)

        try:
            if parent_descriptor is None:
                staging_path = destination.parent / staging_name
                if os.name == "nt":
                    # Windows rename fails when the destination already exists,
                    # giving the same atomic no-replace contract as link(2).
                    os.rename(staging_path, destination)
                else:
                    os.link(
                        staging_path,
                        destination,
                        follow_symlinks=False,
                    )
            else:
                os.link(
                    staging_name,
                    destination.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
        except FileExistsError as error:
            raise FileExistsError(
                "Refusing to replace an existing CLI install path"
            ) from error
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if staging_name is not None:
            try:
                if parent_descriptor is None:
                    os.unlink(destination.parent / staging_name)
                else:
                    os.unlink(staging_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def ensure_cli():
    """Download the CLI binary if not already cached. Returns the path."""
    ver = _get_version()
    if ver == "unknown":
        print("[jacs] Could not determine package version for CLI download.", file=sys.stderr)
        return None
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", ver):
        print("[jacs] Refusing unsafe package version metadata", file=sys.stderr)
        return None
    try:
        release_base = _release_base(ver)
    except ValueError as error:
        print(f"[jacs] {error}", file=sys.stderr)
        return None

    key = _platform_key()
    if not key:
        print(f"[jacs] {_unsupported_platform_reason()}", file=sys.stderr)
        return None
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", key):
        print("[jacs] Refusing unsafe platform metadata", file=sys.stderr)
        return None

    # Cache by exact package version and executable target. An older wheel or
    # another machine sharing this home directory cannot supply the binary.
    cache_root = _absolute_lexical_path(_cache_dir())
    version_cache = cache_root / ver
    cache = version_cache / key
    bin_path = cache / _bin_name()
    try:
        _ensure_safe_cache_directory(cache_root, cache)
    except (OSError, ValueError) as error:
        print(
            f"[jacs] Refusing unsafe CLI cache hierarchy: {error}",
            file=sys.stderr,
        )
        return None
    if os.path.lexists(bin_path):
        if _safe_cached_binary(bin_path, cache_root):
            return str(bin_path)
        print(f"[jacs] Refusing unsafe cached CLI path: {bin_path}", file=sys.stderr)
        return None

    is_windows = platform.system() == "Windows"
    ext = "zip" if is_windows else "tar.gz"
    asset = f"jacs-cli-{ver}-{key}.{ext}"
    url = f"{release_base}/{asset}"

    with tempfile.TemporaryDirectory(prefix="jacs-cli-") as tmp:
        archive_path = os.path.join(tmp, asset)
        checksum_path = os.path.join(tmp, f"{asset}.sha256")
        try:
            checksum_url = _download_checksum(release_base, url, checksum_path)
            print(
                f"[jacs] Downloaded checksum for pinned version {ver} from {checksum_url}",
                file=sys.stderr,
            )
            print(f"[jacs] Downloading CLI binary from {url}", file=sys.stderr)
            _download(url, archive_path, max_bytes=MAX_ARCHIVE_BYTES)
            expected_sha256 = _read_expected_sha256(checksum_path, asset)
            actual_sha256 = _sha256_file(archive_path)
            if expected_sha256 != actual_sha256:
                print(
                    f"[jacs] Checksum mismatch for {asset}: expected {expected_sha256}, got {actual_sha256}",
                    file=sys.stderr,
                )
                return None
        except Exception as e:
            print(f"[jacs] Download failed: {e}", file=sys.stderr)
            return None

        try:
            src = _extract_archive_binary(archive_path, tmp, _bin_name(), is_windows)
        except Exception as e:
            print(f"[jacs] Could not extract CLI binary: {e}", file=sys.stderr)
            return None

        try:
            _install_binary_atomically(
                src, bin_path, is_windows, cache_root=cache_root
            )
        except Exception as e:
            print(f"[jacs] Could not cache CLI binary: {e}", file=sys.stderr)
            return None

    print(f"[jacs] CLI binary cached at {bin_path}", file=sys.stderr)
    return str(bin_path)


def _cargo_binary_hint():
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).expanduser()
    binary_name = "jacs.exe" if platform.system() == "Windows" else "jacs"
    binary_path = str(cargo_home / "bin" / binary_name)
    return f'"{binary_path}"' if " " in binary_path else binary_path


def main():
    """Entry point for `jacs` CLI command via pip."""
    cli_path = ensure_cli()
    if cli_path is None:
        print(
            "Could not download the JACS CLI binary for your platform.\n"
            "Install it manually:\n"
            "  cargo install jacs-cli\n"
            "A Python virtual environment may keep this shim first on PATH; "
            "invoke Cargo's binary explicitly:\n"
            f"  {_cargo_binary_hint()}\n"
            f"  OR download from https://github.com/{REPO}/releases",
            file=sys.stderr,
        )
        sys.exit(1)

    result = subprocess.run([cli_path] + sys.argv[1:])
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
