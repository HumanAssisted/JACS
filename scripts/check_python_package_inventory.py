#!/usr/bin/env python3
"""Validate that Python release archives contain only approved legal artifacts."""

from __future__ import annotations

import argparse
from collections import Counter
import gzip
import os
from pathlib import Path
import stat
import struct
import sys
import tarfile
from typing import BinaryIO
import unicodedata
import zipfile

DEBUG_TRANSCRIPT = "jacs/src/crypt/debug.txt"
LICENSE_FILENAME_ROOTS = ("COPYING", "LICENCE", "LICENSE")
NOTICE_FILENAME = "THIRD-PARTY-NOTICES"
NOTICE_FILENAME_ROOTS = (
    "NOTICE",
    "NOTICES",
    NOTICE_FILENAME,
    "THIRD_PARTY_NOTICES",
)
WINDOWS_RESERVED_DEVICE_STEMS = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
)

# These bounds are deliberately above current maturin wheel/sdist sizes while
# preventing archive metadata from authorizing unbounded decompression work.
MAX_ARCHIVE_ENTRIES = 10_000
MAX_ENTRY_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_UNCOMPRESSED_RATIO = 200
MAX_ARCHIVE_METADATA_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_PATH_BYTES = 4 * 1024
MAX_TAR_TRAILING_PADDING_BYTES = 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024

TAR_BLOCK_BYTES = 512
TAR_METADATA_TYPES = frozenset({b"g", b"K", b"L", b"x", b"X"})
TAR_PAX_METADATA_TYPES = frozenset({b"g", b"x", b"X"})
TAR_GNU_SPARSE_TYPE = b"S"
ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
ZIP_LOCAL_SIGNATURE = b"PK\x03\x04"
ZIP_EOCD_BYTES = 22
ZIP_MAX_COMMENT_BYTES = (1 << 16) - 1
ZIP_CENTRAL_HEADER_BYTES = 46


class _ArchiveRejected(ValueError):
    """A stable, content-free reason an archive exceeded a safety bound."""


class _LegalEntry:
    __slots__ = ("name", "matches")

    def __init__(self, name: str, matches: bool | None) -> None:
        self.name = name
        self.matches = matches


class _ArchiveInventory:
    __slots__ = (
        "names",
        "normalized_names",
        "licenses",
        "notices",
        "errors",
    )

    def __init__(self) -> None:
        self.names: list[str] = []
        self.normalized_names: list[str | None] = []
        self.licenses: list[_LegalEntry] = []
        self.notices: list[_LegalEntry] = []
        self.errors: list[str] = []


def _normalize_archive_path(
    name: str, *, is_directory: bool
) -> tuple[str | None, list[str]]:
    """Return a best-effort canonical path plus every rejection reason."""

    issues: list[str] = []
    if len(name.encode("utf-8", "surrogatepass")) > MAX_ARCHIVE_PATH_BYTES:
        issues.append(f"path exceeds {MAX_ARCHIVE_PATH_BYTES} bytes")
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in name):
        issues.append("control characters are not allowed")
    if "\\" in name:
        issues.append("backslash separators are not allowed")

    working = name.replace("\\", "/")
    if working.startswith("/"):
        issues.append("absolute paths are not allowed")
    if len(working) >= 2 and working[0].isalpha() and working[1] == ":":
        issues.append("Windows drive paths are not allowed")
    if is_directory and working.endswith("/"):
        working = working[:-1]

    normalized_components: list[str] = []
    for component in working.split("/"):
        if component == "":
            issues.append("empty path components are not allowed")
            continue
        if component == ".":
            issues.append("dot path components are not allowed")
            continue
        if component == "..":
            issues.append("parent path components are not allowed")
            if normalized_components:
                normalized_components.pop()
            continue

        windows_component = unicodedata.normalize("NFC", component)
        if ":" in windows_component:
            issues.append("colon/alternate data streams are not allowed")
            windows_component = windows_component.split(":", 1)[0]
        if windows_component.endswith((".", " ")):
            issues.append("trailing dots or spaces are not allowed")
        windows_component = windows_component.rstrip(". ")
        if not windows_component:
            issues.append("empty path components after Windows normalization")
            continue
        reserved_stem = windows_component.split(".", 1)[0].casefold()
        if reserved_stem in WINDOWS_RESERVED_DEVICE_STEMS:
            issues.append("Windows reserved device names are not allowed")
        normalized_components.append(
            unicodedata.normalize("NFC", windows_component.casefold())
        )

    normalized = "/".join(normalized_components)
    if not normalized:
        issues.append("empty archive paths are not allowed")

    # Keep one stable instance of each reason without losing diagnostic order.
    issues = list(dict.fromkeys(issues))
    return (normalized or None), issues


def _record_archive_path(
    inventory: _ArchiveInventory, name: str, *, is_directory: bool
) -> str | None:
    normalized, issues = _normalize_archive_path(name, is_directory=is_directory)
    inventory.names.append(name)
    inventory.normalized_names.append(normalized)
    if issues:
        inventory.errors.append(f"unsafe archive path {name!r}: " + ", ".join(issues))
    return normalized


def _basename(name: str) -> str:
    """Return an archive basename independent of host path conventions."""

    return name.replace("\\", "/").rsplit("/", 1)[-1].upper()


def _legal_kind(name: str) -> str | None:
    basename = _basename(name)
    if any(
        basename == root or basename.startswith((f"{root}.", f"{root}-", f"{root}_"))
        for root in LICENSE_FILENAME_ROOTS
    ):
        return "license"
    if any(
        basename == root or basename.startswith((f"{root}.", f"{root}-", f"{root}_"))
        for root in NOTICE_FILENAME_ROOTS
    ):
        return "notice"
    return None


def _expected_legal_bytes(
    kind: str | None, canonical_license: bytes, canonical_notices: bytes
) -> bytes | None:
    if kind == "license":
        return canonical_license
    if kind == "notice":
        return canonical_notices
    return None


def _record_legal_entry(
    inventory: _ArchiveInventory,
    name: str,
    kind: str | None,
    matches: bool | None,
) -> None:
    if kind is None:
        return
    entry = _LegalEntry(name=name, matches=matches)
    if kind == "license":
        inventory.licenses.append(entry)
    else:
        inventory.notices.append(entry)


def _check_entry_metadata(name: str, size: int, total: int) -> int:
    if size < 0:
        raise _ArchiveRejected(f"archive entry has a negative size: {name}")
    if size > MAX_ENTRY_UNCOMPRESSED_BYTES:
        raise _ArchiveRejected(
            "archive entry exceeds "
            f"{MAX_ENTRY_UNCOMPRESSED_BYTES} uncompressed bytes: "
            f"{name} ({size} bytes)"
        )
    new_total = total + size
    if new_total > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise _ArchiveRejected(
            f"archive exceeds {MAX_TOTAL_UNCOMPRESSED_BYTES} total uncompressed bytes"
        )
    return new_total


def _check_ratio(uncompressed: int, compressed: int, location: str) -> None:
    if uncompressed == 0:
        return
    if compressed <= 0 or uncompressed > compressed * MAX_UNCOMPRESSED_RATIO:
        raise _ArchiveRejected(
            "archive uncompressed-to-compressed ratio exceeds "
            f"{MAX_UNCOMPRESSED_RATIO}:1 at {location}"
        )


def _read_exact(stream: BinaryIO, size: int, description: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise _ArchiveRejected(f"truncated {description}")
    return data


def _discard_exact(stream: BinaryIO, size: int, description: str) -> None:
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, READ_CHUNK_BYTES))
        if not chunk:
            raise _ArchiveRejected(f"truncated {description}")
        remaining -= len(chunk)


def _validate_tar_trailing_padding(stream: BinaryIO) -> None:
    """Allow bounded record padding, but no hidden members after TAR EOF."""

    trailing_bytes = 0
    while True:
        chunk = stream.read(READ_CHUNK_BYTES)
        if not chunk:
            return
        trailing_bytes += len(chunk)
        if trailing_bytes > MAX_TAR_TRAILING_PADDING_BYTES:
            raise _ArchiveRejected(
                "TAR trailing padding exceeds "
                f"{MAX_TAR_TRAILING_PADDING_BYTES} bytes"
            )
        if chunk.strip(b"\0"):
            raise _ArchiveRejected("non-zero TAR data follows its end marker")


def _validate_pax_metadata(payload: bytes) -> None:
    """Parse bounded PAX records and reject every modern GNU sparse form."""

    offset = 0
    while offset < len(payload):
        separator = payload.find(b" ", offset)
        if separator < 0 or separator - offset > 20:
            raise _ArchiveRejected("invalid PAX metadata record length")
        encoded_length = payload[offset:separator]
        if not encoded_length or not encoded_length.isdigit():
            raise _ArchiveRejected("invalid PAX metadata record length")
        record_length = int(encoded_length)
        record_end = offset + record_length
        if record_end <= separator + 1 or record_end > len(payload):
            raise _ArchiveRejected("PAX metadata record exceeds its bounds")

        record = payload[separator + 1 : record_end]
        if not record.endswith(b"\n"):
            raise _ArchiveRejected("PAX metadata record is missing its terminator")
        key, delimiter, _value = record[:-1].partition(b"=")
        if not delimiter or not key:
            raise _ArchiveRejected("invalid PAX metadata key/value record")
        if key.startswith(b"GNU.sparse."):
            raise _ArchiveRejected("GNU sparse PAX metadata is not supported")
        offset = record_end


def _preflight_tar(stream: BinaryIO, compressed_size: int) -> None:
    """Bound raw TAR/PAX/GNU records before tarfile parses their payloads."""

    declared_total = 0
    metadata_total = 0
    entry_count = 0
    zero_blocks = 0

    stream.seek(0)
    with gzip.GzipFile(fileobj=stream, mode="rb") as decompressed:
        while True:
            header = decompressed.read(TAR_BLOCK_BYTES)
            if not header:
                raise _ArchiveRejected("TAR archive is missing its end marker")
            if len(header) != TAR_BLOCK_BYTES:
                raise _ArchiveRejected("truncated TAR header")
            if header == bytes(TAR_BLOCK_BYTES):
                zero_blocks += 1
                if zero_blocks == 2:
                    _validate_tar_trailing_padding(decompressed)
                    return
                continue
            if zero_blocks:
                raise _ArchiveRejected("non-zero TAR data follows an end marker")

            try:
                member = tarfile.TarInfo.frombuf(
                    header, encoding="utf-8", errors="surrogateescape"
                )
            except tarfile.HeaderError as error:
                raise _ArchiveRejected(f"invalid TAR header: {error}") from error

            entry_count += 1
            if entry_count > MAX_ARCHIVE_ENTRIES:
                raise _ArchiveRejected(
                    f"archive has more than {MAX_ARCHIVE_ENTRIES} entries"
                )
            if member.type == TAR_GNU_SPARSE_TYPE:
                raise _ArchiveRejected("GNU sparse TAR metadata is not supported")

            declared_total = _check_entry_metadata(
                member.name, member.size, declared_total
            )
            if member.type in TAR_METADATA_TYPES:
                metadata_total += member.size
                if metadata_total > MAX_ARCHIVE_METADATA_BYTES:
                    raise _ArchiveRejected(
                        f"TAR metadata exceeds {MAX_ARCHIVE_METADATA_BYTES} bytes"
                    )
            _check_ratio(declared_total, compressed_size, member.name)

            padded_size = (
                (member.size + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES
            ) * TAR_BLOCK_BYTES
            if member.type in TAR_PAX_METADATA_TYPES:
                payload = _read_exact(
                    decompressed, member.size, f"PAX metadata {member.name!r}"
                )
                _validate_pax_metadata(payload)
                _discard_exact(
                    decompressed,
                    padded_size - member.size,
                    f"TAR padding after {member.name!r}",
                )
            else:
                _discard_exact(decompressed, padded_size, f"TAR entry {member.name!r}")


def _find_zip_eocd(stream: BinaryIO, file_size: int) -> tuple[int, int, int, int]:
    tail_size = min(file_size, ZIP_EOCD_BYTES + ZIP_MAX_COMMENT_BYTES)
    stream.seek(file_size - tail_size)
    tail = _read_exact(stream, tail_size, "ZIP end record")

    search_end = len(tail)
    while search_end:
        offset = tail.rfind(ZIP_EOCD_SIGNATURE, 0, search_end)
        if offset < 0:
            break
        if len(tail) - offset >= ZIP_EOCD_BYTES:
            (
                _signature,
                disk_number,
                central_disk,
                entries_on_disk,
                entry_count,
                central_size,
                central_offset,
                comment_size,
            ) = struct.unpack_from("<4s4H2LH", tail, offset)
            if offset + ZIP_EOCD_BYTES + comment_size == len(tail):
                eocd_offset = file_size - tail_size + offset
                break
        search_end = offset
    else:
        offset = -1

    if offset < 0:
        raise _ArchiveRejected("ZIP end-of-central-directory record is missing")
    if (
        entry_count == 0xFFFF
        or entries_on_disk == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    ):
        raise _ArchiveRejected(
            "ZIP64 archives are not supported by inventory preflight"
        )
    if disk_number != 0 or central_disk != 0 or entries_on_disk != entry_count:
        raise _ArchiveRejected("multi-disk ZIP archives are not supported")
    if entry_count > MAX_ARCHIVE_ENTRIES:
        raise _ArchiveRejected(f"archive has more than {MAX_ARCHIVE_ENTRIES} entries")
    if central_size > MAX_ARCHIVE_METADATA_BYTES:
        raise _ArchiveRejected(
            f"ZIP central directory exceeds {MAX_ARCHIVE_METADATA_BYTES} bytes"
        )
    return eocd_offset, entry_count, central_size, central_offset


def _preflight_zip(stream: BinaryIO, file_size: int) -> _ArchiveInventory:
    """Bound and scan the ZIP central directory before ZipFile loads it."""

    eocd_offset, expected_count, central_size, declared_offset = _find_zip_eocd(
        stream, file_size
    )
    actual_offset = eocd_offset - central_size
    if actual_offset < 0 or declared_offset != actual_offset:
        raise _ArchiveRejected("ZIP central-directory offset is invalid")

    inventory = _ArchiveInventory()
    consumed = 0
    entry_count = 0
    local_offsets: list[int] = []
    stream.seek(actual_offset)
    while consumed < central_size:
        if central_size - consumed < ZIP_CENTRAL_HEADER_BYTES:
            raise _ArchiveRejected("truncated ZIP central-directory header")
        header = _read_exact(
            stream, ZIP_CENTRAL_HEADER_BYTES, "ZIP central-directory header"
        )
        if header[:4] != ZIP_CENTRAL_SIGNATURE:
            raise _ArchiveRejected("invalid ZIP central-directory signature")

        flags = int.from_bytes(header[8:10], "little")
        name_size = int.from_bytes(header[28:30], "little")
        extra_size = int.from_bytes(header[30:32], "little")
        comment_size = int.from_bytes(header[32:34], "little")
        uncompressed_size = int.from_bytes(header[24:28], "little")
        external_attributes = int.from_bytes(header[38:42], "little")
        local_offset = int.from_bytes(header[42:46], "little")
        if local_offset == 0xFFFFFFFF:
            raise _ArchiveRejected(
                "ZIP64 archives are not supported by inventory preflight"
            )
        local_offsets.append(local_offset)
        record_size = ZIP_CENTRAL_HEADER_BYTES + name_size + extra_size + comment_size
        if consumed + record_size > central_size:
            raise _ArchiveRejected("ZIP central-directory entry exceeds its bounds")

        encoded_name = _read_exact(stream, name_size, "ZIP entry filename")
        encoding = "utf-8" if flags & 0x800 else "cp437"
        try:
            name = encoded_name.decode(encoding, "strict")
        except UnicodeDecodeError as error:
            raise _ArchiveRejected(
                f"ZIP entry filename is not valid {encoding}"
            ) from error
        _discard_exact(
            stream, extra_size + comment_size, "ZIP central-directory metadata"
        )

        unix_type = stat.S_IFMT(external_attributes >> 16)
        name_is_directory = name.endswith("/")
        dos_directory = bool(external_attributes & 0x10)
        unix_directory = unix_type == stat.S_IFDIR
        if (name_is_directory or dos_directory or unix_directory) and (
            not name_is_directory
            or uncompressed_size != 0
            or unix_type not in (0, stat.S_IFDIR)
        ):
            raise _ArchiveRejected(f"inconsistent ZIP directory member: {name!r}")
        is_directory = name_is_directory
        _record_archive_path(inventory, name, is_directory=is_directory)
        entry_count += 1
        if entry_count > MAX_ARCHIVE_ENTRIES:
            raise _ArchiveRejected(
                f"archive has more than {MAX_ARCHIVE_ENTRIES} entries"
            )
        consumed += record_size

    if consumed != central_size or entry_count != expected_count:
        raise _ArchiveRejected("ZIP central-directory entry count is inconsistent")
    if local_offsets and min(local_offsets) != 0:
        raise _ArchiveRejected("ZIP local-file data must begin at byte zero")
    if len(set(local_offsets)) != len(local_offsets):
        raise _ArchiveRejected("ZIP entries share a local-file offset")
    for local_offset in local_offsets:
        if local_offset >= actual_offset:
            raise _ArchiveRejected("ZIP local-file offset is invalid")
        stream.seek(local_offset)
        if _read_exact(stream, 4, "ZIP local-file header") != ZIP_LOCAL_SIGNATURE:
            raise _ArchiveRejected("ZIP local-file signature is invalid")
    return inventory


def _stream_entry(
    stream: BinaryIO,
    *,
    name: str,
    expected_size: int,
    total_read: int,
    expected_legal_bytes: bytes | None,
) -> tuple[bool | None, int]:
    """Read one member in bounded chunks and compare legal bytes in place."""

    matches = expected_legal_bytes is not None
    entry_read = 0
    while True:
        chunk = stream.read(READ_CHUNK_BYTES)
        if not chunk:
            break
        entry_read += len(chunk)
        total_read += len(chunk)
        if entry_read > MAX_ENTRY_UNCOMPRESSED_BYTES:
            raise _ArchiveRejected(
                "archive entry exceeds "
                f"{MAX_ENTRY_UNCOMPRESSED_BYTES} uncompressed bytes while reading: {name}"
            )
        if total_read > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise _ArchiveRejected(
                f"archive exceeds {MAX_TOTAL_UNCOMPRESSED_BYTES} "
                "total uncompressed bytes while reading"
            )
        if expected_legal_bytes is not None and matches:
            start = entry_read - len(chunk)
            matches = chunk == expected_legal_bytes[start:entry_read]

    if entry_read != expected_size:
        raise _ArchiveRejected(
            f"archive entry size differs from metadata: {name} "
            f"({expected_size} declared, {entry_read} read)"
        )
    if expected_legal_bytes is not None:
        matches = matches and entry_read == len(expected_legal_bytes)
        return matches, total_read
    return None, total_read


def _zip_member_is_regular(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    # Many valid wheels omit the Unix file type and publish permission bits
    # only. Explicit special-file types are never regular package members.
    return file_type in (0, stat.S_IFREG)


def _zip_member_is_directory(info: zipfile.ZipInfo) -> bool:
    return info.filename.endswith("/") and info.file_size == 0


def _zip_inventory(
    stream: BinaryIO,
    file_size: int,
    canonical_license: bytes,
    canonical_notices: bytes,
) -> _ArchiveInventory:
    inventory = _preflight_zip(stream, file_size)
    declared_total = 0
    compressed_total = 0
    total_read = 0

    stream.seek(0)
    with zipfile.ZipFile(stream) as archive:
        members = archive.infolist()
        if len(members) != len(inventory.names):
            raise _ArchiveRejected(
                "ZIP central-directory contents changed during bounded parsing"
            )

        for index, info in enumerate(members):
            name = inventory.names[index]
            normalized_name = inventory.normalized_names[index]
            if info.filename != name:
                inventory.errors.append(
                    f"unsafe archive path {name!r}: ZIP filename is interpreted "
                    f"as {info.filename!r}"
                )
            kind = _legal_kind(normalized_name) if normalized_name else None
            if _zip_member_is_directory(info):
                continue
            if not _zip_member_is_regular(info):
                inventory.errors.append(
                    f"unsupported non-regular archive member: {name!r}"
                )
                continue

            declared_total = _check_entry_metadata(name, info.file_size, declared_total)
            compressed_total += info.compress_size
            _check_ratio(info.file_size, info.compress_size, name)
            _check_ratio(declared_total, compressed_total, name)

            with archive.open(info, "r") as entry_stream:
                matches, total_read = _stream_entry(
                    entry_stream,
                    name=name,
                    expected_size=info.file_size,
                    total_read=total_read,
                    expected_legal_bytes=_expected_legal_bytes(
                        kind, canonical_license, canonical_notices
                    ),
                )
            _record_legal_entry(inventory, name, kind, matches)
    return inventory


def _tar_inventory(
    stream: BinaryIO,
    compressed_size: int,
    canonical_license: bytes,
    canonical_notices: bytes,
) -> _ArchiveInventory:
    _preflight_tar(stream, compressed_size)
    inventory = _ArchiveInventory()
    declared_total = 0
    total_read = 0

    stream.seek(0)
    with tarfile.open(fileobj=stream, mode="r:gz") as archive:
        for entry_count, member in enumerate(archive, start=1):
            if entry_count > MAX_ARCHIVE_ENTRIES:
                raise _ArchiveRejected(
                    f"archive has more than {MAX_ARCHIVE_ENTRIES} entries"
                )

            name = member.name
            normalized_name = _record_archive_path(
                inventory, name, is_directory=member.isdir()
            )
            kind = _legal_kind(normalized_name) if normalized_name else None
            if member.isdir():
                continue
            if not member.isfile():
                inventory.errors.append(
                    f"unsupported non-regular archive member: {name!r}"
                )
                continue

            declared_total = _check_entry_metadata(name, member.size, declared_total)
            _check_ratio(declared_total, compressed_size, name)
            entry_stream = archive.extractfile(member)
            if entry_stream is None:
                raise _ArchiveRejected(f"could not read archive entry: {name}")
            with entry_stream:
                matches, total_read = _stream_entry(
                    entry_stream,
                    name=name,
                    expected_size=member.size,
                    total_read=total_read,
                    expected_legal_bytes=_expected_legal_bytes(
                        kind, canonical_license, canonical_notices
                    ),
                )
            _record_legal_entry(inventory, name, kind, matches)
    return inventory


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _archive_inventory(
    path: Path, canonical_license: bytes, canonical_notices: bytes
) -> _ArchiveInventory:
    if path.suffix != ".whl" and not path.name.endswith(".tar.gz"):
        raise _ArchiveRejected(f"unsupported Python distribution archive: {path}")

    with path.open("rb") as stream:
        initial_metadata = os.fstat(stream.fileno())
        if path.suffix == ".whl":
            inventory = _zip_inventory(
                stream,
                initial_metadata.st_size,
                canonical_license,
                canonical_notices,
            )
        else:
            inventory = _tar_inventory(
                stream,
                initial_metadata.st_size,
                canonical_license,
                canonical_notices,
            )

        try:
            descriptor_identity = _file_identity(os.fstat(stream.fileno()))
            path_identity = _file_identity(path.stat())
        except OSError as error:
            raise _ArchiveRejected(
                "archive changed while it was being inspected"
            ) from error
        if (
            descriptor_identity != _file_identity(initial_metadata)
            or path_identity != descriptor_identity
        ):
            raise _ArchiveRejected("archive changed while it was being inspected")
        return inventory


def inventory_errors(
    path: Path, canonical_license: bytes, canonical_notices: bytes
) -> list[str]:
    """Return stable inventory errors for one wheel or source distribution."""

    try:
        archive = _archive_inventory(path, canonical_license, canonical_notices)
    except _ArchiveRejected as error:
        return [str(error)]
    except (
        EOFError,
        OSError,
        RuntimeError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        return [f"could not read Python distribution archive: {error}"]

    entry_counts = Counter(archive.names)
    duplicate_entries = sorted(
        name for name, count in entry_counts.items() if count > 1
    )
    normalized_groups: dict[str, list[str]] = {}
    for raw_name, normalized_name in zip(
        archive.names, archive.normalized_names, strict=True
    ):
        if normalized_name is not None:
            normalized_groups.setdefault(normalized_name, []).append(raw_name)
    normalized_duplicates = sorted(
        normalized_name
        for normalized_name, raw_names in normalized_groups.items()
        if len(raw_names) > 1 and len(set(raw_names)) > 1
    )
    errors = list(archive.errors)
    errors.extend(f"duplicate archive path: {name}" for name in duplicate_entries)
    errors.extend(
        f"duplicate normalized archive path: {name}" for name in normalized_duplicates
    )

    if not archive.licenses:
        errors.append("canonical Apache-2.0 license file is missing")
    else:
        conflicting_licenses = sorted(
            {entry.name for entry in archive.licenses if entry.matches is False}
        )
        if conflicting_licenses:
            errors.append(
                "packaged license file does not match LICENSE-APACHE: "
                + ", ".join(conflicting_licenses)
            )

    if not archive.notices:
        errors.append("THIRD-PARTY-NOTICES is missing")
    else:
        conflicting_notices = sorted(
            {entry.name for entry in archive.notices if entry.matches is False}
        )
        if conflicting_notices:
            errors.append(
                "packaged THIRD-PARTY-NOTICES does not match repository canonical file: "
                + ", ".join(conflicting_notices)
            )

    debug_entries = sorted(
        {
            name
            for name in archive.normalized_names
            if name is not None and name.endswith(DEBUG_TRANSCRIPT)
        }
    )
    if debug_entries:
        errors.append(
            "debug signature transcript must not ship: " + ", ".join(debug_entries)
        )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--license",
        required=True,
        type=Path,
        help="repository canonical Apache-2.0 license",
    )
    parser.add_argument(
        "--notices",
        required=True,
        type=Path,
        help="repository canonical third-party notices",
    )
    parser.add_argument("archives", nargs="+", type=Path)
    args = parser.parse_args(argv)

    canonical_license = args.license.read_bytes()
    canonical_notices = args.notices.read_bytes()
    failed = False
    for archive in args.archives:
        errors = inventory_errors(archive, canonical_license, canonical_notices)
        if errors:
            failed = True
            for error in errors:
                print(f"ERROR: {archive}: {error}", file=sys.stderr)
        else:
            print(f"OK: {archive}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
