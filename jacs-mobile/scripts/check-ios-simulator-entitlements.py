#!/usr/bin/env python3
"""Check the built simulator executable's __TEXT,__entitlements in every slice."""

import plistlib
import struct
import sys
from pathlib import Path

GROUP = "JACSTEST01.ai.hai.jacs.simulator-tests"


def entitlements(data: bytes) -> list[dict]:
    # Xcode's universal simulator executable uses a big-endian fat header;
    # its arm64/x86_64 slices are little-endian 64-bit Mach-O files.
    if data[:4] == b"\xca\xfe\xba\xbe":
        if len(data) < 8:
            raise ValueError("truncated universal Mach-O header")
        count = struct.unpack_from(">I", data, 4)[0]
        table_end = 8 + 20 * count
        if not count or table_end > len(data):
            raise ValueError("invalid universal Mach-O architecture table")
        result = []
        ranges = []
        for index in range(count):
            _, _, offset, size, _ = struct.unpack_from(">IIIII", data, 8 + 20 * index)
            if offset < table_end or not size or offset + size > len(data):
                raise ValueError("invalid universal Mach-O slice bounds")
            if any(offset < end and start < offset + size for start, end in ranges):
                raise ValueError("overlapping universal Mach-O slices")
            ranges.append((offset, offset + size))
            result.extend(thin_entitlements(data[offset:offset + size]))
        return result
    return thin_entitlements(data)


def thin_entitlements(data: bytes) -> list[dict]:
    if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError("expected an arm64/x86_64 Mach-O executable")
    count, size = struct.unpack_from("<II", data, 16)
    commands_end = 32 + size
    if commands_end > len(data):
        raise ValueError("truncated Mach-O load commands")
    position = 32
    found = []
    for _ in range(count):
        if position + 8 > commands_end:
            raise ValueError("truncated Mach-O load command")
        command, length = struct.unpack_from("<II", data, position)
        if length < 8 or position + length > commands_end:
            raise ValueError("invalid Mach-O load command bounds")
        if command == 0x19:  # LC_SEGMENT_64
            if length < 72:
                raise ValueError("truncated Mach-O segment")
            sections = struct.unpack_from("<I", data, position + 64)[0]
            if 72 + 80 * sections > length:
                raise ValueError("truncated Mach-O section table")
            for index in range(sections):
                section = position + 72 + 80 * index
                name, segment, _, section_size, offset = struct.unpack_from(
                    "<16s16sQQI", data, section)
                if name.rstrip(b"\0") != b"__entitlements" or segment.rstrip(b"\0") != b"__TEXT":
                    continue
                if offset < commands_end or not section_size or offset + section_size > len(data):
                    raise ValueError("invalid simulator entitlement section bounds")
                found.append(plistlib.loads(data[offset:offset + section_size].rstrip(b"\0")))
        position += length
    if position != commands_end or len(found) != 1 or not isinstance(found[0], dict):
        raise ValueError("expected exactly one simulator entitlement dictionary per slice")
    return found


def validate(data: bytes) -> int:
    slices = entitlements(data)
    for values in slices:
        if values.get("application-identifier") != GROUP:
            raise ValueError("test host lacks its synthetic application identity")
        if values.get("keychain-access-groups") != [GROUP]:
            raise ValueError("test host lacks its isolated Keychain group")
    return len(slices)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: check-ios-simulator-entitlements.py <built-host-executable>")
    try:
        count = validate(Path(sys.argv[1]).read_bytes())
    except (OSError, ValueError, struct.error, plistlib.InvalidFileException) as error:
        raise SystemExit(f"iOS simulator entitlement check failed: {error}")
    print(f"PASS: {count} built simulator slice(s) have the exact isolated Keychain identity.")
