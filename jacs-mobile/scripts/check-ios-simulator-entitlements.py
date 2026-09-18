#!/usr/bin/env python3
"""Check the built simulator executable, not an input entitlements plist.

Xcode puts iOS Simulator entitlements in __TEXT,__entitlements. The ordinary
code signature instead contains macOS host-process entitlements. Assert the
isolated Keychain identity in every architecture of the actual Mach-O binary.
"""

import plistlib
import struct
import sys
from pathlib import Path

GROUP = "JACSTEST01.ai.hai.jacs.simulator-tests"


def slices(binary):
    magic = binary[:4]
    fat_formats = {
        b"\xca\xfe\xba\xbe": (">", "IIIII"),
        b"\xbe\xba\xfe\xca": ("<", "IIIII"),
        b"\xca\xfe\xba\xbf": (">", "IIQQII"),
        b"\xbf\xba\xfe\xca": ("<", "IIQQII"),
    }
    if magic not in fat_formats:
        return [binary]
    endian, layout = fat_formats[magic]
    count = struct.unpack_from(endian + "I", binary, 4)[0]
    width = struct.calcsize(endian + layout)
    if not count or 8 + count * width > len(binary):
        raise ValueError("Invalid universal Mach-O architecture table")
    result = []
    for index in range(count):
        _, _, offset, size, *_ = struct.unpack_from(endian + layout, binary, 8 + index * width)
        if offset < 8 + count * width or not size or offset + size > len(binary):
            raise ValueError("Invalid universal Mach-O architecture bounds")
        result.append(binary[offset:offset + size])
    return result


def embedded_entitlements(binary):
    endian = {b"\xcf\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xcf": ">"}.get(binary[:4])
    if endian is None or len(binary) < 32:
        raise ValueError("Expected a 64-bit simulator Mach-O executable")
    count, command_bytes = struct.unpack_from(endian + "II", binary, 16)
    limit = 32 + command_bytes
    if limit > len(binary):
        raise ValueError("Invalid Mach-O load-command bounds")
    cursor = 32
    found = []
    for _ in range(count):
        if cursor + 8 > limit:
            raise ValueError("Truncated Mach-O load command")
        command, size = struct.unpack_from(endian + "II", binary, cursor)
        if size < 8 or cursor + size > limit:
            raise ValueError("Invalid Mach-O load command size")
        if command == 0x19:  # LC_SEGMENT_64
            if size < 72:
                raise ValueError("Truncated Mach-O segment")
            sections = struct.unpack_from(endian + "I", binary, cursor + 64)[0]
            if 72 + sections * 80 > size:
                raise ValueError("Invalid Mach-O section table")
            for index in range(sections):
                section = cursor + 72 + index * 80
                name = binary[section:section + 16].rstrip(b"\0")
                segment = binary[section + 16:section + 32].rstrip(b"\0")
                if (segment, name) != (b"__TEXT", b"__entitlements"):
                    continue
                length, offset = struct.unpack_from(endian + "QI", binary, section + 40)
                if not length or offset < limit or offset + length > len(binary):
                    raise ValueError("Invalid simulator entitlement section bounds")
                found.append(plistlib.loads(binary[offset:offset + length].rstrip(b"\0")))
        cursor += size
    if cursor != limit or len(found) != 1:
        raise ValueError("Expected exactly one embedded simulator entitlement section")
    return found[0]


def check(binary):
    architectures = slices(binary)
    for executable in architectures:
        entitlements = embedded_entitlements(executable)
        if entitlements.get("application-identifier") != GROUP:
            raise ValueError("Simulator host lacks its isolated application identity")
        if entitlements.get("keychain-access-groups") != [GROUP]:
            raise ValueError("Simulator host lacks its isolated Keychain group")
    return len(architectures)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: check-ios-simulator-entitlements.py <built-simulator-executable>")
    count = check(Path(sys.argv[1]).read_bytes())
    print(f"PASS: isolated Keychain entitlements embedded in all {count} simulator architecture(s).")
