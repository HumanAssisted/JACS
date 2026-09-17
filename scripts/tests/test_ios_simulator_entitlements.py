"""Regression coverage for checking actual simulator Mach-O entitlements."""

import importlib.util
import plistlib
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "simulator_entitlements", ROOT / "jacs-mobile/scripts/check-ios-simulator-entitlements.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def executable(values, section_name=b"__entitlements"):
    payload = plistlib.dumps(values)
    offset = 32 + 72 + 80
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 152, 0, 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT", 0,
                          offset + len(payload), 0, offset + len(payload), 5, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", section_name, b"__TEXT", offset,
                          len(payload), offset, 0, 0, 0, 0, 0, 0, 0)
    return header + segment + section + payload


def universal(*slices):
    offset = 8 + 20 * len(slices)
    table = b""
    for index, data in enumerate(slices):
        table += struct.pack(">IIIII", 0x0100000C if index == 0 else 0x01000007,
                             0, offset, len(data), 0)
        offset += len(data)
    return struct.pack(">II", 0xCAFEBABE, len(slices)) + table + b"".join(slices)


class SimulatorEntitlementTests(unittest.TestCase):
    def setUp(self):
        self.values = {"application-identifier": MODULE.GROUP,
                       "keychain-access-groups": [MODULE.GROUP]}

    def test_accepts_thin_and_every_universal_slice(self):
        data = executable(self.values)
        self.assertEqual(MODULE.validate(data), 1)
        self.assertEqual(MODULE.validate(universal(data, data)), 2)

    def test_rejects_missing_or_wrong_identity_in_either_slice(self):
        good = executable(self.values)
        for invalid in ({}, {**self.values, "application-identifier": "wrong"},
                        {**self.values, "keychain-access-groups": [MODULE.GROUP, "other"]}):
            bad = executable(invalid)
            for data in (bad, universal(good, bad), universal(bad, good)):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    MODULE.validate(data)

    def test_decoy_plist_outside_entitlement_section_is_not_accepted(self):
        with self.assertRaises(ValueError):
            MODULE.validate(executable(self.values, section_name=b"__cstring"))

    def test_rejects_truncation_and_invalid_section_bounds(self):
        valid = executable(self.values)
        for data in (valid[:20], valid[:100], valid[:-20]):
            with self.assertRaises(ValueError):
                MODULE.validate(data)
        data = bytearray(valid)
        struct.pack_into("<I", data, 32 + 72 + 48, len(data) + 1)
        with self.assertRaises(ValueError):
            MODULE.validate(data)

    def test_rejects_missing_and_overlapping_universal_slices(self):
        for data in (struct.pack(">II", 0xCAFEBABE, 0), b"\xca\xfe\xba\xbe"):
            with self.assertRaises(ValueError):
                MODULE.validate(data)
        data = bytearray(universal(executable(self.values), executable(self.values)))
        first_offset = struct.unpack_from(">I", data, 16)[0]
        struct.pack_into(">I", data, 36, first_offset)
        with self.assertRaises(ValueError):
            MODULE.validate(data)


if __name__ == "__main__":
    unittest.main()
