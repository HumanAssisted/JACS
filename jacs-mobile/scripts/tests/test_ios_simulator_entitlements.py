import importlib.util
import plistlib
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("entitlements", Path(__file__).parents[1] / "check-ios-simulator-entitlements.py")
entitlements = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entitlements)


def executable(application=entitlements.GROUP, groups=None):
    payload = plistlib.dumps({"application-identifier": application,
                             "keychain-access-groups": [entitlements.GROUP] if groups is None else groups})
    # 64-bit Mach-O with one LC_SEGMENT_64 and one section, followed by its data.
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x100000C, 0, 2, 1, 152, 0, 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT", 0, 184 + len(payload),
                          0, 184 + len(payload), 7, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__entitlements", b"__TEXT", 184,
                          len(payload), 184, 0, 0, 0, 0, 0, 0, 0)
    return header + segment + section + payload


def universal(first, second):
    start = 48
    return (struct.pack(">II", 0xCAFEBABE, 2)
            + struct.pack(">IIIII", 0x100000C, 0, start, len(first), 0)
            + struct.pack(">IIIII", 0x1000007, 0, start + len(first), len(second), 0)
            + first + second)


class SimulatorEntitlementTests(unittest.TestCase):
    def test_thin_and_universal_executables(self):
        self.assertEqual(entitlements.check(executable()), 1)
        self.assertEqual(entitlements.check(universal(executable(), executable())), 2)

    def test_every_architecture_must_have_the_isolated_identity(self):
        with self.assertRaises(ValueError):
            entitlements.check(universal(executable(), executable(application="wrong")))

    def test_extra_or_missing_keychain_access_is_rejected(self):
        for groups in ([], [entitlements.GROUP, "another-group"]):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                entitlements.check(executable(groups=groups))

    def test_input_plist_is_not_evidence_of_embedded_entitlements(self):
        with self.assertRaises(ValueError):
            entitlements.check(plistlib.dumps({"application-identifier": entitlements.GROUP}))

    def test_truncated_section_and_invalid_fat_bounds_fail(self):
        with self.assertRaises(ValueError):
            entitlements.check(executable()[:-1])
        with self.assertRaises(ValueError):
            entitlements.check(universal(executable(), executable())[:-1])


if __name__ == "__main__":
    unittest.main()
