"""Exercise the real native build script without compiling the native dependency graph."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = Path("schemas/agreement/v2/agreement.schema.json")


class NativeBuildFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="jacs-build-freshness-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.crate = self.root / "checkout/archive/native/jacs"
        self.crate.mkdir(parents=True)
        (self.crate / "src").mkdir()
        (self.crate / "src/lib.rs").write_text("pub fn fixture() {}\n")
        (self.crate / "Cargo.toml").write_text(
            '[package]\nname = "jacs"\nversion = "0.0.0"\nedition = "2024"\n'
            '[workspace]\n'
        )
        shutil.copyfile(ROOT / "archive/native/jacs/build.rs", self.crate / "build.rs")
        self.own_schema = self.crate / SCHEMA
        self.own_schema.parent.mkdir(parents=True)
        self.own_schema.write_bytes((ROOT / "archive/native/jacs" / SCHEMA).read_bytes())
        self.core_schema = self.root / "checkout/jacs-core" / SCHEMA
        # Deliberately isolate this dependency-free probe from user caches and
        # wrappers: a cache hit must not hide Cargo scheduling a needless rebuild.
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("CARGO_", "KACHE_"))
            and key not in {"RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"}
        }
        self.env.update({
            "CARGO_HOME": str(self.root / "cargo"),
            "CARGO_TARGET_DIR": str(self.root / "target"),
            "CARGO_BUILD_BUILD_DIR": str(self.root / "intermediate"),
            "CARGO_INCREMENTAL": "0",
            "RUSTC_WRAPPER": "",
            "RUSTC_WORKSPACE_WRAPPER": "",
        })

    def build(self, *, succeeds=True):
        result = subprocess.run(
            ["cargo", "build", "--offline", "--message-format=json"],
            cwd=self.crate, env=self.env, capture_output=True, text=True, timeout=60,
        )
        if not succeeds:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("agreement v2 schema drift", result.stderr)
            return None
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        library = [item for item in artifacts if item.get("reason") == "compiler-artifact"
                   and item["target"]["kind"] == ["lib"]]
        self.assertEqual(len(library), 1, result.stdout)
        return library[0]["fresh"]

    def test_checkout_stays_fresh_and_rechecks_both_schemas(self):
        self.core_schema.parent.mkdir(parents=True)
        self.core_schema.write_bytes(self.own_schema.read_bytes())
        self.assertFalse(self.build())
        self.assertTrue(self.build(), "unchanged checkout must not rebuild jacs")

        self.own_schema.write_bytes(self.own_schema.read_bytes() + b"\n")
        self.build(succeeds=False)
        self.core_schema.write_bytes(self.own_schema.read_bytes())
        self.assertFalse(self.build())
        self.assertTrue(self.build())

        self.core_schema.write_bytes(self.core_schema.read_bytes() + b"\n")
        self.build(succeeds=False)
        self.own_schema.write_bytes(self.core_schema.read_bytes())
        self.assertFalse(self.build())
        self.assertTrue(self.build())

    def test_published_package_without_core_stays_fresh(self):
        self.assertFalse(self.core_schema.exists())
        self.assertFalse(self.build())
        self.assertTrue(self.build(), "absent optional core must not force a rebuild")
        self.own_schema.write_bytes(self.own_schema.read_bytes() + b"\n")
        self.assertFalse(self.build(), "the packaged schema remains a tracked input")
        self.assertTrue(self.build())


if __name__ == "__main__":
    unittest.main()
