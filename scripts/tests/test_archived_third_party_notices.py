"""Exercise the archived notice CLI without resurrecting active crate copies."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "archive/native/scripts/third_party_notices.py"
COPIES = (
    "jacs", "jacs-media", "binding-core", "jacs-mcp", "jacs-cli",
    "jacs-duckdb", "jacs-redb", "jacs-surrealdb", "jacs-postgresql",
    "jacsnpm", "jacspy", "jacspy/python/jacs",
)
START = "===== BEGIN GENERATED CARGO DEPENDENCY INVENTORY ====="
END = "===== END GENERATED CARGO DEPENDENCY INVENTORY ====="
PREFIX = b"Archived acknowledgments must remain unchanged.\n\n"
SUFFIX = b"\n\nFULL LICENSE APPENDIX\nKeep these source bytes unchanged.\n"


class ArchivedNoticeTests(unittest.TestCase):
    def test_archive_regeneration_preserves_copies_and_exact_first_party_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_root = Path(temporary)
            output = output_root / "THIRD-PARTY-NOTICES"
            output.write_bytes(PREFIX + f"{START}\nstale\n{END}".encode() + SUFFIX)
            for relative in COPIES:
                (output_root / relative).mkdir(parents=True, exist_ok=True)

            def package(identifier, name, version, manifest, source=None):
                return {
                    "id": identifier, "name": name, "version": version,
                    "manifest_path": str(manifest), "source": source, "license": "MIT",
                }

            core_manifest = ROOT / "jacs-core/Cargo.toml"
            registry = "registry+https://github.com/rust-lang/crates.io-index"
            packages = [
                package("native", "jacs", "0.13.0", output_root / "jacs/Cargo.toml"),
                package("local-core", "jacs-core", "0.13.0", core_manifest),
                package("registry-core", "jacs-core", "0.12.0", "/registry/jacs-core/Cargo.toml", registry),
                package("other-core", "jacs-core", "0.11.0", output_root / "other-core/Cargo.toml"),
                package("spoofed-source", "jacs-core", "0.10.0", core_manifest, registry),
                package("relative-path", "jacs-core", "0.9.0", "jacs-core/Cargo.toml"),
                package("other-name", "different-package", "1.0.0", core_manifest),
            ]
            metadata = output_root / "metadata.json"
            metadata.write_text(json.dumps({
                "packages": packages,
                "workspace_members": ["native"],
                "resolve": {"nodes": [{"id": item["id"]} for item in packages]},
            }))
            command = [
                sys.executable, str(SCRIPT), "--metadata-file", str(metadata),
                "--output", str(output),
            ]
            for mode in ("--write", "--check"):
                result = subprocess.run(command + [mode], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            generated = output.read_bytes()
            self.assertTrue(generated.startswith(PREFIX + START.encode()))
            self.assertTrue(generated.endswith(END.encode() + SUFFIX))
            self.assertNotIn(b"  - jacs-core 0.13.0", generated)
            self.assertNotIn(b"  - jacs 0.13.0", generated)
            for version in ("0.12.0", "0.11.0", "0.10.0", "0.9.0"):
                self.assertIn(f"  - jacs-core {version}".encode(), generated)
            self.assertIn(b"  - different-package 1.0.0", generated)
            for relative in COPIES:
                self.assertEqual((output_root / relative / "THIRD-PARTY-NOTICES").read_bytes(), generated)
                self.assertTrue((ROOT / "archive/native" / relative).is_dir())
            for active in ("jacs-core", "jacs-mobile", "jacs-wasm"):
                self.assertFalse((output_root / active).exists())


if __name__ == "__main__":
    unittest.main()
