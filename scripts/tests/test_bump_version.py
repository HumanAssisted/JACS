"""Version updates run against disposable repositories; never bump this checkout."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
CRATES = ("jacs-core", "jacs-wasm", "jacs-mobile", "jacs-mcp", "jacs-cli")
ARCHIVE_LOCKS = (
    "archive/native/Cargo.lock",
    "archive/native/jacs/examples/observability/Cargo.lock",
    "archive/native/jacs-surrealdb/Cargo.lock",
)


class BumpVersionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copy2(ROOT / "Makefile", self.root / "Makefile")
        (self.root / "scripts").mkdir()
        for name in ("bump-version.sh", "bump_version.py", "seal-changelog.sh"):
            shutil.copy2(ROOT / "scripts" / name, self.root / "scripts" / name)
        self.write("Cargo.toml", '[workspace]\nmembers = ' + json.dumps(CRATES) + '\nexclude = ["archive/native"]\n')
        for crate in CRATES:
            dependency = '' if crate == 'jacs-core' else 'jacs-core = { version = "0.13.0", path = "../jacs-core" }\n'
            self.write(f"{crate}/Cargo.toml", f'[package]\nname = "{crate}"\nversion = "0.13.0"\n\n[dependencies]\n{dependency}external = {{ version = "0.13.0", features = ["version"] }}\n')
            self.write(f"{crate}/src/lib.rs", '// Disposable fixture.\n')
        self.write("jacs-wasm/package.template.json", '{"name":"@jacs/wasm","version":"0.13.0","license":"Apache-2.0"}\n')
        self.write("jacs-mcp/contract/jacs-mcp-contract.json", '{"server":{"name":"jacs-mcp","version":"0.13.0"},"tools":[]}\n')
        self.write("release/shipped-artifacts.json", json.dumps({"source_version": "0.13.0", "observed_at": "2026-09-20", "artifacts": {"crate": {"version": "0.12.7", "status": "published", "checksum": "recorded-checksum"}, "wasm": {"version": None, "status": "unpublished"}}}) + '\n')
        lock = 'version = 4\n\n'
        for crate in CRATES:
            dependency = '' if crate == 'jacs-core' else 'dependencies = [\n "jacs-core 0.13.0",\n "external",\n]\n'
            lock += f'[[package]]\nname = "{crate}"\nversion = "0.13.0"\n{dependency}\n'
        lock += '[[package]]\nname = "external"\nversion = "0.13.0"\nsource = "registry+https://example.invalid/index"\nchecksum = "third-party-checksum-must-not-change"\n'
        self.write("Cargo.lock", lock)
        self.write("CHANGELOG.md", '## 0.13.0\n\n(unreleased)\n\nExisting release notes.\n')
        self.write("archive/native/Cargo.toml", '[workspace]\nmembers = ["jacs", "binding-core"]\n')
        for directory, name in [('jacs', 'jacs'), ('binding-core', 'jacs-binding-core')]:
            self.write(f"archive/native/{directory}/Cargo.toml", f'[package]\nname = "{name}"\nversion = "0.12.7"\n\n[dependencies]\njacs-core = {{ version = "0.13.0", path = "../../../jacs-core" }}\n')
            self.write(f"archive/native/{directory}/src/lib.rs", '// Preserved archive fixture.\n')
        archived_lock = ('version = 4\n\n[[package]]\nname = "jacs"\nversion = "0.12.7"\ndependencies = [\n "jacs-core 0.13.0",\n]\n\n'
                         '[[package]]\nname = "jacs-cli"\nversion = "0.13.0"\n\n'
                         '[[package]]\nname = "jacs-core"\nversion = "0.13.0"\n\n'
                         '[[package]]\nname = "external"\nversion = "0.13.0"\nsource = "registry+https://example.invalid/index"\nchecksum = "archived-third-party-sentinel"\n')
        for relative in ARCHIVE_LOCKS:
            self.write(relative, archived_lock)
        self.write('archive/native/untouched.txt', 'ARCHIVED SENTINEL\n')

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, path, text):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)

    def snapshot(self):
        return {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob('*') if path.is_file()}

    def run_bump(self, *args):
        return subprocess.run(['bash', str(self.root / 'scripts/bump-version.sh'), *args], text=True, capture_output=True, timeout=15)

    def test_major_minor_patch_align_only_first_party_release_versions(self):
        for bump, expected in [('major', '1.0.0'), ('minor', '0.14.0'), ('patch', '0.13.1')]:
            with self.subTest(bump=bump):
                before = self.snapshot()
                completed = self.run_bump(bump)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                for crate in CRATES:
                    manifest = tomllib.loads((self.root / crate / 'Cargo.toml').read_text())
                    self.assertEqual(manifest['package']['version'], expected)
                    self.assertEqual(manifest['dependencies']['external']['version'], '0.13.0')
                    if crate != 'jacs-core':
                        self.assertEqual(manifest['dependencies']['jacs-core']['version'], expected)
                lock = tomllib.loads((self.root / 'Cargo.lock').read_text())['package']
                self.assertTrue(all(p['version'] == expected for p in lock if p['name'] in CRATES))
                external = next(p for p in lock if p['name'] == 'external')
                self.assertEqual(external['version'], '0.13.0')
                self.assertEqual(external['checksum'], 'third-party-checksum-must-not-change')
                for package in lock:
                    for dependency in package.get('dependencies', []):
                        if dependency.startswith('jacs-core '):
                            self.assertEqual(dependency, 'jacs-core ' + expected)
                self.assertEqual(json.loads((self.root / 'jacs-wasm/package.template.json').read_text())['version'], expected)
                self.assertEqual(json.loads((self.root / 'jacs-mcp/contract/jacs-mcp-contract.json').read_text())['server']['version'], expected)
                matrix = json.loads((self.root / 'release/shipped-artifacts.json').read_text())
                self.assertEqual(matrix, {**json.loads(before['release/shipped-artifacts.json']), 'source_version': expected})
                self.assertTrue((self.root / 'CHANGELOG.md').read_text().startswith(f'## {expected}\n\n(unreleased)'))
                for directory in ('jacs', 'binding-core'):
                    manifest = tomllib.loads((self.root / f'archive/native/{directory}/Cargo.toml').read_text())
                    self.assertEqual(manifest['package']['version'], '0.12.7')
                    self.assertEqual(manifest['dependencies']['jacs-core']['version'], expected)
                for relative in ARCHIVE_LOCKS:
                    old_packages = tomllib.loads(before[relative].decode())['package']
                    packages = tomllib.loads((self.root / relative).read_text())['package']
                    for previous, updated in zip(old_packages, packages, strict=True):
                        if previous['name'] == 'jacs-core':
                            self.assertEqual(updated, {**previous, 'version': expected})
                        elif previous['name'] == 'jacs':
                            self.assertEqual(updated, {**previous, 'dependencies': ['jacs-core ' + expected]})
                        else:
                            self.assertEqual(updated, previous)
                editable_archive = {*ARCHIVE_LOCKS, 'archive/native/jacs/Cargo.toml', 'archive/native/binding-core/Cargo.toml'}
                for name, value in before.items():
                    if name.startswith('archive/') and name not in editable_archive:
                        self.assertEqual((self.root / name).read_bytes(), value)
                # Reuse the same isolated fixture for the next independent case.
                for name, value in before.items():
                    (self.root / name).write_bytes(value)

    def test_late_mismatches_or_invalid_inputs_never_partially_write(self):
        cases = [
            ('jacs-cli/Cargo.toml', 'version = "0.13.0"', 'version = "0.12.0"'),
            ('jacs-wasm/Cargo.toml', 'version = "0.13.0", path', 'version = "0.12.0", path'),
            ('jacs-wasm/Cargo.toml', 'path = "../jacs-core"', 'path = "../archive/native/jacs-core"'),
            ('jacs-wasm/package.template.json', '"version":"0.13.0"', '"version":"0.12.0"'),
            ('jacs-mcp/contract/jacs-mcp-contract.json', '"version":"0.13.0"', '"version":"0.13.0","version":"0.13.0"'),
            ('release/shipped-artifacts.json', '"source_version": "0.13.0"', '"source_version": "0.12.0"'),
            ('Cargo.lock', '"jacs-core 0.13.0"', '"jacs-core 0.12.0"'),
            ('Cargo.toml', '"jacs-cli"', '"archive/native/jacs"'),
            ('jacs-core/Cargo.toml', 'version = "0.13.0"', 'version = "0.13.0-beta.1"'),
            ('CHANGELOG.md', '## 0.13.0', '## 0.13.1'),
            ('archive/native/jacs/Cargo.toml', 'version = "0.13.0", path', 'version = "0.12.0", path'),
            ('archive/native/binding-core/Cargo.toml', 'path = "../../../jacs-core"', 'path = "../jacs-core"'),
            ('archive/native/jacs-surrealdb/Cargo.lock', 'name = "jacs-core"\nversion = "0.13.0"', 'name = "jacs-core"\nversion = "0.12.0"'),
        ]
        for filename, old, new in cases:
            with self.subTest(filename=filename, invalid=new):
                path = self.root / filename
                original = path.read_text()
                path.write_text(original.replace(old, new))
                before = self.snapshot()
                completed = self.run_bump('patch')
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(self.snapshot(), before)
                path.write_text(original)

    def test_check_mode_and_invalid_cli_leave_every_file_unchanged(self):
        before = self.snapshot()
        completed = self.run_bump('patch', '--check')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('0.13.0 -> 0.13.1', completed.stdout)
        self.assertEqual(self.snapshot(), before)
        for args in [[], ['invalid'], ['patch', 'unexpected']]:
            self.assertNotEqual(self.run_bump(*args).returncode, 0)
            self.assertEqual(self.snapshot(), before)

    def test_make_bump_choices_and_read_only_previews(self):
        for bump, expected in [('patch', '0.13.1'), ('minor', '0.14.0'), ('major', '1.0.0')]:
            with self.subTest(bump=bump):
                before = self.snapshot()
                preview = subprocess.run(['make', f'plan-bump-{bump}'], cwd=self.root, capture_output=True, text=True, timeout=15)
                self.assertEqual(preview.returncode, 0, preview.stderr)
                self.assertIn(f'0.13.0 -> {expected}', preview.stdout)
                self.assertEqual(self.snapshot(), before)

                applied = subprocess.run(['make', f'bump-{bump}'], cwd=self.root, capture_output=True, text=True, timeout=15)
                self.assertEqual(applied.returncode, 0, applied.stderr)
                for crate in CRATES:
                    manifest = tomllib.loads((self.root / crate / 'Cargo.toml').read_text())
                    self.assertEqual(manifest['package']['version'], expected)
                self.assertEqual(json.loads((self.root / 'jacs-wasm/package.template.json').read_text())['version'], expected)
                matrix = json.loads((self.root / 'release/shipped-artifacts.json').read_text())
                self.assertEqual(matrix, {**json.loads(before['release/shipped-artifacts.json']), 'source_version': expected})
                for name, value in before.items():
                    (self.root / name).write_bytes(value)

    def test_missing_file_and_symlink_are_rejected_before_writing(self):
        path = self.root / 'jacs-mcp/contract/jacs-mcp-contract.json'
        original = path.read_bytes()
        path.unlink()
        before = self.snapshot()
        self.assertNotEqual(self.run_bump('patch').returncode, 0)
        self.assertEqual(self.snapshot(), before)
        target = self.root / 'outside.json'
        target.write_bytes(original)
        path.symlink_to(target)
        before = self.snapshot()
        self.assertNotEqual(self.run_bump('patch').returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_archive_optional_locks_without_active_core_stay_unchanged(self):
        registry = ('version = 4\n\n[[package]]\nname = "jacs-core"\nversion = "0.11.0"\n'
                    'source = "registry+https://example.invalid/index"\nchecksum = "do-not-change"\n')
        self.write(ARCHIVE_LOCKS[1], registry)
        (self.root / ARCHIVE_LOCKS[2]).unlink()
        completed = self.run_bump('minor')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual((self.root / ARCHIVE_LOCKS[1]).read_text(), registry)
        self.assertFalse((self.root / ARCHIVE_LOCKS[2]).exists())

    def test_archive_registry_core_and_old_package_versions_are_preserved(self):
        path = self.root / ARCHIVE_LOCKS[0]
        path.write_text(path.read_text() + '\n[[package]]\nname = "jacs-core"\nversion = "0.13.0"\nsource = "registry+https://example.invalid/index"\nchecksum = "registry-core-sentinel"\ndependencies = [\n "jacs-core 0.13.0 (registry+https://example.invalid/index)",\n]\n')
        completed = self.run_bump('minor')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        packages = tomllib.loads(path.read_text())['package']
        local = next(p for p in packages if p['name'] == 'jacs-core' and 'source' not in p)
        registry = next(p for p in packages if p['name'] == 'jacs-core' and 'source' in p)
        self.assertEqual(local['version'], '0.14.0')
        self.assertEqual(registry['version'], '0.13.0')
        self.assertEqual(registry['checksum'], 'registry-core-sentinel')
        self.assertEqual(registry['dependencies'], ['jacs-core 0.13.0 (registry+https://example.invalid/index)'])

    @unittest.skipUnless(shutil.which('cargo'), 'Cargo is required for the archived metadata smoke')
    def test_archive_cargo_metadata_after_an_isolated_minor_bump(self):
        completed = self.run_bump('minor')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        before = self.snapshot()
        metadata = subprocess.run(['cargo', 'metadata', '--offline', '--no-deps', '--format-version', '1', '--manifest-path', str(self.root / 'archive/native/Cargo.toml')], capture_output=True, text=True, timeout=30)
        self.assertEqual(metadata.returncode, 0, metadata.stderr)
        packages = json.loads(metadata.stdout)['packages']
        self.assertEqual({package['name'] for package in packages}, {'jacs', 'jacs-binding-core'})
        for package in packages:
            self.assertEqual(package['version'], '0.12.7')
            core = next(dep for dep in package['dependencies'] if dep['name'] == 'jacs-core')
            self.assertEqual(core['req'], '^0.14.0')
            self.assertEqual(Path(core['path']), self.root / 'jacs-core')
        self.assertEqual(self.snapshot(), before)

    def test_seal_defaults_to_core_and_is_idempotent(self):
        script = str(self.root / 'scripts/seal-changelog.sh')
        before = subprocess.run(['bash', script, 'check'], capture_output=True, text=True)
        self.assertNotEqual(before.returncode, 0)
        sealed = subprocess.run(['bash', script, 'seal'], capture_output=True, text=True)
        self.assertEqual(sealed.returncode, 0, sealed.stderr)
        after = (self.root / 'CHANGELOG.md').read_bytes()
        checked = subprocess.run(['bash', script, 'check'], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        repeated = subprocess.run(['bash', script, 'seal'], capture_output=True, text=True)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual((self.root / 'CHANGELOG.md').read_bytes(), after)
        invalid = subprocess.run(['bash', script, 'seal', '0.13.*'], capture_output=True, text=True)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual((self.root / 'CHANGELOG.md').read_bytes(), after)


if __name__ == '__main__':
    unittest.main()
