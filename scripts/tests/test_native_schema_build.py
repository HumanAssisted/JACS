"""Run the real native build script without compiling the native dependency graph."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / 'archive/native/jacs/build.rs'
SCHEMA = Path('schemas/agreement/v2/agreement.schema.json')


class NativeSchemaBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='jacs-schema-build-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.crate = self.root / 'archive/native/jacs'
        (self.crate / 'src').mkdir(parents=True)
        (self.crate / 'src/lib.rs').write_text('pub const VALID: bool = true;\n')
        (self.crate / 'Cargo.toml').write_text(
            '[package]\nname="schema-guard-probe"\nversion="0.0.0"\nedition="2024"\n[workspace]\n')
        shutil.copyfile(BUILD_SCRIPT, self.crate / 'build.rs')
        self.native = self.crate / SCHEMA
        self.core = self.root / 'jacs-core' / SCHEMA
        self.native.parent.mkdir(parents=True)
        self.native.write_bytes(b'{"schema":"same"}\n')
        self.env = os.environ.copy()
        for key in ('CARGO_BUILD_TARGET_DIR', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTFLAGS'):
            self.env.pop(key, None)
        # Cargo freshness is under test, not compiler-cache behavior. These tiny
        # std-only crates bypass wrappers so unrelated cache work cannot delay
        # them; every output remains task-owned and is removed by cleanup.
        self.env.update(CARGO_TARGET_DIR=str(self.root / 'target'),
                        CARGO_BUILD_BUILD_DIR=str(self.root / 'build'),
                        CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0', CARGO_TERM_COLOR='never',
                        RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='')

    def add_core(self):
        self.core.parent.mkdir(parents=True)
        self.core.write_bytes(self.native.read_bytes())

    def check(self, *, failure=None):
        child = subprocess.Popen(['cargo', 'check', '--offline', '--message-format', 'json'],
                                 cwd=self.crate, env=self.env, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, start_new_session=os.name != 'nt')
        try:
            stdout, stderr = child.communicate(timeout=60)
        except BaseException:
            if os.name == 'nt':
                child.kill()
            else:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.communicate()
            raise
        if failure:
            self.assertNotEqual(child.returncode, 0, stdout + stderr)
            self.assertIn(failure, stderr)
            return None
        self.assertEqual(child.returncode, 0, stdout + stderr)
        messages = [json.loads(line) for line in stdout.splitlines() if line.startswith('{')]
        libraries = [message for message in messages if message.get('reason') == 'compiler-artifact'
                     and message['target']['kind'] == ['lib']]
        self.assertEqual(len(libraries), 1, stdout)
        return libraries[0]['fresh']

    def test_repository_second_build_is_fresh_and_either_schema_drift_fails(self):
        self.add_core()
        self.assertFalse(self.check())
        self.assertTrue(self.check(), 'unchanged schema must not rebuild JACS or dependents')
        original = self.native.read_bytes()
        self.native.write_bytes(b'{"schema":"native drift"}\n')
        self.check(failure='agreement v2 schema drift')
        self.native.write_bytes(original)
        self.core.write_bytes(b'{"schema":"core drift"}\n')
        self.check(failure='agreement v2 schema drift')
        self.native.write_bytes(self.core.read_bytes())
        self.assertFalse(self.check(), 'matching schema changes must invalidate the build')
        self.assertTrue(self.check())

    def test_published_layout_without_portable_core_stays_fresh(self):
        self.assertFalse(self.core.parent.exists())
        self.assertFalse(self.check())
        self.assertTrue(self.check(), 'absent source-tree sibling must not be watched')
        self.native.write_bytes(b'{"schema":"published update"}\n')
        self.assertFalse(self.check())
        self.assertTrue(self.check())

    def test_existing_core_directory_with_missing_schema_fails_closed(self):
        self.add_core()
        self.core.unlink()
        self.check(failure='cannot read')

    def test_native_schema_must_be_readable_even_without_portable_core(self):
        self.native.unlink()
        self.check(failure='cannot read')

    def test_unreadable_schema_paths_cannot_compare_as_two_empty_values(self):
        self.add_core()
        # Directories fail fs::read even when the test runner has elevated rights.
        for schema in (self.native, self.core):
            schema.unlink()
            schema.mkdir()
        self.check(failure='cannot read')

    def test_unreadable_portable_schema_fails_closed(self):
        self.add_core()
        self.core.unlink()
        self.core.mkdir()
        self.check(failure='cannot read')


if __name__ == '__main__':
    unittest.main()
