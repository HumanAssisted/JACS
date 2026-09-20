"""Setup failure/recovery checks; the real Rust flow is make rust-cache-smoke."""

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import chdir, redirect_stdout
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "rust-cache.py"
SPEC = importlib.util.spec_from_file_location("rust_cache", SCRIPT)
CACHE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE)
SMOKE_SPEC = importlib.util.spec_from_file_location("rust_cache_smoke", SCRIPT.with_name("rust-cache-smoke.py"))
SMOKE = importlib.util.module_from_spec(SMOKE_SPEC)
SMOKE_SPEC.loader.exec_module(SMOKE)
NATIVE_ENV = ''.join(f'{key} = "{value}"\n' for key, value in CACHE.NATIVE_DEFAULTS.items())
NATIVE_EMPTY_CONFIG = '[build]\nrustc-wrapper = "kache"\n[env]\n' + NATIVE_ENV


class RustCacheSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rust-cache-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.cargo = self.root / "cargo"
        self.config = self.root / "config"
        self.env = patch.dict(os.environ, {
            "CARGO_HOME": str(self.cargo), "XDG_CONFIG_HOME": str(self.config),
            "PATH": str(self.cargo / "bin"),
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        output = redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def test_preview_writes_nothing_and_does_not_download(self):
        with patch.object(CACHE, "install") as install, patch.object(CACHE.subprocess, "run") as run:
            CACHE.setup()
        install.assert_not_called()
        run.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_empty_cargo_home_uses_default_instead_of_checkout(self):
        user_dir = self.root / "user"
        expected_cargo = user_dir / ".cargo"
        def initialize(argv, **kwargs):
            staged = Path(kwargs["env"]["CARGO_HOME"])
            self.assertEqual(staged.parent, expected_cargo)
            (staged / "config.toml").write_text(NATIVE_EMPTY_CONFIG)
            return subprocess.CompletedProcess(argv, 0, "", "")
        with chdir(self.root), patch.dict(os.environ, {"CARGO_HOME": ""}), \
                patch.object(CACHE.Path, "home", return_value=user_dir), \
                patch.object(CACHE.shutil, "which", return_value="/bin/kache"), \
                patch.object(CACHE, "check_version"), patch.object(CACHE.subprocess, "run", side_effect=initialize):
            CACHE.setup(apply=True)
        self.assertEqual(CACHE.read_toml(expected_cargo / "config.toml")["build"]["rustc-wrapper"], "kache")
        self.assertFalse((self.root / "config.toml").exists())

    def test_kache_config_override_even_empty_requires_manual_setup(self):
        for value in ("", "/custom/kache.toml"):
            with self.subTest(value=value), patch.dict(os.environ, {"KACHE_CONFIG": value}), \
                    patch.object(CACHE, "install") as install:
                with self.assertRaisesRegex(ValueError, "Unset KACHE_CONFIG"):
                    CACHE.setup(apply=True)
                install.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_xdg_config_home_must_be_absolute_for_persistent_setup(self):
        for value in ("", "config", "~/.config"):
            with self.subTest(value=value), patch.dict(os.environ, {"XDG_CONFIG_HOME": value}):
                with self.assertRaisesRegex(ValueError, "XDG_CONFIG_HOME.*absolute"):
                    CACHE.setup()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_conflicting_wrapper_refused_before_any_install(self):
        self.cargo.mkdir()
        original = '[build]\nrustc-wrapper = "sccache"\n[profile.dev]\ndebug = 1\n'
        (self.cargo / "config.toml").write_text(original)
        with patch.object(CACHE, "install") as install:
            with self.assertRaisesRegex(ValueError, "Existing Rust wrapper"):
                CACHE.setup(apply=True)
        install.assert_not_called()
        self.assertEqual((self.cargo / "config.toml").read_text(), original)
        self.assertFalse(self.config.exists())

    def test_environment_wrapper_refused(self):
        for key in ["RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER"]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "Existing Rust wrapper"):
                CACHE.check_wrapper({}, {key: "/tools/custom-wrapper"})

    def test_included_cargo_settings_are_not_silently_overridden(self):
        with self.assertRaisesRegex(ValueError, "includes"):
            CACHE.check_wrapper({"include": ["compiler.toml"]}, {})

    def test_different_installed_version_is_not_replaced(self):
        with patch.object(CACHE.shutil, "which", return_value="/tools/kache"), \
                patch.object(CACHE.subprocess, "check_output", return_value="kache 0.22.0\n"), \
                patch.object(CACHE, "install") as install:
            with self.assertRaisesRegex(ValueError, "No binary replaced"):
                CACHE.setup(apply=True)
        install.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_legacy_cargo_config_and_ambiguous_pair(self):
        self.cargo.mkdir()
        legacy = self.cargo / "config"
        legacy.write_text("[build]\n")
        self.assertEqual(CACHE.cargo_config_path(self.cargo), legacy)
        (self.cargo / "config.toml").write_text("")
        with self.assertRaisesRegex(ValueError, "Both"):
            CACHE.cargo_config_path(self.cargo)

    def test_existing_cache_config_preserved_and_upstream_owns_cargo_edit(self):
        self.config.joinpath("kache").mkdir(parents=True)
        config = self.config / "kache/config.toml"
        original = '# User choice\n[cache]\nlocal_max_size = "4GiB"\nlocal_only = true\n'
        config.write_text(original)
        def initialize(argv, **kwargs):
            staged = Path(kwargs["env"]["CARGO_HOME"])
            self.assertNotEqual(staged, self.cargo)
            self.assertFalse((self.cargo / "config.toml").exists())
            (staged / "config.toml").write_text(NATIVE_EMPTY_CONFIG)
            return subprocess.CompletedProcess(argv, 0, "", "")
        with patch.object(CACHE.shutil, "which", return_value="/bin/kache"), \
                patch.object(CACHE, "check_version"), \
                patch.object(CACHE.subprocess, "run", side_effect=initialize) as run:
            CACHE.setup(apply=True)
        self.assertEqual(config.read_text(), original)
        self.assertEqual(run.call_count, 1)
        published = CACHE.read_toml(self.cargo / "config.toml")
        self.assertEqual(published["env"], {"KACHE_BUILD_SCRIPT_CACHE": {"value": "0"}})
        self.assertEqual(published["build"]["rustc-wrapper"], "kache")

    def test_failed_upstream_init_leaves_original_cargo_config_unchanged(self):
        self.cargo.mkdir()
        config = self.cargo / "config.toml"
        original = b'[profile.dev]\ndebug = "line-tables-only"\n'
        config.write_bytes(original)
        with patch.object(CACHE.shutil, "which", return_value="/bin/kache"), \
                patch.object(CACHE, "check_version"), \
                patch.object(CACHE.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "bad config")):
            with self.assertRaisesRegex(ValueError, "user Cargo config left unchanged"):
                CACHE.setup(apply=True)
        self.assertEqual(config.read_bytes(), original)
        self.assertEqual(list(self.cargo.iterdir()), [config])

    def test_relative_environment_paths_are_normalized_before_chdir(self):
        def initialize(argv, **kwargs):
            self.assertEqual(argv[0], str(self.root / "tools/kache"))
            staged = Path(kwargs["env"]["CARGO_HOME"])
            self.assertEqual(staged.parent, self.cargo)
            self.assertEqual(kwargs["env"]["XDG_CONFIG_HOME"], str(self.config))
            self.assertEqual(kwargs["env"]["PATH"], str(self.root / "tools"))
            (staged / "config.toml").write_text(NATIVE_EMPTY_CONFIG)
            return subprocess.CompletedProcess(argv, 0, "", "")
        with chdir(self.root), patch.dict(os.environ, {"CARGO_HOME": "cargo", "PATH": "tools"}), \
                patch.object(CACHE.shutil, "which", return_value="tools/kache"), \
                patch.object(CACHE, "check_version"), patch.object(CACHE.subprocess, "run", side_effect=initialize):
            CACHE.setup(apply=True)
        self.assertEqual(CACHE.read_toml(self.cargo / "config.toml")["build"]["rustc-wrapper"], "kache")

    def test_cargo_home_literal_tilde_is_not_shell_expanded(self):
        expected_cargo = self.root / "~" / "cargo"
        def initialize(argv, **kwargs):
            staged = Path(kwargs["env"]["CARGO_HOME"])
            self.assertEqual(staged.parent, expected_cargo)
            (staged / "config.toml").write_text(NATIVE_EMPTY_CONFIG)
            return subprocess.CompletedProcess(argv, 0, "", "")
        with chdir(self.root), patch.dict(os.environ, {"CARGO_HOME": "~/cargo"}), \
                patch.object(CACHE.Path, "expanduser", return_value=self.cargo), \
                patch.object(CACHE.shutil, "which", return_value="/bin/kache"), \
                patch.object(CACHE, "check_version"), patch.object(CACHE.subprocess, "run", side_effect=initialize):
            CACHE.setup(apply=True)
        self.assertEqual(CACHE.read_toml(expected_cargo / "config.toml")["build"]["rustc-wrapper"], "kache")

    def test_legacy_setup_does_not_create_a_shadow_config(self):
        self.cargo.mkdir()
        config = self.cargo / "config"
        original = b'[profile.dev]\ndebug = 1\n'
        config.write_bytes(original)
        def initialize(argv, **kwargs):
            staged = Path(kwargs["env"]["CARGO_HOME"])
            self.assertEqual((staged / "config").read_bytes(), original)
            self.assertFalse((staged / "config.toml").exists())
            (staged / "config").write_text(original.decode() + NATIVE_EMPTY_CONFIG)
            return subprocess.CompletedProcess(argv, 0, "", "")
        with patch.object(CACHE.shutil, "which", return_value="/bin/kache"), \
                patch.object(CACHE, "check_version"), patch.object(CACHE.subprocess, "run", side_effect=initialize):
            CACHE.setup(apply=True)
        self.assertFalse((self.cargo / "config.toml").exists())
        self.assertEqual(CACHE.read_toml(config)["build"]["rustc-wrapper"], "kache")
        self.assertEqual([p.read_bytes() for p in self.cargo.glob('.kache-cargo-backup-*')], [original])

    def test_native_compiler_choices_and_explicit_script_policy_preserved(self):
        original = '[env]\nCC = "custom-cc"\nCXX = "custom-cxx"\nHOST_CC = "host-cc"\nKACHE_BUILD_SCRIPT_CACHE = "1"\n'
        initialized = original + 'HOST_CXX = "kache c++"\nCC_KNOWN_WRAPPER_CUSTOM = "kache"\n[build]\nrustc-wrapper = "kache"\n'
        updated = CACHE.rust_only_config(original, initialized)
        self.assertEqual(CACHE.tomllib.loads(updated)["env"], CACHE.tomllib.loads(original)["env"])

    def test_unexpected_native_edits_are_refused(self):
        original = '[profile.dev]\ndebug = 1\n'
        initialized = NATIVE_EMPTY_CONFIG + '[profile.dev]\ndebug = 2\n'
        with self.assertRaisesRegex(ValueError, "Unexpected kache configuration changes"):
            CACHE.rust_only_config(original, initialized)

    def test_atomic_publish_keeps_config_symlink_and_exact_backup(self):
        self.cargo.mkdir()
        actual = self.root / "shared.toml"
        original = b'# keep this comment\n[profile.dev]\ndebug = 1\n'
        actual.write_bytes(original)
        actual.chmod(0o640)
        config = self.cargo / "config.toml"
        config.symlink_to(actual)
        updated = original.decode() + '[build]\nrustc-wrapper = "kache"\n'
        CACHE.publish_cargo_config(config, original, updated)
        self.assertTrue(config.is_symlink())
        self.assertEqual(actual.read_text(), updated)
        self.assertEqual(actual.stat().st_mode & 0o777, 0o640)
        backups = list(self.root.glob('.kache-cargo-backup-*'))
        self.assertEqual([p.read_bytes() for p in backups], [original])
        CACHE.publish_cargo_config(config, updated.encode(), updated)
        self.assertEqual(list(self.root.glob('.kache-cargo-backup-*')), backups)

    def test_concurrent_config_edit_is_preserved(self):
        config = self.root / "config.toml"
        config.write_bytes(b'# another edit\n')
        with self.assertRaisesRegex(ValueError, "changed during setup"):
            CACHE.publish_cargo_config(config, b'# original\n', '# desired\n')
        self.assertEqual(config.read_bytes(), b'# another edit\n')
        self.assertEqual(list(self.root.iterdir()), [config])

    def test_smoke_cannot_inherit_cargo_build_paths_or_flags(self):
        inherited = {
            "PATH": "/bin", "CARGO_BUILD_BUILD_DIR": "/external/shared",
            "CARGO_TARGET_DIR": "/external/target", "CARGO_ENCODED_RUSTFLAGS": "-Cpanic=abort",
            "CARGO_BUILD_TARGET": "wasm32-unknown-unknown", "RUSTFLAGS": "-Dwarnings",
            "KACHE_SOCKET_PATH": "/external/daemon.sock", "KACHE_BUILD_SCRIPT_CACHE": "1",
        }
        env = SMOKE.smoke_environment(self.root, Path('/bin/kache'), inherited)
        self.assertFalse(set(inherited).intersection(env) - {"PATH", "KACHE_BUILD_SCRIPT_CACHE"})
        self.assertEqual(env["KACHE_BUILD_SCRIPT_CACHE"], "0")
        self.assertEqual(env["CARGO_HOME"], str(self.root / "cargo"))
        class StopProbe(Exception):
            pass
        def intercept(argv, **kwargs):
            if argv[0] == "cargo":
                self.assertEqual(kwargs["env"]["CARGO_BUILD_BUILD_DIR"], argv[-1])
                self.assertIn("jacs-kache-", argv[-1])
                raise StopProbe
            return subprocess.CompletedProcess(argv, 0, "", "")
        with patch.dict(os.environ, inherited), patch.object(SMOKE.subprocess, "run", side_effect=intercept):
            with self.assertRaises(StopProbe):
                SMOKE.smoke(Path('/bin/kache'))

    def test_malformed_config_refused_before_install(self):
        self.config.joinpath("kache").mkdir(parents=True)
        (self.config / "kache/config.toml").write_text("[invalid")
        with patch.object(CACHE, "install") as install:
            with self.assertRaises(ValueError):
                CACHE.setup(apply=True)
        install.assert_not_called()

    def test_non_path_install_refused_without_creating_directories(self):
        with patch.dict(os.environ, {"PATH": "/unrelated-bin"}):
            with self.assertRaisesRegex(ValueError, "PATH"):
                CACHE.setup(apply=True)
        self.assertEqual(list(self.root.iterdir()), [])

    def archive(self, *, symlink=False):
        archive = self.root / "archive.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            member = tarfile.TarInfo("kache")
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "/unexpected"
                bundle.addfile(member)
            else:
                member.size = 13
                bundle.addfile(member, io.BytesIO(b"test artifact"))
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def download(self, archive):
        def fake_run(argv, **kwargs):
            shutil.copyfile(archive, argv[-1])
        return fake_run

    def test_checksum_failure_cannot_install_or_execute_binary(self):
        archive, _ = self.archive()
        binary = self.cargo / "bin/kache"
        with patch.object(CACHE.subprocess, "run", side_effect=self.download(archive)), \
                patch.object(CACHE, "check_version") as execute:
            with self.assertRaisesRegex(ValueError, "checksum"):
                CACHE.install(binary, "test-target", "0" * 64)
        execute.assert_not_called()
        self.assertFalse(binary.exists())
        self.assertEqual(list(binary.parent.iterdir()), [])

    def test_verified_archive_installs_without_overwriting_a_binary(self):
        archive, digest = self.archive()
        binary = self.cargo / "bin/kache"
        with patch.object(CACHE.subprocess, "run", side_effect=self.download(archive)), \
                patch.object(CACHE, "check_version"):
            CACHE.install(binary, "test-target", digest)
            binary.write_bytes(b"existing version")
            with self.assertRaises(FileExistsError):
                CACHE.install(binary, "test-target", digest)
        self.assertEqual(binary.read_bytes(), b"existing version")

    def test_archive_symlink_refused(self):
        archive, digest = self.archive(symlink=True)
        binary = self.cargo / "bin/kache"
        with patch.object(CACHE.subprocess, "run", side_effect=self.download(archive)), \
                patch.object(CACHE, "check_version") as execute:
            with self.assertRaisesRegex(ValueError, "regular binary"):
                CACHE.install(binary, "test-target", digest)
        execute.assert_not_called()
        self.assertFalse(binary.exists())


if __name__ == "__main__":
    unittest.main()
