#!/usr/bin/env python3
"""Set up one local kache store for Cargo builds in every repo/worktree.

Python 3.11+, curl, and Cargo are required. Preview is the default; --apply
installs a checksum-pinned release and delegates Cargo configuration to kache.
"""

import argparse
import copy
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib


VERSION = "0.23.1"
# Digests published with https://github.com/kunobi-ninja/kache/releases/tag/v0.23.1
RELEASES = {
    ("Darwin", "arm64"): ("aarch64-apple-darwin", "c2d16f19ffcf369cacc562c6f4343a81e442feaad1b1abf0fd437b0b17c3e3f5"),
    ("Darwin", "x86_64"): ("x86_64-apple-darwin", "313560f5df5170e92612817a44c41f6ac1bfc13ec13ea2290f412aa3bd06cbf6"),
    ("Linux", "aarch64"): ("aarch64-unknown-linux-musl", "3ade5ccdcba4aaae66b9896b8ff258071aff0296398a11dd880c6cc1240084af"),
    ("Linux", "x86_64"): ("x86_64-unknown-linux-musl", "f79ed4e865ccaccdf1288ac51d0b2e1e0a9b316aaea60a871cecee556f382943"),
}
DEFAULT_CONFIG = """# Shared local cache for JACS, haiai, musubi, hai, and their worktrees.
# This is a retention target, not a hard disk quota; live targets retain blocks.
[cache]
local_max_size = "10GiB"
local_only = true
adaptive_incremental = false
"""
NATIVE_DEFAULTS = {
    "HOST_CC": "kache cc",
    "HOST_CXX": "kache c++",
    "CC_KNOWN_WRAPPER_CUSTOM": "kache",
}


def read_toml(path):
    return tomllib.loads(path.read_text()) if path.exists() else {}


def cargo_config_path(cargo_dir):
    canonical, legacy = cargo_dir / "config.toml", cargo_dir / "config"
    if canonical.exists() and legacy.exists():
        raise ValueError(f"Both {canonical} and {legacy} exist; consolidate them before setup.")
    return legacy if legacy.exists() else canonical


def check_wrapper(config, environ):
    if config.get("include"):
        raise ValueError("Cargo config uses includes; review inherited wrappers and configure kache manually.")
    for value in (config.get("build", {}).get("rustc-wrapper"),
                  environ.get("RUSTC_WRAPPER"), environ.get("CARGO_BUILD_RUSTC_WRAPPER")):
        if value and Path(value).name != "kache":
            raise ValueError(f"Existing Rust wrapper {value!r}; choose which wrapper to use before setup.")


def check_version(binary):
    actual = subprocess.check_output([str(binary), "--version"], text=True).strip()
    if actual != f"kache {VERSION}":
        raise ValueError(f"{binary} reports {actual!r}; this setup is qualified with kache {VERSION}. No binary replaced.")


def install(binary, target, digest):
    """Verify before execution; publish without overwriting an existing binary."""
    binary.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".kache-install-", dir=binary.parent) as staging:
        archive = Path(staging) / "release.tar.gz"
        url = f"https://github.com/kunobi-ninja/kache/releases/download/v{VERSION}/kache-{target}.tar.gz"
        subprocess.run([
            "curl", "--fail", "--location", "--silent", "--show-error",
            "--connect-timeout", "15", "--max-time", "120", url, "--output", str(archive),
        ], check=True)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise ValueError("kache release checksum mismatch; nothing installed.")
        staged = Path(staging) / "kache"
        with tarfile.open(archive, "r:gz") as bundle:
            member = bundle.getmember("kache")
            if not member.isfile():
                raise ValueError("kache release does not contain a regular binary.")
            with bundle.extractfile(member) as source, staged.open("xb") as dest:
                shutil.copyfileobj(source, dest)
        staged.chmod(0o755)
        check_version(staged)
        os.link(staged, binary)  # Fails safely if another installer won the race.


def rust_only_config(original, initialized):
    """Narrow the pinned upstream edit, then verify every preserved TOML value."""
    expected = copy.deepcopy(tomllib.loads(original))
    expected.setdefault("build", {})["rustc-wrapper"] = "kache"
    original_env = expected.setdefault("env", {})
    for key, value in NATIVE_DEFAULTS.items():
        if key not in original_env:
            line = f'{key} = "{value}"\n'
            if initialized.count(line) != 1:
                raise ValueError(f"Unexpected kache native-compiler edit for {key}; user config left unchanged.")
            initialized = initialized.replace(line, "", 1)
    if "KACHE_BUILD_SCRIPT_CACHE" not in original_env:
        # Non-forced: an explicit per-build environment choice still wins.
        initialized += '\n[env.KACHE_BUILD_SCRIPT_CACHE]\nvalue = "0"\n'
        original_env["KACHE_BUILD_SCRIPT_CACHE"] = {"value": "0"}
    if tomllib.loads(initialized) != expected:
        raise ValueError("Unexpected kache configuration changes; user config left unchanged.")
    return initialized


def publish_cargo_config(path, original, updated):
    """Atomically publish a verified edit, retaining the exact original backup."""
    path = path.resolve()  # Preserve a user's config symlink.
    current = path.read_bytes() if path.exists() else None
    if current != original:
        raise ValueError("Cargo config changed during setup; rerun after the other edit finishes.")
    payload = updated.encode()
    if payload == original:
        return
    with tempfile.TemporaryDirectory(prefix=".kache-config-", dir=path.parent) as staging:
        staged = Path(staging) / "config"
        staged.write_bytes(payload)
        staged.chmod(path.stat().st_mode & 0o777 if original is not None else 0o600)
        if original is not None:
            with tempfile.NamedTemporaryFile(prefix=".kache-cargo-backup-", dir=path.parent, delete=False) as backup:
                backup.write(original)
            print(f"Cargo config backup: {backup.name}", flush=True)
        if original is None:
            os.link(staged, path)  # Do not overwrite a config created concurrently.
        else:
            os.replace(staged, path)


def setup(apply=False):
    if "KACHE_CONFIG" in os.environ:
        raise ValueError("Unset KACHE_CONFIG for user-wide setup (including an empty value); per-build overrides remain supported afterward.")
    # Cargo treats an empty CARGO_HOME as unset and does not expand literal ~.
    cargo_dir = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo").resolve()
    cargo_config = cargo_config_path(cargo_dir)
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config is not None and not Path(xdg_config).is_absolute():
        raise ValueError("XDG_CONFIG_HOME must be an absolute path or unset; a relative/empty value makes kache settings depend on the checkout.")
    config_dir = Path(xdg_config if xdg_config is not None else Path.home() / ".config").resolve()
    cache_config = config_dir / "kache/config.toml"
    original = cargo_config.read_bytes() if cargo_config.exists() else None
    cargo_values = tomllib.loads(original.decode()) if original is not None else {}
    check_wrapper(cargo_values, os.environ)
    read_toml(cache_config)  # Refuse malformed configuration before any writes.
    found = shutil.which("kache")
    binary = Path(found).resolve() if found else cargo_dir / "bin/kache"
    release = RELEASES.get((platform.system(), platform.machine()))
    if found:
        check_version(binary)
    else:
        if not release:
            raise ValueError(f"No pinned binary for this platform. Install kache {VERSION} on PATH first.")
        search_dirs = {Path(p).resolve() for p in os.get_exec_path() if p}
        if binary.parent not in search_dirs:
            raise ValueError(f"Add {binary.parent} to PATH before setup; Cargo must be able to find kache in future shells.")
        if binary.exists() or binary.is_symlink():
            raise ValueError(f"{binary} exists but is not executable on PATH; inspect it before setup.")

    print(f"{'Use' if found else 'Install'} kache {VERSION}: {binary}", flush=True)
    print("One-time setup for this user/Cargo home; current and future worktrees inherit it.", flush=True)
    print(f"Cargo config (all repos/worktrees using this Cargo home): {cargo_config}", flush=True)
    print(f"{'Preserve existing' if cache_config.exists() else 'Create local 10 GiB'} cache config: {cache_config}", flush=True)
    print("Rust artifact caching only; existing native compiler settings are preserved.", flush=True)
    build_script_policy = cargo_values.get("env", {}).get("KACHE_BUILD_SCRIPT_CACHE")
    if build_script_policy is not None:
        print(f"Preserve existing KACHE_BUILD_SCRIPT_CACHE policy: {build_script_policy!r}", flush=True)
        if build_script_policy not in ("0", {"value": "0"}):
            print("Enabling build-script run caching can reuse undeclared native inputs.", flush=True)
    else:
        print("Default build-script run caching to off; scripts retain their normal Cargo execution rules.", flush=True)
    print("Existing targets are not removed. No login service or shell edits.", flush=True)
    if not apply:
        print("Preview only. Run make rust-cache-setup to apply.")
        return

    if not found:
        install(binary, *release)
    cache_config.parent.mkdir(parents=True, exist_ok=True)
    try:
        with cache_config.open("x") as stream:
            stream.write(DEFAULT_CONFIG)
    except FileExistsError:
        pass
    cargo_dir.mkdir(parents=True, exist_ok=True)
    # Stage upstream's formatting-preserving edit so its added HOST_CC/HOST_CXX
    # never override a user's plain CC/CXX, even briefly. Only publish once the
    # complete Rust-only configuration has been validated. Absolute child paths
    # also preserve the meaning of relative CARGO_HOME/PATH across this chdir.
    with tempfile.TemporaryDirectory(prefix=".kache-setup-", dir=cargo_dir) as staging:
        staged_cargo = Path(staging)
        staged_config = staged_cargo / cargo_config.name
        if original is not None:
            staged_config.write_bytes(original)
        child_env = {
            **os.environ, "CARGO_HOME": str(staged_cargo), "XDG_CONFIG_HOME": str(config_dir),
            "KACHE_CONFIG": str(cache_config),
            "PATH": os.pathsep.join(str(Path(p or ".").resolve()) for p in os.get_exec_path()),
        }
        result = subprocess.run(
            [str(binary), "init", "--yes", "--no-service", "--no-shell"],
            cwd=staged_cargo, env=child_env, text=True, capture_output=True,
        )
        if result.returncode:
            raise ValueError(f"kache init failed; user Cargo config left unchanged.\n{result.stdout}\n{result.stderr}")
        updated = rust_only_config((original or b"").decode(), staged_config.read_text())
        publish_cargo_config(cargo_config, original, updated)
    print("Ready. Use normal cargo commands in JACS, haiai, musubi, and hai.")
    print("Run make rust-cache-smoke to verify reuse, then kache stats to inspect the shared store.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="install/configure; otherwise preview without writes")
    args = parser.parse_args()
    try:
        setup(args.apply)
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"rust-cache: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
