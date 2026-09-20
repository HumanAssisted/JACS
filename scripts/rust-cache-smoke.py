#!/usr/bin/env python3
"""Offline reuse/invalidation check using a disposable, dependency-free Rust crate.

Only temporary copies and a private kache store are touched. No cargo clean,
user configuration edits, downloads, or pre-existing targets are involved.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


# Keep the probe independent of the portable and archived workspaces. It tests
# cache behavior without downloading or compiling JACS dependencies.
MANIFEST = """[package]
name = "jacs-cache-smoke"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]
"""
LOCKFILE = """version = 4

[[package]]
name = "jacs-cache-smoke"
version = "0.0.0"
"""
SOURCE = """pub fn cache_probe() -> &'static str { "jacs-cache-smoke" }

#[test]
fn original_source_runs() { assert_eq!(cache_probe(), "jacs-cache-smoke"); }
"""


def smoke_environment(root, binary, inherited):
    # Cargo's separate build-dir option is independent of --target-dir. Drop
    # inherited Cargo configuration/flags and set both output locations below.
    env = {k: v for k, v in inherited.items()
           if not k.startswith(("KACHE_", "CARGO_")) and k not in {"RUSTFLAGS", "RUSTDOCFLAGS"}}
    env.update({
        "KACHE_CONFIG": str(root / "kache.toml"), "KACHE_HOST_CONFIG": "",
        "KACHE_CACHE_DIR": str(root / "cache"), "KACHE_RUNTIME_DIR": str(root / "run"),
        "KACHE_BUILD_SCRIPT_CACHE": "0",
        "RUSTC_WRAPPER": str(binary), "RUSTC_WORKSPACE_WRAPPER": "",
        "CARGO_HOME": str(root / "cargo"), "CARGO_INCREMENTAL": "0",
    })
    return env


def smoke(binary):
    # Keep the Unix socket path short, including on macOS's long default TMPDIR.
    with tempfile.TemporaryDirectory(prefix="jacs-kache-", dir="/tmp") as folder:
        root = Path(folder).resolve()
        config = root / "kache.toml"
        config.write_text('[cache]\nlocal_max_size = "256MiB"\nlocal_only = true\nadaptive_incremental = false\n')
        env = smoke_environment(root, binary, os.environ)

        def build(name, *, changed=False, disabled=False):
            dest = root / name
            dest.mkdir()
            (dest / "Cargo.toml").write_text(MANIFEST)
            (dest / "Cargo.lock").write_text(LOCKFILE)
            (dest / "src").mkdir()
            (dest / "src/lib.rs").write_text(SOURCE)
            if changed:
                # A cached pre-change executable would incorrectly pass. This
                # deliberate failure must surface from the changed source.
                with (dest / "src/lib.rs").open("a") as stream:
                    stream.write('\n#[test]\nfn cache_invalidation_probe() { panic!("changed-source-observed"); }\n')
            result = subprocess.run([
                "cargo", "test", "--offline", "--locked", "--manifest-path", str(dest / "Cargo.toml"),
                "--target-dir", str(dest / "target"),
            ], cwd=dest, env={
                **env, "KACHE_DISABLED": "1" if disabled else "0",
                "CARGO_BUILD_BUILD_DIR": str(dest / "target"),
            }, text=True, capture_output=True)
            if changed:
                if result.returncode != 101 or "changed-source-observed" not in result.stdout:
                    raise RuntimeError(f"Source invalidation check failed:\n{result.stdout}\n{result.stderr}")
            elif result.returncode:
                raise RuntimeError(f"{name} failed:\n{result.stdout}\n{result.stderr}")
            report = json.loads(subprocess.check_output([
                str(binary), "report", "--root", str(dest), "--format", "json",
            ], cwd=dest, env=env, text=True))
            summary = report["summary"]
            if summary["errors"] or summary["store_failures"]:
                raise RuntimeError(f"{name}: cache errors: {summary}")
            print(f"{name}: {summary['local_hits']} hits, {summary['misses']} misses; "
                  f"{report['storage']['reflinked_bytes']} reflinked bytes, "
                  f"{report['storage']['copied_bytes']} copied bytes", flush=True)
            return report

        try:
            first = build("first")
            second = build("second")
            if (first["summary"]["misses"] == 0
                    or second["summary"]["local_hits"] != first["summary"]["misses"]
                    or second["summary"]["misses"] != 0):
                raise RuntimeError("Expected every cold compile to hit in a separate source/target directory.")
            changed = build("changed", changed=True)
            if changed["summary"]["misses"] == 0:
                raise RuntimeError("Changed source was not compiled.")
            bypass = build("bypass", disabled=True)
            if bypass["summary"]["local_hits"]:
                raise RuntimeError("KACHE_DISABLED=1 unexpectedly restored cached artifacts.")
            print("PASS: original tests, cross-directory reuse, changed-source failure, and uncached fallback.")
            if not second["storage"]["reflinked_bytes"]:
                print("No copy-on-write restores observed; this filesystem may not provide worktree disk savings.")
        finally:
            subprocess.run([str(binary), "daemon", "stop"], env=env, cwd=root, capture_output=True, timeout=15)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kache", default="kache", help="kache executable (default: PATH)")
    args = parser.parse_args()
    found = shutil.which(args.kache)
    if not found:
        parser.error("kache not found; run make rust-cache-setup first")
    smoke(Path(found).resolve())
