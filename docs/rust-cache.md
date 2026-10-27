# Shared Rust cache for local worktrees

Separate projects and worktrees can use one [kache](https://github.com/kunobi-ninja/kache)
store while keeping separate Cargo outputs for each worktree. This is optional
local development tooling; normal builds do not require kache.

**Run setup once per user and Cargo home on each machine**, from the JACS root:

```sh
make rust-cache-preview  # Inspect paths and wrapper conflicts; no writes
make rust-cache-setup    # Install/configure pinned kache 0.23.1 once
make rust-cache-smoke    # Small offline check with disposable source/target dirs
make rust-cache-status   # Shared store usage and hit/miss counters
```

If you already configured it for another project, JACS uses that same user
configuration and cache; no second install is needed. Existing and future worktrees inherit
it, including in new shells and after reboot. A different machine, user,
container or `CARGO_HOME` needs its own setup unless it shares the configured
Cargo home and compatible binary. Keep custom home paths absolute and stable.

Setup requires Python 3.11+, curl, Cargo and `$CARGO_HOME/bin` (normally
`~/.cargo/bin`) on PATH. It supports macOS/Linux ARM64 and x86_64, verifies the
release checksum before execution, and refuses conflicting Rust wrappers or a
different installed kache version. Cargo `include` configurations require manual
review; `KACHE_CONFIG` must be unset, and `XDG_CONFIG_HOME` must be unset or an
absolute path. An empty `CARGO_HOME` uses Cargo's default.

Setup stages and validates the user Cargo edit before publishing it atomically
with an exact backup. Existing profiles, patches, compiler settings, symlinks
and cache configuration are preserved; repeating setup does not duplicate
entries. Avoid editing Cargo configuration concurrently. Unusual TOML layouts
unsupported by the pinned initializer fail without publishing an edit. Setup
does not edit shell startup files or install a login service.

A new cache configuration uses local-only storage, a **10 GiB retention target**
and disabled adaptive incremental storage. New Cargo policy sets
`KACHE_BUILD_SCRIPT_CACHE=0`, preserving normal Cargo build-script execution;
existing explicit policies are preserved and reported. Native C/C++ compiler
settings are left unchanged. The default store is `~/Library/Caches/kache` on
macOS or `$XDG_CACHE_HOME/kache` / `~/.cache/kache` on Linux. Keep cache and
worktrees on the same filesystem for copy-on-write restores; leave unrestricted
shared hardlink restores off for reused targets.

Use the normal build commands after setup. Run `kache doctor` from the affected
Cargo directory when diagnosing overrides or misses. Environment Rust wrappers,
repo Cargo settings, another Cargo home or `.kache.toml` can override user
defaults. Keep **both target and intermediate build directories separate** for
concurrent worktrees; check inherited `CARGO_TARGET_DIR`,
`CARGO_BUILD_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR`. Do not copy local Cargo
configuration that points at another worktree or commit absolute paths/a required
wrapper. Toolchain, profile, feature and dependency differences can prevent hits.

**Disk use and cleanup.** Enabling the cache does not import or deduplicate old
outputs. It fills on subsequent compilations. The retention target is not a disk
quota: live targets can retain shared blocks and other outputs occupy space.
Check `df -h` before substantial builds; `du` can count APFS shared blocks more
than once. Inspect `kache report --last-build` for hits and reflink/copy bytes.
Use `--root` to select a specific recorded build root during concurrent work.
Preview observed stale targets with `kache clean --tracked --stale 14d --dry-run`;
for older targets, use `kache clean --dry-run` from a specific checkout and review
every path. Stop builds and clean only selected disposable targets, then run
`kache gc`. Setup and smoke never delete existing targets. Do not automate a broad
cleanup while other worktrees are active.

**Verification and recovery.** `make rust-cache-smoke` builds a dependency-free
probe in separate directories with a private cache, checks warm reuse and
changed-source failure, then tests bypass and removes its temporary outputs.
It does not qualify JACS crypto, native, mobile/WASM or release workloads.
Proc macros with undeclared file/environment inputs need workload-specific
checks or bypass rules. Disabling incremental storage can slow repeated edits;
different filesystems may require copies. Keep release validation separate.

`KACHE_DISABLED=1` bypasses caching for compilations Cargo schedules; it does not
invalidate Cargo-fresh outputs and still strips incremental flags. For fully
unwrapped diagnosis, use fresh disposable target and intermediate directories:

```sh
rust_cache_trial="$(mktemp -d)"
RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER='' \
  CARGO_BUILD_BUILD_DIR="$rust_cache_trial/target" \
  cargo build --locked --target-dir "$rust_cache_trial/target" -p jacs-cli
```

Review/remove that directory afterward. To roll back setup, restore the printed
Cargo backup if no later edits need preserving; otherwise remove only the
`build.rustc-wrapper` and `env.KACHE_BUILD_SCRIPT_CACHE` entries setup added.
Stop the daemon with `kache daemon stop`. If older builds used build-script run
caching, keep the binary until their launchers are rebuilt unwrapped or cleaned.
A failed setup leaves the Cargo config unchanged; a downloaded binary or new
cache config may remain for retry. Installer regressions run through `make check`
or `python3 -m unittest discover -s scripts/tests -p 'test_rust_cache.py'`.
