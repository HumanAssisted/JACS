use predicates::str::contains;
use std::path::PathBuf;

/// Resolve the `jacs` binary.  When run via `cargo test -p jacs` the
/// `CARGO_BIN_EXE_jacs` env-var is **not** set (the binary lives in
/// jacs-cli, not jacs).  Fall back to the workspace target directory.
fn jacs_cli_binary() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_jacs")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/debug/jacs"))
}

#[test]
fn version_flag_prints_version() {
    let bin = jacs_cli_binary();
    if !bin.exists() {
        eprintln!(
            "Skipping version_flag_prints_version: jacs binary not found at {}. \
             Run `cargo build -p jacs-cli` first.",
            bin.display()
        );
        return;
    }
    let mut cmd = assert_cmd::Command::new(&bin);
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}
