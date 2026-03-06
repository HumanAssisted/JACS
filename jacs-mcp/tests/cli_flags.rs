use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn help_flag_prints_usage() {
    let mut cmd = Command::cargo_bin("jacs-mcp").expect("jacs-mcp binary should build");
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(contains("Usage: jacs-mcp"));
}

#[test]
fn version_flag_prints_version() {
    let mut cmd = Command::cargo_bin("jacs-mcp").expect("jacs-mcp binary should build");
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}
