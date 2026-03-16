use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn version_flag_prints_version() {
    let mut cmd = Command::cargo_bin("jacs").expect("jacs binary should build");
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}
