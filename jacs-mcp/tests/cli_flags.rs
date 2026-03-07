use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn standalone_binary_prints_deprecation_and_exits() {
    let mut cmd = Command::cargo_bin("jacs-mcp").expect("jacs-mcp binary should build");
    cmd.assert()
        .failure()
        .stderr(contains("deprecated"))
        .stderr(contains("jacs mcp"));
}
