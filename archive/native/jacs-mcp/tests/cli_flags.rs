use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn standalone_binary_prints_deprecation_and_exits() {
    // The compatibility package ships its deprecated standalone binary under the
    // package name, `jacs-mcp-compat`.
    let mut cmd =
        Command::cargo_bin("jacs-mcp-compat").expect("jacs-mcp-compat binary should build");
    cmd.assert()
        .failure()
        .stderr(contains("deprecated"))
        .stderr(contains("jacs mcp"));
}
