use jacs_cli::build_cli;
use serde_json::Value;

#[test]
fn focused_command_contract_matches_clap() {
    let contract: Value =
        serde_json::from_str(include_str!("../contract/cli_commands.json")).unwrap();
    let mut declared: Vec<&str> = contract["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|command| command["path"].as_str().unwrap())
        .collect();
    let cli = build_cli();
    let mut actual: Vec<&str> = cli
        .get_subcommands()
        .map(|command| command.get_name())
        .collect();
    declared.sort();
    actual.sort();
    assert_eq!(declared, actual);
    assert!(
        cli.get_subcommands()
            .all(|command| command.get_subcommands().next().is_none())
    );
    let mut mapped_tools: Vec<&str> = contract["commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|command| command["mcp_tool"].as_str())
        .collect();
    let mut mcp_tools = jacs_mcp::contract::TOOL_NAMES.to_vec();
    mapped_tools.sort();
    mcp_tools.sort();
    assert_eq!(
        mapped_tools, mcp_tools,
        "The focused CLI and MCP must share the same primitive contract"
    );
}

#[test]
fn secrets_are_never_cli_arguments_and_removed_surfaces_are_rejected() {
    for command in [
        "email",
        "dns",
        "trust",
        "storage",
        "search",
        "attestation",
        "media",
        "network",
        "serve",
        "agent",
    ] {
        assert!(
            build_cli().try_get_matches_from(["jacs", command]).is_err(),
            "{command}"
        );
    }
    for secret in ["--password", "--private-key", "--new-password"] {
        assert!(
            build_cli()
                .try_get_matches_from([
                    "jacs",
                    "create",
                    "--output",
                    "agent.json",
                    secret,
                    "sentinel"
                ])
                .is_err()
        );
    }
    assert!(
        build_cli()
            .try_get_matches_from(["jacs", "verify", "--input", "signed.json"])
            .is_err()
    );
    assert!(
        build_cli()
            .try_get_matches_from([
                "jacs",
                "verify",
                "--input",
                "signed.json",
                "--agent",
                "a",
                "--public-identity",
                "b"
            ])
            .is_err()
    );
}
