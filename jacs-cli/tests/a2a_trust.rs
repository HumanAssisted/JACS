use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;
use std::fs;

#[test]
#[serial]
fn a2a_trust_warns_that_agent_cards_are_unverified_bookmarks() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let trust_dir = temp_dir.path().join("trust-store");
    let card_path = temp_dir.path().join("agent-card.json");

    let card_json = serde_json::json!({
        "name": "bookmark-only-agent",
        "description": "Unsigned A2A card for regression testing",
        "version": "1.0.0",
        "protocolVersions": ["0.4.0"],
        "supportedInterfaces": [{
            "url": "https://example.test/agent/bookmark-only-agent",
            "protocolBinding": "jsonrpc"
        }],
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "capabilities": {
            "extensions": [{
                "uri": "urn:jacs:provenance-v1",
                "description": "JACS cryptographic provenance",
                "required": false
            }]
        },
        "skills": [],
        "metadata": {
            "jacsId": "550e8400-e29b-41d4-a716-446655440060",
            "jacsVersion": "550e8400-e29b-41d4-a716-446655440061"
        }
    });
    fs::write(
        &card_path,
        serde_json::to_string_pretty(&card_json).expect("serialize card"),
    )
    .expect("write card");

    let mut cmd = Command::cargo_bin("jacs").expect("cargo bin jacs");
    cmd.env("JACS_TRUST_STORE_DIR", &trust_dir).args([
        "a2a",
        "trust",
        card_path.to_str().expect("card path str"),
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("unverified A2A Agent Card"))
        .stdout(predicate::str::contains("bookmark"))
        .stdout(predicate::str::contains("Trusted agent").not());
}
