// here I want to test the CLI commands
use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*; // Used for writing assertions
use std::env;
use std::fs::{self, File}; // Add fs for file operations
use std::io::Write; // Add Write trait
use std::path::PathBuf; // Add PathBuf
use std::{error::Error, process::Command}; // Run programs // To read CARGO_PKG_VERSION
use tempfile::tempdir; // Add tempdir

// cargo test   --test cli_tests -- --nocapture

#[test]
fn test_cli_help() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;

    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: jacs [COMMAND]"));

    Ok(())
}

#[test]
fn test_config_read_default() -> Result<(), Box<dyn Error>> {
    // This test assumes default env vars are set or config is minimal
    // More robust tests might set specific env vars
    let mut cmd = Command::cargo_bin("jacs")?;

    cmd.arg("config").arg("read");
    cmd.assert()
        .success()
        // Fix: Match the actual output case and include the colon
        .stdout(predicate::str::contains("JACS_DATA_DIRECTORY:"));

    Ok(())
}

#[test]
fn test_cli_version_subcommand() -> Result<(), Box<dyn Error>> {
    // Renamed for clarity
    let mut cmd = Command::cargo_bin("jacs")?;
    let expected_version_line = format!("jacs version: {}", env!("CARGO_PKG_VERSION"));
    let expected_desc_raw = env!("CARGO_PKG_DESCRIPTION");

    // Test the "version" subcommand
    cmd.arg("version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_version_line))
        .stdout(predicate::str::contains(expected_desc_raw));

    Ok(())
}

// Helper function to get fixture path
fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn test_cli_script_flow() -> Result<(), Box<dyn Error>> {
    // 1. Setup Temp Directory and Paths
    let temp_dir = tempdir()?;
    let temp_path = temp_dir.path();
    let data_dir = temp_path.join("jacs");
    let key_dir = temp_path.join("jacs_keys");
    let config_path = temp_path.join("jacs.config.json"); // Config in temp dir CWD

    // Ensure subdirs exist within the overall temp dir
    fs::create_dir_all(&data_dir)?;
    fs::create_dir_all(&key_dir)?;

    println!("Temp Dir: {}", temp_path.display());
    println!("Data Dir: {}", data_dir.display());
    println!("Key Dir: {}", key_dir.display());
    println!("Config Path: {}", config_path.display());

    // 2. Create jacs.config.json Fixture in Temp Dir
    // Avoids interactive config create; more robust for tests
    let config_content = format!(
        r#"{{
            "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
            "jacs_use_filesystem": true,
            "jacs_use_security": false,
            "jacs_data_directory": "{}",
            "jacs_key_directory": "{}",
            "jacs_agent_private_key_filename": "jacs.private.pem.enc",
            "jacs_agent_public_key_filename": "jacs.public.pem",
            "jacs_agent_key_algorithm": "RSA-PSS",
            "jacs_default_storage": "fs"
        }}"#,
        data_dir.to_str().unwrap().replace('\\', "/"), // Ensure correct path format for JSON
        key_dir.to_str().unwrap().replace('\\', "/")
    );
    let mut config_file = File::create(&config_path)?;
    config_file.write_all(config_content.as_bytes())?;
    println!("Created config file at: {}", config_path.display());

    // 3. Define Environment Variables for Commands
    let dummy_password = "testpassword";

    // 4. Copy Fixtures to Temp Dir
    let agent_raw_path_src = fixture_path("agent.raw.json");
    let agent_raw_path_dest = temp_path.join("agent.raw.json");
    fs::copy(&agent_raw_path_src, &agent_raw_path_dest)?;

    let ddl_path_src = fixture_path("ddl.json");
    let ddl_path_dest = temp_path.join("ddl.json");
    fs::copy(&ddl_path_src, &ddl_path_dest)?;

    let mobius_path_src = fixture_path("mobius.jpeg");
    let mobius_path_dest = temp_path.join("mobius.jpeg");
    fs::copy(&mobius_path_src, &mobius_path_dest)?;
    println!("Copied fixtures to temp dir");

    // --- Run Commands ---

    // Set Current Directory for commands that might rely on it (like config read/create)
    // Alternatively, pass absolute paths always
    let base_cmd = || -> Command {
        let mut cmd = Command::cargo_bin("jacs").unwrap();
        cmd.env("JACS_CONFIG_PATH", &config_path); // Point to config in temp dir
        cmd.env("JACS_DATA_DIRECTORY", &data_dir); // Ensure consistency
        cmd.env("JACS_KEY_DIRECTORY", &key_dir); // Ensure consistency
        cmd.env("JACS_PRIVATE_KEY_PASSWORD", dummy_password); // Avoid interactive prompts
        cmd.current_dir(temp_path); // Run commands from temp dir's perspective
        cmd
    };

    // jacs config read (using the fixture config)
    println!("Running: config read");
    base_cmd()
        .arg("config")
        .arg("read")
        .assert()
        .success()
        .stdout(predicate::str::contains(data_dir.to_str().unwrap())); // Check if data dir from config is shown

    // jacs agent create -f ./agent.raw.json --create-keys=true
    println!("Running: agent create");
    let agent_create_output = base_cmd()
        .arg("agent")
        .arg("create")
        .arg("-f")
        .arg(&agent_raw_path_dest) // Use path in temp dir
        .arg("--create-keys=true")
        .output()?; // Capture output

    assert!(
        agent_create_output.status.success(),
        "agent create failed: {:?}",
        agent_create_output
    );
    let agent_create_stdout = String::from_utf8(agent_create_output.stdout)?;
    println!("Agent Create Output:\n{}", agent_create_stdout);

    // --> Capture Agent ID <-- This part is tricky, assumes format "Agent <ID> created!"
    let agent_id_line = agent_create_stdout
        .lines()
        .find(|line| line.contains("Agent") && line.contains("created!"))
        .unwrap_or("");
    let agent_id = agent_id_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .trim_end_matches('!');
    assert!(!agent_id.is_empty(), "Could not parse agent ID from output");
    println!("Captured Agent ID: {}", agent_id);

    // Check if agent file and keys exist
    assert!(
        key_dir.join("jacs.private.pem.enc").exists(),
        "Private key missing"
    );
    assert!(
        key_dir.join("jacs.public.pem").exists(),
        "Public key missing"
    );
    let agent_file_path = data_dir.join("agent").join(format!("{}.json", agent_id));
    assert!(
        agent_file_path.exists(),
        "Agent file missing: {}",
        agent_file_path.display()
    );

    // jacs document create -f ddl.json --embed=true --attach mobius.jpeg
    println!("Running: document create");
    let doc_create_output = base_cmd()
        .arg("document")
        .arg("create")
        .arg("-f")
        .arg(&ddl_path_dest) // Use path in temp dir
        .arg("--attach")
        .arg(&mobius_path_dest) // Use path in temp dir
        .arg("--embed=true")
        // We need the agent context, specify the created agent file
        .arg("-a")
        .arg(&agent_file_path)
        .output()?; // Capture output

    assert!(
        doc_create_output.status.success(),
        "document create failed: {:?}",
        doc_create_output
    );
    let doc_create_stdout = String::from_utf8(doc_create_output.stdout)?;
    println!("Document Create Output:\n{}", doc_create_stdout);

    // --> Capture Document Filename <-- Assumes format "created doc <filename>" or similar
    let doc_path_line = doc_create_stdout
        .lines()
        .find(|line| line.contains("created doc"))
        .unwrap_or("");
    let doc_relative_path = doc_path_line
        .split("created doc")
        .nth(1)
        .unwrap_or("")
        .trim();
    assert!(
        !doc_relative_path.is_empty(),
        "Could not parse document path from output"
    );
    let doc_full_path = data_dir.join("documents").join(doc_relative_path); // Assuming it saves relative to data_dir/documents
    assert!(
        doc_full_path.exists(),
        "Document file missing: {}",
        doc_full_path.display()
    );
    println!("Captured Document Path: {}", doc_full_path.display());

    // jacs document verify -f ./jacs/documents/... (use captured path)
    println!("Running: document verify");
    base_cmd()
        .arg("document")
        .arg("verify")
        .arg("-f")
        .arg(&doc_full_path) // Use full path to created doc
        .arg("-a")
        .arg(&agent_file_path) // Specify agent for verification context
        .assert()
        .success()
        .stdout(predicate::str::contains("document verified OK"));

    // jacs document create-agreement -f ... --agentids agent1,agent2
    // Using the captured agent ID. Needs another agent ID - let's just use the same one twice for demo
    println!("Running: document create-agreement");
    base_cmd()
        .arg("document")
        .arg("create-agreement")
        .arg("-f")
        .arg(&doc_full_path)
        .arg("-a")
        .arg(&agent_file_path) // Agent context
        .arg("--agentids")
        .arg(format!("{},{}", agent_id, agent_id)) // Use captured ID twice
        .assert()
        .success()
        .stdout(predicate::str::contains("Agreement created")); // Adjust expected output

    // jacs document sign-agreement -f ...
    println!("Running: document sign-agreement");
    base_cmd()
        .arg("document")
        .arg("sign-agreement")
        .arg("-f")
        .arg(&doc_full_path)
        .arg("-a")
        .arg(&agent_file_path) // Agent context for signing
        .assert()
        .success()
        .stdout(predicate::str::contains("signed by")); // Adjust expected output

    // jacs document check-agreement -f ...
    println!("Running: document check-agreement");
    base_cmd()
        .arg("document")
        .arg("check-agreement")
        .arg("-f")
        .arg(&doc_full_path)
        .arg("-a")
        .arg(&agent_file_path) // Agent context
        .assert()
        .success()
        .stdout(predicate::str::contains(agent_id)) // Check if the signing agent ID is listed
        .stdout(predicate::str::contains("signed: true")); // Check status

    // Cleanup is handled by temp_dir going out of scope
    Ok(())
}
