// here I want to test the CLI commands
use assert_cmd::prelude::*; // Add methods on commands
use base64;
use predicates::prelude::*; // Used for writing assertions
use std::env;
use std::fs::{self, File}; // Add fs for file operations
use std::io::Write; // Add Write trait
use std::path::PathBuf; // Add PathBuf
use std::{
    error::Error,
    process::{Command, Stdio},
}; // Run programs // To read CARGO_PKG_VERSION
use tempfile::tempdir; // Add tempdir // Ensure base64 is imported if used for dummy jpeg

// RUST_BACKTRACE=1 cargo test   --test cli_tests -- --nocapture

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
    let data_dir = temp_path.join("jacs_data"); // Use distinct names
    let key_dir = temp_path.join("jacs_keys");
    // Config will be created by the command in temp_path

    // NOTE: Don't create data/key dirs yet, let config create handle it if necessary,
    // or create them after config create if agent create expects them.
    // fs::create_dir_all(&data_dir)?;
    // fs::create_dir_all(&key_dir)?;

    println!("Temp Dir: {}", temp_path.display());
    println!("(Will create data dir: {})", data_dir.display());
    println!("(Will create key dir: {})", key_dir.display());

    // --- Run `config create` Interactively (Simulated) ---
    println!("Running: config create (simulated interaction)");
    let mut cmd_config_create = Command::cargo_bin("jacs")?;
    cmd_config_create.current_dir(temp_path); // Run from temp dir
    cmd_config_create.arg("config").arg("create");

    // --> FIX: Set environment variables for the config create process <--
    cmd_config_create.env("JACS_DEFAULT_STORAGE", "fs"); // Critical: For internal MultiStorage init
    cmd_config_create.env("JACS_DATA_DIRECTORY", &data_dir); // Needed if checking input agent file path
    cmd_config_create.env("JACS_KEY_DIRECTORY", &key_dir); // Needed if checking input agent file path
    // Password will be handled by interactive input below, but other commands might need it set via env later.

    cmd_config_create.stdin(Stdio::piped()); // Prepare to pipe input
    cmd_config_create.stdout(Stdio::piped()); // Capture stdout to see prompts if needed
    cmd_config_create.stderr(Stdio::piped()); // Capture stderr for errors

    let mut child = cmd_config_create.spawn()?;
    let mut child_stdin = child.stdin.take().expect("Failed to open stdin");

    // Write answers matching the prompts in cli.rs config create
    // Order: agent_filename, priv_key, pub_key, algo, storage, password, use_fs, use_sec, data_dir, key_dir
    let inputs = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        "",                         // agent_filename (empty)
        "jacs.private.pem.enc",     // priv_key (default)
        "jacs.public.pem",          // pub_key (default)
        "RSA-PSS",                  // algo (default)
        "fs",                       // storage (matching env var)
        "testpassword",             // password
        "true",                     // use_fs (default)
        "false",                    // use_sec (default)
        data_dir.to_str().unwrap(), // data_dir (matching env var)
        key_dir.to_str().unwrap()   // key_dir (matching env var)
    );

    // Write inputs in a separate thread to avoid blocking
    std::thread::spawn(move || {
        child_stdin
            .write_all(inputs.as_bytes())
            .expect("Failed to write to stdin");
        // stdin is closed when child_stdin goes out of scope
    });

    // Wait for the command to finish and check status
    let output = child.wait_with_output()?;
    println!(
        "Config Create STDOUT:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    println!(
        "Config Create STDERR:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "`jacs config create` failed");

    // Verify config file was created in the temp dir
    let config_path = temp_path.join("jacs.config.json");
    assert!(config_path.exists(), "jacs.config.json was not created");
    println!(
        "Config file created successfully at: {}",
        config_path.display()
    );

    // Now ensure data/key dirs exist if subsequent commands need them pre-created
    fs::create_dir_all(&data_dir)?;
    fs::create_dir_all(&key_dir)?;

    // 3. Define Environment Variables for subsequent commands
    let dummy_password = "testpassword"; // Use the same password as provided above

    // 4. Create other input files (agent raw, ddl, jpeg) directly in Temp Dir
    let agent_raw_path_dest = temp_path.join("agent.raw.json");
    let mut agent_raw_file = File::create(&agent_raw_path_dest)?;
    write!(
        agent_raw_file,
        r#"{{"jacsAgentType": "ai", "name": "Test Agent"}}"#
    )?;

    let ddl_path_dest = temp_path.join("ddl.json");
    let mut ddl_file = File::create(&ddl_path_dest)?;
    write!(ddl_file, r#"{{"data": "sample document data"}}"#)?;

    let mobius_path_dest = temp_path.join("mobius.jpeg");
    // Decode base64 string for dummy jpeg content
    // Ensure you have `use base64;` at the top
    let mobius_content_result = base64::decode(
        "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AP//Z",
    );
    let mobius_content = match mobius_content_result {
        Ok(content) => content,
        Err(e) => panic!("Failed to decode base64 content for dummy jpeg: {}", e),
    };
    let mut mobius_file = File::create(&mobius_path_dest)?;
    mobius_file.write_all(&mobius_content)?;
    println!("Created input files in temp dir");

    // --- Run Subsequent Commands ---

    // Define base command helper that sets env vars (reads created config implicitly now)
    let base_cmd = || -> Command {
        let mut cmd = Command::cargo_bin("jacs").unwrap();
        // Set env vars needed by commands *after* config create
        // JACS_CONFIG_PATH is not strictly needed if running from temp_path where jacs.config.json is
        // cmd.env("JACS_CONFIG_PATH", &config_path);
        cmd.env("JACS_DATA_DIRECTORY", &data_dir); // Still useful for clarity/consistency
        cmd.env("JACS_KEY_DIRECTORY", &key_dir); // Still useful for clarity/consistency
        cmd.env("JACS_PRIVATE_KEY_PASSWORD", dummy_password); // Crucial for agent create/sign
        cmd.current_dir(temp_path); // Run commands from temp dir's perspective
        cmd
    };

    // jacs config read (should read the file created by `config create`)
    println!("Running: config read");
    base_cmd()
        .arg("config")
        .arg("read")
        .assert()
        .success()
        .stdout(predicate::str::contains(data_dir.to_str().unwrap()));

    // jacs agent create -f ./agent.raw.json --create-keys=true
    println!("Running: agent create");
    let agent_create_output = base_cmd()
        .arg("agent")
        .arg("create")
        .arg("-f")
        .arg(&agent_raw_path_dest) // Use path in temp dir
        .arg("--create-keys=true")
        .output()?;
    assert!(
        agent_create_output.status.success(),
        "agent create failed: {:?}",
        agent_create_output
    );
    let agent_create_stdout = String::from_utf8(agent_create_output.stdout)?;
    println!("Agent Create Output:\n{}", agent_create_stdout);
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
    let agent_file_path = data_dir.join("agent").join(format!("{}.json", agent_id));
    assert!(
        key_dir.join("jacs.private.pem.enc").exists(),
        "Private key missing"
    );
    assert!(
        key_dir.join("jacs.public.pem").exists(),
        "Public key missing"
    );
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
        .arg(&ddl_path_dest)
        .arg("--attach")
        .arg(&mobius_path_dest)
        .arg("--embed=true")
        .arg("-a")
        .arg(&agent_file_path) // Use created agent file path
        .output()?;
    assert!(
        doc_create_output.status.success(),
        "document create failed: {:?}",
        doc_create_output
    );
    let doc_create_stdout = String::from_utf8(doc_create_output.stdout)?;
    println!("Document Create Output:\n{}", doc_create_stdout);
    let doc_path_line = doc_create_stdout
        .lines()
        .find(|line| line.contains("created doc"))
        .unwrap_or("");
    // Adjusted parsing assuming filename might have spaces or complex chars
    let doc_relative_path = doc_path_line.trim_start_matches("created doc ").trim();
    assert!(
        !doc_relative_path.is_empty(),
        "Could not parse document path from output: '{}'",
        doc_path_line
    );
    // Document create saves relative to the *current working directory* of the command, which is temp_path
    // let doc_full_path = data_dir.join("documents").join(doc_relative_path); // Old assumption incorrect
    let doc_full_path = temp_path.join(doc_relative_path); // Path is relative to CWD
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
        .arg(&doc_full_path) // Use full path relative to temp dir CWD
        .arg("-a")
        .arg(&agent_file_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("document verified OK"));

    // jacs document create-agreement -f ... --agentids agent1,agent2
    println!("Running: document create-agreement");
    base_cmd()
        .arg("document")
        .arg("create-agreement")
        .arg("-f")
        .arg(&doc_full_path) // Use full path relative to temp dir CWD
        .arg("-a")
        .arg(&agent_file_path)
        .arg("--agentids")
        .arg(format!("{},{}", agent_id, agent_id))
        .assert()
        .success()
        .stdout(predicate::str::contains("Agreement created"));

    // jacs document sign-agreement -f ...
    println!("Running: document sign-agreement");
    base_cmd()
        .arg("document")
        .arg("sign-agreement")
        .arg("-f")
        .arg(&doc_full_path) // Use full path relative to temp dir CWD
        .arg("-a")
        .arg(&agent_file_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed by"));

    // jacs document check-agreement -f ...
    println!("Running: document check-agreement");
    base_cmd()
        .arg("document")
        .arg("check-agreement")
        .arg("-f")
        .arg(&doc_full_path) // Use full path relative to temp dir CWD
        .arg("-a")
        .arg(&agent_file_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(agent_id))
        .stdout(predicate::str::contains("signed: true"));

    Ok(())
}
