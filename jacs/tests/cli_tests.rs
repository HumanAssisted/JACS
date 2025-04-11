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
    // --> Add print statement RIGHT AT THE START <--
    println!(">>> Starting test_cli_script_flow execution <<<");

    // 1. Setup Temp Directory and Paths
    println!("Attempting to create tempdir..."); // Add print before tempdir call
    let temp_dir = tempdir()?;
    println!("Tempdir created successfully."); // Add print after tempdir call
    let temp_path = temp_dir.path();
    let data_dir = temp_path.join("jacs_data");
    let key_dir = temp_path.join("jacs_keys");

    println!("Temp Dir: {}", temp_path.display()); // Original prints start here
    println!("(Will create data dir: {})", data_dir.display());
    println!("(Will create key dir: {})", key_dir.display());

    fs::create_dir_all(&data_dir)?;
    fs::create_dir_all(&key_dir)?;

    // --- Run `config create` Interactively (Simulated) ---
    println!("Running: config create (simulated interaction)");
    let mut cmd_config_create = Command::cargo_bin("jacs")?;
    cmd_config_create.current_dir(temp_path);
    cmd_config_create.arg("config").arg("create");

    // --> FIX 1: Set environment variables for the config create process <--
    cmd_config_create.env("JACS_DEFAULT_STORAGE", "fs"); // Critical: For internal MultiStorage init
    cmd_config_create.env("JACS_DATA_DIRECTORY", &data_dir); // Needed if checking input agent file path
    cmd_config_create.env("JACS_KEY_DIRECTORY", &key_dir); // Needed if checking input agent file path
    cmd_config_create.env("JACS_PRIVATE_KEY_PASSWORD", "testpassword"); // Skips interactive password

    cmd_config_create.stdin(Stdio::piped());
    cmd_config_create.stdout(Stdio::piped());
    cmd_config_create.stderr(Stdio::piped());

    let mut child = cmd_config_create.spawn()?;
    let mut child_stdin = child.stdin.take().expect("Failed to open stdin");

    // Define inputs individually for clarity (Ensure 9 lines for prompts)
    let input_agent_filename = "";
    let input_priv_key = "jacs.private.pem.enc";
    let input_pub_key = "jacs.public.pem";
    let input_algo = "RSA-PSS";
    let input_storage = "fs";
    let input_use_fs = "true";
    let input_use_sec = "false";
    let input_data_dir = data_dir.to_str().unwrap();
    let input_key_dir = key_dir.to_str().unwrap();

    // Assemble the input string (9 lines - password line omitted)
    let inputs = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        input_agent_filename,
        input_priv_key,
        input_pub_key,
        input_algo,
        input_storage,
        input_use_fs,
        input_use_sec,
        input_data_dir,
        input_key_dir
    );
    println!("--- Sending Inputs to 'config create' ---");
    println!("{}", inputs.trim_end());
    println!("----------------------------------------");

    // Write inputs in thread
    std::thread::spawn(move || {
        child_stdin
            .write_all(inputs.as_bytes())
            .expect("Failed to write to stdin");
    });

    // Wait for output and assert success
    let output = child.wait_with_output()?;
    println!("--- 'config create' STDOUT ---");
    println!("{}", String::from_utf8_lossy(&output.stdout));
    println!("-------------------------------");
    println!("--- 'config create' STDERR ---");
    println!("{}", String::from_utf8_lossy(&output.stderr));
    println!("-------------------------------");
    assert!(output.status.success(), "`jacs config create` failed");

    // Verify config file and create dirs
    let config_path = temp_path.join("jacs.config.json");
    assert!(config_path.exists(), "jacs.config.json was not created");
    println!(
        "Config file created successfully at: {}",
        config_path.display()
    );
    fs::create_dir_all(&data_dir)?;
    fs::create_dir_all(&key_dir)?;

    // Create other input files (same as before)
    let agent_raw_path_dest = data_dir.join("agent.raw.json");
    let mut agent_raw_file = File::create(&agent_raw_path_dest)?;
    write!(
        agent_raw_file,
        r#"{{"jacsAgentType": "ai", "name": "Test Agent"}}"#
    )?;

    let ddl_path_dest = data_dir.join("ddl.json");
    let mut ddl_file = File::create(&ddl_path_dest)?;
    write!(ddl_file, r#"{{"data": "sample document data"}}"#)?;

    let mobius_path_dest = data_dir.join("mobius.jpeg");
    let mobius_content_result = base64::decode(
        "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AP//Z",
    );
    let mobius_content = mobius_content_result.expect("Bad base64");
    let mut mobius_file = File::create(&mobius_path_dest)?;
    mobius_file.write_all(&mobius_content)?;
    println!("Created input files in temp data dir");

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
        cmd.env("JACS_DATA_DIRECTORY", &data_dir);
        cmd.env("JACS_KEY_DIRECTORY", &key_dir);
        cmd.env("JACS_PRIVATE_KEY_PASSWORD", dummy_password);
        cmd.current_dir(temp_path); // Keep CWD as temp_path
        cmd
    };

    // jacs config read (should read the file created by `config create`)
    println!("Running: config read");
    base_cmd()
        .arg("config")
        .arg("read")
        .assert()
        .success()
        .stdout(predicate::str::contains("JACS_DATA_DIRECTORY:"));

    // jacs agent create -f ./agent.raw.json --create-keys=true
    println!("Running: agent create");
    let agent_create_output = base_cmd()
        .arg("agent")
        .arg("create")
        .arg("-f")
        .arg("agent.raw.json")
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
        .arg("ddl.json")
        .arg("--attach")
        .arg("mobius.jpeg")
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
    let doc_relative_path = doc_path_line.trim_start_matches("created doc ").trim();
    assert!(
        !doc_relative_path.is_empty(),
        "Could not parse document path from output: '{}'",
        doc_path_line
    );
    let doc_full_path = data_dir.join("documents").join(doc_relative_path);
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
        .arg(doc_full_path.strip_prefix(&temp_path).unwrap())
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
        .arg(doc_full_path.strip_prefix(&temp_path).unwrap())
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
        .arg(doc_full_path.strip_prefix(&temp_path).unwrap())
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
        .arg(doc_full_path.strip_prefix(&temp_path).unwrap())
        .arg("-a")
        .arg(&agent_file_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(agent_id))
        .stdout(predicate::str::contains("signed: true"));

    Ok(())
}
