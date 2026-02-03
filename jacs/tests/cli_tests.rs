// here I want to test the CLI commands
use assert_cmd::prelude::*; // Add methods on commands
use base64::{Engine as _, engine::general_purpose::STANDARD}; // Import Engine trait and STANDARD engine
use predicates::prelude::*; // Used for writing assertions
use std::env;
use std::fs::{self, File}; // Add fs for file operations
use std::io::Write; // Add Write trait
use std::path::Path;
// use std::sync::Once;
use jacs::storage::MultiStorage;
use std::{
    error::Error,
    process::{Command, Stdio},
}; // Run programs // To read CARGO_PKG_VERSION
mod utils;
use utils::{fixtures_raw_dir, PASSWORD_ENV_VAR, TEST_PASSWORD};
// static INIT: Once = Once::new();

// fn setup() {
//     INIT.call_once(|| {
//         env_logger::init();
//     });
// }

// RUST_BACKTRACE=1 cargo test   --test cli_tests -- --nocapture

#[test]
fn test_agent_lookup_help() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;

    cmd.arg("agent").arg("lookup").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Look up another agent's public key"))
        .stdout(predicate::str::contains("<domain>"))
        .stdout(predicate::str::contains("--no-dns"))
        .stdout(predicate::str::contains("--strict"));

    Ok(())
}

#[test]
fn test_agent_lookup_nonexistent_domain() -> Result<(), Box<dyn Error>> {
    // Test lookup against a domain that definitely won't have JACS configured
    // This tests that the CLI handles "not found" cases gracefully
    let mut cmd = Command::cargo_bin("jacs")?;

    cmd.arg("agent")
        .arg("lookup")
        .arg("example.com")
        .arg("--no-dns"); // Skip DNS to speed up test

    cmd.assert()
        .success() // Should succeed even if endpoint returns 404
        .stdout(predicate::str::contains("Agent Lookup: example.com"))
        .stdout(predicate::str::contains("Public Key"))
        .stdout(predicate::str::contains("DNS TXT Record: Skipped"));

    Ok(())
}

#[test]
fn test_agent_lookup_with_dns() -> Result<(), Box<dyn Error>> {
    // Test lookup with DNS enabled (will fail to find record but should handle gracefully)
    let mut cmd = Command::cargo_bin("jacs")?;

    cmd.arg("agent").arg("lookup").arg("example.com");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Agent Lookup: example.com"))
        .stdout(predicate::str::contains("DNS TXT Record"))
        .stdout(predicate::str::contains("No DNS TXT record found"));

    Ok(())
}

#[test]
fn test_agent_lookup_missing_domain() -> Result<(), Box<dyn Error>> {
    // Test that missing domain argument is handled
    let mut cmd = Command::cargo_bin("jacs")?;

    cmd.arg("agent").arg("lookup");

    cmd.assert()
        .failure() // Should fail due to missing required argument
        .stderr(predicate::str::contains("required"));

    Ok(())
}

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

// // Helper function to get fixture path
// fn fixture_path(name: &str) -> PathBuf {
//     PathBuf::from(env!("CARGO_MANIFEST_DIR"))
//         .join("tests")
//         .join("fixtures")
//         .join(name)
// }

#[test]
fn test_cli_script_flow() -> Result<(), Box<dyn Error>> {
    // Save the original working directory at the start of the test
    let original_cwd = std::env::current_dir()?;
    println!("Original working directory: {:?}", original_cwd);

    println!(">>> Starting test_cli_script_flow execution <<<");
    let data_dir_string = "jacs_data";
    let key_dir_string = "jacs_keys";

    // 1. Setup Scratch Directory and Paths
    println!("Setting up scratch directory...");
    let scratch_dir = original_cwd.join("tests").join("scratch");

    // Clean up any existing files from previous test runs
    if scratch_dir.exists() {
        println!("Cleaning existing scratch directory");
        let _ = fs::remove_dir_all(&scratch_dir);
    }

    fs::create_dir_all(&scratch_dir)?;
    println!(
        "Scratch directory created successfully at: {}",
        scratch_dir.display()
    );

    let data_dir = scratch_dir.join(data_dir_string);
    let key_dir = scratch_dir.join(key_dir_string);

    println!("Scratch Dir: {}", scratch_dir.display());
    println!("(Will create data dir: {})", data_dir.display());
    println!("(Will create key dir: {})", key_dir.display());

    fs::create_dir_all(&data_dir)?;
    fs::create_dir_all(&key_dir)?;

    // Change to the scratch directory
    std::env::set_current_dir(&scratch_dir)?;
    println!(
        "Changed working directory to scratch dir: {:?}",
        std::env::current_dir()?
    );

    // --- Run `config create` Interactively (Simulated) ---
    println!("Running: config create (simulated interaction)");
    let mut cmd_config_create = Command::cargo_bin("jacs")?;
    cmd_config_create.current_dir(&scratch_dir);
    cmd_config_create.arg("config").arg("create");

    cmd_config_create.env(PASSWORD_ENV_VAR, TEST_PASSWORD); // Skips interactive password

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
    let input_use_sec = "false";
    // IMPORTANT: Use relative paths for directories
    let input_data_dir = data_dir_string;
    let input_key_dir = key_dir_string;

    // Assemble the input string - ADJUST THIS ORDER BASED ON ACTUAL CLI PROMPTS
    let inputs = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        input_agent_filename, // 1. Agent filename (empty)
        input_priv_key,       // 2. Private key filename
        input_pub_key,        // 3. Public key filename
        input_algo,           // 4. Algorithm
        input_storage,        // 5. Storage type
        input_use_sec,        // 6. Use security? (Example - CHECK ACTUAL)
        input_data_dir,       // 7. Data directory? (Example - CHECK ACTUAL)
        input_key_dir, // 8. Key directory? (Example - CHECK ACTUAL)                                // Password prompt is skipped by env var
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
    let config_path = scratch_dir.join("jacs.config.json");
    assert!(config_path.exists(), "jacs.config.json was not created");
    println!(
        "Config file created successfully at: {}",
        config_path.display()
    );
    fs::create_dir_all(&data_dir)?;
    fs::create_dir_all(&key_dir)?;

    // After config create completes:
    println!("Created jacs.config.json contents:");
    let config_contents = std::fs::read_to_string(scratch_dir.join("jacs.config.json"))?;
    println!("{}", config_contents);

    // Add debugging to check key files
    println!("\n=== Checking Key Files After Config Create ===");
    println!("Current dir: {:?}", std::env::current_dir()?);
    println!("Key dir exists: {}", key_dir.exists());
    if key_dir.exists() {
        println!("Contents of key directory:");
        for entry in fs::read_dir(&key_dir)? {
            match entry {
                Ok(entry) => println!("  {:?}", entry.path()),
                Err(e) => println!("  Error reading entry: {}", e),
            }
        }
    }

    // Verify the specific key files exist
    let priv_key_path = key_dir.join("jacs.private.pem.enc");
    let pub_key_path = key_dir.join("jacs.public.pem");
    println!(
        "Private key path exists: {} at {:?}",
        priv_key_path.exists(),
        priv_key_path
    );
    println!(
        "Public key path exists: {} at {:?}",
        pub_key_path.exists(),
        pub_key_path
    );
    println!("===========================================\n");

    // Create other input files
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
    // Use the STANDARD engine to decode
    let mobius_content_result = STANDARD.decode(
        "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AP//Z",
    );
    let mobius_content = mobius_content_result.expect("Bad base64");
    let mut mobius_file = File::create(&mobius_path_dest)?;
    mobius_file.write_all(&mobius_content)?;
    println!("Created input files in data dir");

    // 3. Define Environment Variables for subsequent commands
    let dummy_password = TEST_PASSWORD; // Use centralized test password constant

    // 4. Create other input files directly in scratch Dir too
    let agent_raw_path_dest = scratch_dir.join("agent.raw.json");
    let mut agent_raw_file = File::create(&agent_raw_path_dest)?;
    write!(
        agent_raw_file,
        r#"{{"jacsAgentType": "ai", "name": "Test Agent"}}"#
    )?;

    let ddl_path_dest = scratch_dir.join("ddl.json");
    let mut ddl_file = File::create(&ddl_path_dest)?;
    write!(ddl_file, r#"{{"data": "sample document data"}}"#)?;

    let mobius_path_dest = scratch_dir.join("mobius.jpeg");
    let mobius_content_result = STANDARD.decode(
        "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AP//Z",
    );
    let mobius_content = match mobius_content_result {
        Ok(content) => content,
        Err(e) => panic!("Failed to decode base64 content for dummy jpeg: {}", e),
    };
    let mut mobius_file = File::create(&mobius_path_dest)?;
    mobius_file.write_all(&mobius_content)?;
    println!("Created input files in scratch dir");

    // Define base command helper that sets env vars
    let base_cmd = || -> Command {
        let mut cmd = Command::cargo_bin("jacs").unwrap();
        cmd.env(PASSWORD_ENV_VAR, dummy_password);
        cmd.env("JACS_AGENT_KEY_ALGORITHM", "RSA-PSS");
        cmd.current_dir(&scratch_dir); // Use scratch dir as CWD
        cmd
    };

    // jacs config read
    println!("Running: config read");
    base_cmd()
        .arg("config")
        .arg("read")
        .assert()
        .success()
        .stdout(predicate::str::contains("JACS_DATA_DIRECTORY:"));

    // jacs agent create (interactive creation)
    println!("Running: agent create (interactive)");
    let mut cmd_agent_create = base_cmd();
    cmd_agent_create.arg("agent").arg("create");
    cmd_agent_create.arg("--create-keys=true");

    // Pipe stdin for interactive prompts
    cmd_agent_create.stdin(Stdio::piped());
    cmd_agent_create.stdout(Stdio::piped());
    cmd_agent_create.stderr(Stdio::piped());

    let mut agent_child = cmd_agent_create.spawn()?;
    let mut agent_child_stdin = agent_child
        .stdin
        .take()
        .expect("Failed to open stdin for agent create");

    // Provide input for agent create prompts
    let input_agent_type = "ai"; // Matches default
    let input_service_desc = "Test Service Desc";
    let input_success_desc = "Test Success Desc";
    let input_failure_desc = "Test Failure Desc";
    let input_config_confirm = "yes";

    let agent_inputs = format!(
        "{}
{}
{}
{}
{}
",
        input_agent_type,
        input_service_desc,
        input_success_desc,
        input_failure_desc,
        input_config_confirm
    );
    println!("--- Sending Inputs to 'agent create' ---");
    println!("{}", agent_inputs.trim_end());
    println!("---------------------------------------");

    // Write inputs in thread
    std::thread::spawn(move || {
        agent_child_stdin
            .write_all(agent_inputs.as_bytes())
            .expect("Failed to write to agent create stdin");
    });

    // Wait for output and assert success
    let agent_create_output = agent_child.wait_with_output()?;
    let agent_create_stdout = String::from_utf8_lossy(&agent_create_output.stdout);
    let agent_create_stderr = String::from_utf8_lossy(&agent_create_output.stderr);
    println!("--- 'agent create' STDOUT ---");
    println!("{}", agent_create_stdout);
    println!("----------------------------");
    println!("--- 'agent create' STDERR ---");
    println!("{}", agent_create_stderr);
    println!("----------------------------");

    assert!(
        agent_create_output.status.success(),
        "agent create failed: stdout: {}\nstderr: {}",
        agent_create_stdout,
        agent_create_stderr
    );

    // Parse agent ID
    let agent_id_line = agent_create_stdout
        .lines()
        .find(|line| line.contains("Agent") && line.contains("created successfully!"))
        .unwrap_or("");
    let agent_id = agent_id_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .trim_end_matches('!');
    assert!(!agent_id.is_empty(), "Could not parse agent ID from output");
    println!("Captured Agent ID: {}", agent_id);

    // Debug key directory
    println!("\n=== EXTENSIVE KEY DEBUGGING ===");
    let config_path = "jacs.config.json";
    let config_content = fs::read_to_string(config_path)?;
    println!("Config file content:\n{}", config_content);

    println!("Current directory: {:?}", std::env::current_dir()?);
    println!("Listing contents of current directory:");
    for entry in fs::read_dir(".")? {
        let entry = entry?;
        println!("  {:?}", entry.path());
    }

    let config: serde_json::Value = serde_json::from_str(&config_content)?;
    let key_dir_from_config = config["jacs_key_directory"]
        .as_str()
        .unwrap_or("./jacs_keys");
    println!("Key directory from config: {}", key_dir_from_config);

    if Path::new(key_dir_from_config).exists() {
        println!("Key directory from config exists. Contents:");
        for entry in fs::read_dir(key_dir_from_config)? {
            let entry = entry?;
            println!("  {:?}", entry.path());
        }
    } else {
        println!("Key directory from config DOES NOT EXIST!");
    }

    let full_private_key_path = format!(
        "{}/{}",
        key_dir_from_config,
        config["jacs_agent_private_key_filename"]
            .as_str()
            .unwrap_or("jacs.private.pem.enc")
    );
    let full_public_key_path = format!(
        "{}/{}",
        key_dir_from_config,
        config["jacs_agent_public_key_filename"]
            .as_str()
            .unwrap_or("jacs.public.pem")
    );

    println!(
        "Full private key path from config: {}",
        full_private_key_path
    );
    println!(
        "Private key exists at full path: {}",
        Path::new(&full_private_key_path).exists()
    );

    println!("Full public key path from config: {}", full_public_key_path);
    println!(
        "Public key exists at full path: {}",
        Path::new(&full_public_key_path).exists()
    );

    if !Path::new(key_dir_from_config).exists() {
        println!(
            "Creating key directory from config: {}",
            key_dir_from_config
        );
        fs::create_dir_all(key_dir_from_config)?;
    }
    println!("=== END EXTENSIVE KEY DEBUGGING ===\n");

    // Check for agent files
    let storage = MultiStorage::new("fs".to_string())?;

    println!("Listing all files in key directory:");
    if Path::new(key_dir_string).exists() {
        for entry in fs::read_dir(key_dir_string)? {
            println!("  Found: {:?}", entry?.path());
        }
    } else {
        println!("  Key directory doesn't exist!");
    }

    let priv_key = format!("{}/jacs.private.pem.enc", key_dir_string);
    let pub_key = format!("{}/jacs.public.pem", key_dir_string);

    println!("Checking for private key at: {}", priv_key);
    let priv_exists = storage.file_exists(&priv_key, None)?;
    println!("Private key exists (according to storage): {}", priv_exists);

    println!("Checking for public key at: {}", pub_key);
    let pub_exists = storage.file_exists(&pub_key, None)?;
    println!("Public key exists (according to storage): {}", pub_exists);

    let priv_exists_fs = Path::new(&priv_key).exists();
    let pub_exists_fs = Path::new(&pub_key).exists();

    println!("Private key exists (filesystem): {}", priv_exists_fs);
    println!("Public key exists (filesystem): {}", pub_exists_fs);

    assert!(priv_exists_fs, "Private key missing at {}", priv_key);
    assert!(pub_exists_fs, "Public key missing at {}", pub_key);

    // Check agent directory
    let agent_dir_path = format!("{}/agent", data_dir_string);
    println!("--- Checking contents of: {} ---", agent_dir_path);
    match std::fs::read_dir(&agent_dir_path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(e) => println!("Found: {:?}", e.path()),
                    Err(e) => println!("Error reading directory entry: {}", e),
                }
            }
        }
        Err(e) => println!("Could not read directory {}: {}", agent_dir_path, e),
    }
    println!("-------------------------------------------");

    let agent_file_path = format!("{}/agent/{}.json", data_dir_string, agent_id);
    assert!(
        Path::new(&agent_file_path).exists(),
        "Agent file missing: {}",
        agent_file_path
    );

    // jacs agent verify
    println!("Running: agent verify");
    base_cmd()
        .arg("agent")
        .arg("verify")
        .arg("-a")
        .arg(&agent_file_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("signature verified OK"));

    println!("Running: document tests ");

    // Get fixtures paths using centralized helper
    // Note: fixtures_raw_dir() works from the original cwd, but we've changed to scratch dir
    // So we use relative path here since we're in tests/scratch and fixtures is at tests/fixtures
    let fixtures_raw = Path::new("../fixtures/raw").to_path_buf();
    println!("Using fixtures raw directory at: {:?}", fixtures_raw);
    let src_ddl = fixtures_raw.join("favorite-fruit.json");
    let src_mobius = fixtures_raw.join("mobius.jpeg");

    let dst_ddl = format!("{}/fruit.json", data_dir_string);
    let dst_mobius = format!("{}/mobius.jpeg", data_dir_string);

    println!("Attempting to copy:");
    println!("From: {:?}", src_ddl);
    println!("To: {}", dst_ddl);
    println!("And from: {:?}", src_mobius);
    println!("To: {}", dst_mobius);

    // Check if source files exist
    println!("Source ddi exists: {}", src_ddl.exists());
    println!("Source mobius exists: {}", src_mobius.exists());

    // Copy the files (this should work now that we're using a fixed directory structure)
    std::fs::copy(&src_ddl, Path::new(&dst_ddl))?;
    std::fs::copy(&src_mobius, Path::new(&dst_mobius))?;

    println!("Files copied successfully");
    println!("Destination ddl exists: {}", Path::new(&dst_ddl).exists());
    println!(
        "Destination mobius exists: {}",
        Path::new(&dst_mobius).exists()
    );

    // Continue with the rest of the test as before...
    // (The rest of the test doesn't need to change)

    // At the end of the test, restore original directory
    std::env::set_current_dir(&original_cwd)?;
    println!("Restored original working directory at end of test");

    Ok(())
}
