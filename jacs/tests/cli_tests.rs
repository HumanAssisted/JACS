// here I want to test the CLI commands
use assert_cmd::prelude::*; // Add methods on commands
use base64::{engine::general_purpose::STANDARD, Engine as _}; // Import Engine trait and STANDARD engine
use predicates::prelude::*; // Used for writing assertions
use std::env;
use std::fs::{self, File}; // Add fs for file operations
use std::io::Write; // Add Write trait
                    // use std::sync::Once;
use jacs::storage::MultiStorage;
use std::{
    error::Error,
    process::{Command, Stdio},
}; // Run programs // To read CARGO_PKG_VERSION
mod utils;
use utils::{PASSWORD_ENV_VAR, TEST_PASSWORD};
const PASSWORD_FILE_ENV_VAR: &str = "JACS_PASSWORD_FILE";
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
        .stdout(predicate::str::contains(
            "Look up another agent's public key",
        ))
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
    println!(">>> Starting test_cli_script_flow execution <<<");
    let data_dir_string = "jacs_data";
    let key_dir_string = "jacs_keys";

    // 1. Setup Scratch Directory and Paths
    println!("Setting up scratch directory...");
    let scratch = tempfile::tempdir()?;
    let scratch_dir = scratch.path().to_path_buf();
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
    let config_contents = std::fs::read_to_string(&config_path)?;
    println!("{}", config_contents);

    // Add debugging to check key files
    println!("\n=== Checking Key Files After Config Create ===");
    println!("Scratch dir: {}", scratch_dir.display());
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
    let config_content = fs::read_to_string(&config_path)?;
    println!("Config file content:\n{}", config_content);

    println!("Scratch directory: {}", scratch_dir.display());
    println!("Listing contents of scratch directory:");
    for entry in fs::read_dir(&scratch_dir)? {
        let entry = entry?;
        println!("  {:?}", entry.path());
    }

    let config: serde_json::Value = serde_json::from_str(&config_content)?;
    let key_dir_from_config = config["jacs_key_directory"]
        .as_str()
        .unwrap_or("./jacs_keys");
    println!("Key directory from config: {}", key_dir_from_config);
    let key_dir_from_config_path = scratch_dir.join(key_dir_from_config);

    if key_dir_from_config_path.exists() {
        println!("Key directory from config exists. Contents:");
        for entry in fs::read_dir(&key_dir_from_config_path)? {
            let entry = entry?;
            println!("  {:?}", entry.path());
        }
    } else {
        println!("Key directory from config DOES NOT EXIST!");
    }

    let full_private_key_path = key_dir_from_config_path.join(
        config["jacs_agent_private_key_filename"]
            .as_str()
            .unwrap_or("jacs.private.pem.enc"),
    );
    let full_public_key_path = key_dir_from_config_path.join(
        config["jacs_agent_public_key_filename"]
            .as_str()
            .unwrap_or("jacs.public.pem"),
    );

    println!(
        "Full private key path from config: {}",
        full_private_key_path.display()
    );
    println!(
        "Private key exists at full path: {}",
        full_private_key_path.exists()
    );

    println!(
        "Full public key path from config: {}",
        full_public_key_path.display()
    );
    println!(
        "Public key exists at full path: {}",
        full_public_key_path.exists()
    );

    if !key_dir_from_config_path.exists() {
        println!(
            "Creating key directory from config: {}",
            key_dir_from_config_path.display()
        );
        fs::create_dir_all(&key_dir_from_config_path)?;
    }
    println!("=== END EXTENSIVE KEY DEBUGGING ===\n");

    // Check for agent files
    let storage = MultiStorage::new("fs".to_string())?;

    println!("Listing all files in key directory:");
    if key_dir.exists() {
        for entry in fs::read_dir(&key_dir)? {
            println!("  Found: {:?}", entry?.path());
        }
    } else {
        println!("  Key directory doesn't exist!");
    }

    let priv_key = key_dir.join("jacs.private.pem.enc");
    let pub_key = key_dir.join("jacs.public.pem");

    println!("Checking for private key at: {}", priv_key.display());
    let priv_exists = storage.file_exists(priv_key.to_string_lossy().as_ref(), None)?;
    println!("Private key exists (according to storage): {}", priv_exists);

    println!("Checking for public key at: {}", pub_key.display());
    let pub_exists = storage.file_exists(pub_key.to_string_lossy().as_ref(), None)?;
    println!("Public key exists (according to storage): {}", pub_exists);

    let priv_exists_fs = priv_key.exists();
    let pub_exists_fs = pub_key.exists();

    println!("Private key exists (filesystem): {}", priv_exists_fs);
    println!("Public key exists (filesystem): {}", pub_exists_fs);

    assert!(
        priv_exists_fs,
        "Private key missing at {}",
        priv_key.display()
    );
    assert!(pub_exists_fs, "Public key missing at {}", pub_key.display());

    // Check agent directory
    let agent_dir_path = data_dir.join("agent");
    println!("--- Checking contents of: {} ---", agent_dir_path.display());
    match std::fs::read_dir(&agent_dir_path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(e) => println!("Found: {:?}", e.path()),
                    Err(e) => println!("Error reading directory entry: {}", e),
                }
            }
        }
        Err(e) => println!(
            "Could not read directory {}: {}",
            agent_dir_path.display(),
            e
        ),
    }
    println!("-------------------------------------------");

    let agent_file_path = agent_dir_path.join(format!("{}.json", agent_id));
    assert!(
        agent_file_path.exists(),
        "Agent file missing: {}",
        agent_file_path.display()
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
    let src_ddl = utils::raw_fixture("favorite-fruit.json");
    let src_mobius = utils::raw_fixture("mobius.jpeg");

    let dst_ddl = data_dir.join("fruit.json");
    let dst_mobius = data_dir.join("mobius.jpeg");

    println!("Attempting to copy:");
    println!("From: {:?}", src_ddl);
    println!("To: {}", dst_ddl.display());
    println!("And from: {:?}", src_mobius);
    println!("To: {}", dst_mobius.display());

    // Check if source files exist
    println!("Source ddi exists: {}", src_ddl.exists());
    println!("Source mobius exists: {}", src_mobius.exists());

    // Copy the files (this should work now that we're using a fixed directory structure)
    std::fs::copy(&src_ddl, &dst_ddl)?;
    std::fs::copy(&src_mobius, &dst_mobius)?;

    println!("Files copied successfully");
    println!("Destination ddl exists: {}", dst_ddl.exists());
    println!("Destination mobius exists: {}", dst_mobius.exists());

    // Continue with the rest of the test as before...
    // (The rest of the test doesn't need to change)

    Ok(())
}

// =============================================================================
// jacs verify (top-level standalone verification)
// =============================================================================

#[test]
fn test_verify_help() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("verify").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Verify a signed JACS document"))
        .stdout(predicate::str::contains("--remote"))
        .stdout(predicate::str::contains("--json"))
        .stdout(predicate::str::contains("--key-dir"));
    Ok(())
}

#[test]
fn test_verify_missing_file() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("verify").arg("nonexistent.json");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Read file failed"));
    Ok(())
}

#[test]
fn test_verify_invalid_json() -> Result<(), Box<dyn Error>> {
    // Create a temp file with invalid JSON
    let tmp_dir = std::env::temp_dir().join("jacs_cli_test_verify_invalid");
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;
    let bad_file = tmp_dir.join("bad.json");
    fs::write(&bad_file, "not json at all")?;

    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("verify").arg(bad_file.to_string_lossy().as_ref());
    cmd.assert().failure();

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

#[test]
fn test_verify_unsigned_json() -> Result<(), Box<dyn Error>> {
    // Create a temp file with valid JSON but no JACS signature
    let tmp_dir = std::env::temp_dir().join("jacs_cli_test_verify_unsigned");
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;
    let unsigned_file = tmp_dir.join("unsigned.json");
    fs::write(&unsigned_file, r#"{"hello": "world"}"#)?;

    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("verify")
        .arg(unsigned_file.to_string_lossy().as_ref());
    cmd.assert().failure();

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

#[test]
fn test_quickstart_help_shows_password_bootstrap_options() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("quickstart").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Password bootstrap options (set exactly one explicit source)",
        ))
        .stdout(predicate::str::contains("JACS_PRIVATE_KEY_PASSWORD"))
        .stdout(predicate::str::contains(PASSWORD_FILE_ENV_VAR));
    Ok(())
}

#[test]
fn test_quickstart_uses_password_file_bootstrap() -> Result<(), Box<dyn Error>> {
    let tmp_dir = std::env::temp_dir().join("jacs_cli_test_quickstart_password_file");
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;

    let password_file = tmp_dir.join("password.txt");
    fs::write(&password_file, format!("{}\n", TEST_PASSWORD))?;
    let password_file_value = password_file.to_string_lossy().to_string();

    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.current_dir(&tmp_dir)
        .env_remove(PASSWORD_ENV_VAR)
        .env(PASSWORD_FILE_ENV_VAR, &password_file_value)
        .arg("quickstart")
        .arg("--name=test-quickstart")
        .arg("--domain=test.example.com")
        .arg("--algorithm=ed25519");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("JACS agent ready"));

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

#[test]
fn test_quickstart_fails_with_ambiguous_password_sources() -> Result<(), Box<dyn Error>> {
    let tmp_dir = std::env::temp_dir().join("jacs_cli_test_quickstart_password_conflict");
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;

    let password_file = tmp_dir.join("password.txt");
    fs::write(&password_file, format!("{}\n", TEST_PASSWORD))?;
    let password_file_value = password_file.to_string_lossy().to_string();

    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.current_dir(&tmp_dir)
        .env(PASSWORD_ENV_VAR, TEST_PASSWORD)
        .env(PASSWORD_FILE_ENV_VAR, &password_file_value)
        .arg("quickstart")
        .arg("--name=test-quickstart")
        .arg("--domain=test.example.com")
        .arg("--algorithm=ed25519");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(
            "Multiple password sources configured",
        ))
        .stderr(predicate::str::contains(PASSWORD_FILE_ENV_VAR));

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

#[test]
fn test_agent_verify_uses_configured_default_agent_without_agent_file() -> Result<(), Box<dyn Error>>
{
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let quickstart_dir =
        std::env::temp_dir().join(format!("jacs_cli_test_verify_default_agent_{}", unique));
    let probe_dir = std::env::temp_dir().join(format!(
        "jacs_cli_test_verify_default_agent_probe_{}",
        unique
    ));
    let _ = fs::remove_dir_all(&quickstart_dir);
    let _ = fs::remove_dir_all(&probe_dir);
    fs::create_dir_all(&quickstart_dir)?;
    fs::create_dir_all(&probe_dir)?;

    let mut quickstart = Command::cargo_bin("jacs")?;
    quickstart
        .current_dir(&quickstart_dir)
        .env(PASSWORD_ENV_VAR, TEST_PASSWORD)
        .arg("quickstart")
        .arg("--name=verify-default-agent")
        .arg("--domain=verify-default.example.test")
        .arg("--algorithm=ed25519");
    quickstart
        .assert()
        .success()
        .stdout(predicate::str::contains("JACS agent ready"));

    let config_path = quickstart_dir.join("jacs.config.json");
    assert!(
        config_path.exists(),
        "quickstart should create jacs.config.json"
    );

    let mut verify = Command::cargo_bin("jacs")?;
    verify
        .current_dir(&probe_dir)
        .env(PASSWORD_ENV_VAR, TEST_PASSWORD)
        .env("JACS_CONFIG", config_path.to_string_lossy().as_ref())
        .arg("agent")
        .arg("verify")
        .arg("--no-dns");
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("signature verified OK"));

    let _ = fs::remove_dir_all(&quickstart_dir);
    let _ = fs::remove_dir_all(&probe_dir);
    Ok(())
}

#[test]
fn test_verify_signed_document_roundtrip() -> Result<(), Box<dyn Error>> {
    // Use quickstart --sign to create a signed document, then verify it
    let tmp_dir = std::env::temp_dir().join("jacs_cli_test_verify_roundtrip");
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;

    // Create input JSON file
    let input_file = tmp_dir.join("input.json");
    fs::write(&input_file, r#"{"message": "test verification"}"#)?;

    // Sign it with quickstart
    let sign_output = Command::cargo_bin("jacs")?
        .current_dir(&tmp_dir)
        .env(PASSWORD_ENV_VAR, TEST_PASSWORD)
        .arg("quickstart")
        .arg("--name=verify-roundtrip")
        .arg("--domain=verify.example.com")
        .arg("--algorithm=ed25519")
        .arg("--sign")
        .arg("-f")
        .arg(input_file.to_string_lossy().as_ref())
        .output()?;

    assert!(
        sign_output.status.success(),
        "quickstart --sign failed: {}",
        String::from_utf8_lossy(&sign_output.stderr)
    );

    let signed_json = String::from_utf8(sign_output.stdout)?;
    let signed_file = tmp_dir.join("signed.json");
    fs::write(&signed_file, &signed_json)?;

    // Now verify with `jacs verify` — it picks up jacs.config.json from cwd
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.current_dir(&tmp_dir)
        .env(PASSWORD_ENV_VAR, TEST_PASSWORD)
        .arg("verify")
        .arg(signed_file.to_string_lossy().as_ref());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("VALID"))
        .stdout(predicate::str::contains("Signer:"))
        .stdout(predicate::str::contains("Signed at:"));

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

#[test]
fn test_verify_json_output() -> Result<(), Box<dyn Error>> {
    let tmp_dir = std::env::temp_dir().join("jacs_cli_test_verify_json");
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;

    let input_file = tmp_dir.join("input.json");
    fs::write(&input_file, r#"{"data": "json output test"}"#)?;

    // Sign
    let sign_output = Command::cargo_bin("jacs")?
        .current_dir(&tmp_dir)
        .env(PASSWORD_ENV_VAR, TEST_PASSWORD)
        .arg("quickstart")
        .arg("--name=verify-json")
        .arg("--domain=verify-json.example.com")
        .arg("--algorithm=ed25519")
        .arg("--sign")
        .arg("-f")
        .arg(input_file.to_string_lossy().as_ref())
        .output()?;
    assert!(sign_output.status.success());

    let signed_json = String::from_utf8(sign_output.stdout)?;
    let signed_file = tmp_dir.join("signed.json");
    fs::write(&signed_file, &signed_json)?;

    // Verify with --json flag
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.current_dir(&tmp_dir)
        .env(PASSWORD_ENV_VAR, TEST_PASSWORD)
        .arg("verify")
        .arg(signed_file.to_string_lossy().as_ref())
        .arg("--json");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(r#""valid": true"#))
        .stdout(predicate::str::contains("signerId"))
        .stdout(predicate::str::contains("timestamp"));

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

#[test]
fn test_verify_tampered_document() -> Result<(), Box<dyn Error>> {
    let tmp_dir = std::env::temp_dir().join("jacs_cli_test_verify_tampered");
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;

    let input_file = tmp_dir.join("input.json");
    fs::write(&input_file, r#"{"data": "tamper test"}"#)?;

    // Sign
    let sign_output = Command::cargo_bin("jacs")?
        .current_dir(&tmp_dir)
        .env(PASSWORD_ENV_VAR, TEST_PASSWORD)
        .arg("quickstart")
        .arg("--name=verify-tamper")
        .arg("--domain=verify-tamper.example.com")
        .arg("--algorithm=ed25519")
        .arg("--sign")
        .arg("-f")
        .arg(input_file.to_string_lossy().as_ref())
        .output()?;
    assert!(sign_output.status.success());

    // Tamper with the signed document
    let signed_json = String::from_utf8(sign_output.stdout)?;
    let tampered = signed_json.replace("tamper test", "TAMPERED DATA");
    let tampered_file = tmp_dir.join("tampered.json");
    fs::write(&tampered_file, &tampered)?;

    // Verify should fail (exit code 1)
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.current_dir(&tmp_dir)
        .env(PASSWORD_ENV_VAR, TEST_PASSWORD)
        .arg("verify")
        .arg(tampered_file.to_string_lossy().as_ref());
    cmd.assert().failure();

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

// =============================================================================
// jacs a2a (A2A trust and discovery commands)
// =============================================================================

#[test]
fn test_a2a_help() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("a2a").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("A2A"))
        .stdout(predicate::str::contains("assess"))
        .stdout(predicate::str::contains("trust"));
    Ok(())
}

#[test]
fn test_a2a_assess_jacs_agent_verified_policy() -> Result<(), Box<dyn Error>> {
    let tmp_dir = std::env::temp_dir().join("jacs_cli_test_a2a_assess_jacs");
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;

    // Create an Agent Card with JACS extension
    let card_json = r#"{
        "name": "JACS Test Agent",
        "description": "An agent with JACS provenance",
        "version": "1.0",
        "protocolVersions": ["0.4.0"],
        "supportedInterfaces": [{"url": "https://test.example.com", "protocolBinding": "jsonrpc"}],
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "capabilities": {
            "extensions": [{
                "uri": "urn:jacs:provenance-v1",
                "description": "JACS cryptographic provenance"
            }]
        },
        "skills": [],
        "metadata": {"jacsId": "test-agent-001", "jacsVersion": "v1"}
    }"#;

    let card_file = tmp_dir.join("agent-card.json");
    fs::write(&card_file, card_json)?;

    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("a2a")
        .arg("assess")
        .arg(card_file.to_string_lossy().as_ref())
        .arg("--policy=verified");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("JACS Test Agent"))
        .stdout(predicate::str::contains("Allowed:     YES"))
        .stdout(predicate::str::contains("JacsVerified"));

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

#[test]
fn test_a2a_assess_non_jacs_agent_rejected() -> Result<(), Box<dyn Error>> {
    let tmp_dir = std::env::temp_dir().join("jacs_cli_test_a2a_assess_nojacs");
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;

    // Create an Agent Card WITHOUT JACS extension
    let card_json = r#"{
        "name": "Plain A2A Agent",
        "description": "An agent without JACS provenance",
        "version": "1.0",
        "protocolVersions": ["0.4.0"],
        "supportedInterfaces": [{"url": "https://test.example.com", "protocolBinding": "jsonrpc"}],
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "capabilities": {},
        "skills": []
    }"#;

    let card_file = tmp_dir.join("plain-card.json");
    fs::write(&card_file, card_json)?;

    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("a2a")
        .arg("assess")
        .arg(card_file.to_string_lossy().as_ref())
        .arg("--policy=verified");

    // Should fail (exit code 1) because verified policy rejects non-JACS agents
    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("Allowed:     NO"))
        .stdout(predicate::str::contains("Untrusted"));

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

#[test]
fn test_a2a_assess_json_output() -> Result<(), Box<dyn Error>> {
    let tmp_dir = std::env::temp_dir().join("jacs_cli_test_a2a_assess_json");
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;

    let card_json = r#"{
        "name": "JSON Output Agent",
        "description": "Test JSON output",
        "version": "1.0",
        "protocolVersions": ["0.4.0"],
        "supportedInterfaces": [{"url": "https://test.example.com", "protocolBinding": "jsonrpc"}],
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "capabilities": {
            "extensions": [{
                "uri": "urn:jacs:provenance-v1",
                "description": "JACS"
            }]
        },
        "skills": [],
        "metadata": {"jacsId": "json-agent", "jacsVersion": "v1"}
    }"#;

    let card_file = tmp_dir.join("json-card.json");
    fs::write(&card_file, card_json)?;

    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("a2a")
        .arg("assess")
        .arg(card_file.to_string_lossy().as_ref())
        .arg("--json");

    let output = cmd.output()?;
    assert!(
        output.status.success(),
        "a2a assess --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let assessment: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(assessment["allowed"], true);
    assert_eq!(assessment["trustLevel"], "JacsVerified");
    assert_eq!(assessment["policy"], "Verified");
    assert_eq!(assessment["agentId"], "json-agent");

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

// =========================================================================
// A2A Discovery CLI tests
// =========================================================================

#[test]
fn test_a2a_discover_help() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("a2a").arg("discover").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Discover a remote A2A agent"))
        .stdout(predicate::str::contains("--json"))
        .stdout(predicate::str::contains("--policy"));
    Ok(())
}

#[test]
fn test_a2a_serve_help() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("a2a").arg("serve").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Serve this agent"))
        .stdout(predicate::str::contains("--port"))
        .stdout(predicate::str::contains("--host"));
    Ok(())
}

#[test]
fn test_a2a_discover_nonexistent_domain() -> Result<(), Box<dyn Error>> {
    // Discovery against a URL that won't have an Agent Card
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("a2a").arg("discover").arg("https://example.com");

    // Should fail because there's no .well-known/agent-card.json at example.com
    cmd.assert().failure();
    Ok(())
}

#[test]
fn test_a2a_help_shows_all_subcommands() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("a2a").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("assess"))
        .stdout(predicate::str::contains("trust"))
        .stdout(predicate::str::contains("discover"))
        .stdout(predicate::str::contains("serve"))
        .stdout(predicate::str::contains("quickstart"));
    Ok(())
}

#[test]
fn test_a2a_quickstart_help() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("a2a").arg("quickstart").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--port"))
        .stdout(predicate::str::contains("--host"))
        .stdout(predicate::str::contains("--algorithm"))
        .stdout(predicate::str::contains("--name"))
        .stdout(predicate::str::contains("--domain"))
        .stdout(predicate::str::contains("Create/load an agent"));
    Ok(())
}

#[test]
fn test_a2a_quickstart_invalid_algorithm() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("a2a")
        .arg("quickstart")
        .arg("--name")
        .arg("a2a-quickstart")
        .arg("--domain")
        .arg("a2a.example.com")
        .arg("--algorithm")
        .arg("invalid-algo");
    // Should fail because "invalid-algo" is not a valid algorithm choice
    cmd.assert().failure();
    Ok(())
}

#[test]
fn test_mcp_help_shows_install_and_run() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("mcp").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("install"))
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains(
            "Install and run the JACS MCP server",
        ));
    Ok(())
}

#[test]
fn test_mcp_install_dry_run_shows_prebuilt_plan() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("mcp").arg("install").arg("--dry-run");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Dry run: MCP prebuilt install plan",
        ))
        .stdout(predicate::str::contains("jacs-mcp-"))
        .stdout(predicate::str::contains(
            "github.com/HumanAssisted/JACS/releases/download",
        ));
    Ok(())
}

#[test]
fn test_mcp_install_dry_run_custom_url() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("mcp")
        .arg("install")
        .arg("--dry-run")
        .arg("--url")
        .arg("https://example.invalid/jacs-mcp.tar.gz");
    cmd.assert().success().stdout(predicate::str::contains(
        "https://example.invalid/jacs-mcp.tar.gz",
    ));
    Ok(())
}

#[test]
fn test_mcp_install_from_cargo_dry_run_shows_cargo_plan() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("mcp")
        .arg("install")
        .arg("--from-cargo")
        .arg("--dry-run")
        .arg("--version")
        .arg("0.8.0");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Dry run: MCP cargo install plan"))
        .stdout(predicate::str::contains(
            "cargo install jacs-mcp --locked --version 0.8.0",
        ));
    Ok(())
}

#[test]
fn test_mcp_run_missing_binary_shows_install_hint() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("mcp")
        .arg("run")
        .arg("--bin")
        .arg("/definitely/not/a/real/jacs-mcp");
    cmd.assert().failure().stderr(predicate::str::contains(
        "Install it with `jacs mcp install`",
    ));
    Ok(())
}

#[test]
fn test_mcp_run_help_mentions_stdio_and_no_forwarded_args() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("mcp").arg("run").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("stdio transport"))
        .stdout(predicate::str::contains("--bin <bin>"))
        .stdout(predicate::str::contains("[args]").not())
        .stdout(predicate::str::contains("Arguments forwarded").not());
    Ok(())
}

#[test]
fn test_mcp_run_rejects_forwarded_runtime_args() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("jacs")?;
    cmd.arg("mcp").arg("run").arg("--transport").arg("http");
    cmd.assert().failure().stderr(predicate::str::contains(
        "unexpected argument '--transport'",
    ));
    Ok(())
}
