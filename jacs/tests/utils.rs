use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::agent::loaders::FileLoader;
use jacs::config::Config;
use log::debug;
use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

// ============================================================================
// Centralized test password constants for JACS test suite.
//
// These standardized test passwords meet the minimum security requirements
// (40+ bits of entropy, 8+ characters, multiple character classes).
// ============================================================================

/// Standard test password that meets entropy requirements.
/// - Length: 13 characters
/// - Character classes: lowercase, uppercase, digits, symbols
/// - Entropy: ~70 bits (well above 40-bit minimum)
pub const TEST_PASSWORD: &str = "TestP@ss123!#";

/// Alternative test password for multi-key scenarios.
/// - Length: 15 characters
pub const TEST_PASSWORD_ALT: &str = "AltP@ssw0rd456$";

/// Minimal test password that just barely meets requirements (8 chars).
pub const TEST_PASSWORD_MINIMAL: &str = "xK9m$pL2";

/// Legacy test password for backward compatibility tests.
/// Note: This still meets current entropy requirements.
pub const TEST_PASSWORD_LEGACY: &str = "secretpassord";

/// Strong test password with high entropy for security-critical tests.
pub const TEST_PASSWORD_STRONG: &str = "MyStr0ng!Pass#2024";

/// Password used for test fixture encrypted keys (ring, pq configs).
/// This matches the password that was used to encrypt the test key files
/// in tests/fixtures/keys/.
pub const TEST_PASSWORD_FIXTURES: &str = "testpassword";

/// Environment variable name for the private key password.
pub const PASSWORD_ENV_VAR: &str = "JACS_PRIVATE_KEY_PASSWORD";

// ============================================================================
// Centralized test fixture path helpers for JACS test suite.
//
// These functions provide the single source of truth for test fixture paths.
// All tests should use these helpers instead of hardcoded path strings.
// ============================================================================

/// Returns the path to the fixtures directory.
/// This is the single source of truth for fixture path resolution.
pub fn find_fixtures_dir() -> PathBuf {
    let possible_paths = [
        "../fixtures",         // When running from tests/scratch
        "tests/fixtures",      // When running from jacs/
        "jacs/tests/fixtures", // When running from workspace root
    ];

    println!(
        "Current working directory: {:?}",
        std::env::current_dir().unwrap()
    );
    for path in possible_paths.iter() {
        println!("Checking path: {}", path);
        if Path::new(path).exists() {
            let found_path = Path::new(path).to_path_buf();
            println!("Found fixtures directory at: {:?}", found_path);
            return found_path;
        }
    }
    panic!("Could not find fixtures directory in any of the expected locations");
}

/// Returns the path to the fixtures/keys directory.
pub fn fixtures_keys_dir() -> PathBuf {
    find_fixtures_dir().join("keys")
}

/// Returns the path to the fixtures/raw directory.
pub fn fixtures_raw_dir() -> PathBuf {
    find_fixtures_dir().join("raw")
}

/// Returns the path to the fixtures/documents directory.
pub fn fixtures_documents_dir() -> PathBuf {
    find_fixtures_dir().join("documents")
}

/// Returns the path to the fixtures/golden directory.
pub fn fixtures_golden_dir() -> PathBuf {
    find_fixtures_dir().join("golden")
}

/// Returns the full path to a file in the fixtures directory.
///
/// # Arguments
/// * `relative` - Relative path from the fixtures directory
///
/// # Example
/// ```ignore
/// let path = fixture_path("raw/myagent.new.json");
/// ```
pub fn fixture_path(relative: &str) -> PathBuf {
    find_fixtures_dir().join(relative)
}

/// Returns the full path to a file in the fixtures/raw directory.
///
/// # Arguments
/// * `name` - Filename within the raw directory
///
/// # Example
/// ```ignore
/// let path = raw_fixture("myagent.new.json");
/// ```
pub fn raw_fixture(name: &str) -> PathBuf {
    fixtures_raw_dir().join(name)
}

/// Returns the full path to a file in the fixtures/keys directory.
///
/// # Arguments
/// * `name` - Filename within the keys directory
pub fn keys_fixture(name: &str) -> PathBuf {
    fixtures_keys_dir().join(name)
}

/// Returns the full path to a file in the fixtures/documents directory.
///
/// # Arguments
/// * `name` - Filename within the documents directory
pub fn documents_fixture(name: &str) -> PathBuf {
    fixtures_documents_dir().join(name)
}

/// Returns the full path to a file in the fixtures/golden directory.
///
/// # Arguments
/// * `name` - Filename within the golden directory
pub fn golden_fixture(name: &str) -> PathBuf {
    fixtures_golden_dir().join(name)
}

/// Returns the fixtures directory path as a string.
/// Useful for setting environment variables that expect string paths.
pub fn fixtures_dir_string() -> String {
    find_fixtures_dir().to_string_lossy().to_string()
}

/// Returns the fixtures/keys directory path as a string.
/// Useful for setting JACS_KEY_DIRECTORY environment variable.
pub fn fixtures_keys_dir_string() -> String {
    fixtures_keys_dir().to_string_lossy().to_string()
}

// Legacy static paths - these now use the centralized helpers internally
// but are kept for backward compatibility with existing tests.

pub static TESTFILE_MODIFIED: &str = "tests/fixtures/documents/MODIFIED_f89b737d-9fb6-417e-b4b8-e89150d69624:913ce948-3765-4bd4-9163-ccdbc7e11e8e.json";

pub static DOCTESTFILE: &str = "tests/fixtures/documents/f89b737d-9fb6-417e-b4b8-e89150d69624:913ce948-3765-4bd4-9163-ccdbc7e11e8e.json";
pub static DOCTESTFILECONFIG: &str = "tests/fixtures/documents/f89b737d-9fb6-417e-b4b8-e89150d69624:913ce948-3765-4bd4-9163-ccdbc7e11e8e.json";

pub static AGENTONE: &str =
    "ddf35096-d212-4ca9-a299-feda597d5525:b57d480f-b8d4-46e7-9d7c-942f2b132717";
pub static AGENTTWO: &str =
    "0f6bb6e8-f27c-4cf7-bb2e-01b647860680:a55739af-a3c8-4b4a-9f24-200313ee4229";

#[cfg(test)]
pub fn generate_new_docs_with_attachments(save: bool) {
    let mut agent = load_test_agent_one();
    let mut document_string =
        load_local_document(&raw_fixture("embed-xml.json").to_string_lossy().to_string()).unwrap();
    let mut document = agent
        .create_document_and_load(
            &document_string,
            vec![
                raw_fixture("plants.xml").to_string_lossy().to_string(),
                raw_fixture("breakfast.xml").to_string_lossy().to_string(),
            ]
            .into(),
            Some(false),
        )
        .unwrap();
    let mut document_key = document.getkey();

    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    _ = agent.save_document(&document_key, None, None, None);

    document_string = load_local_document(
        &raw_fixture("image-embed.json")
            .to_string_lossy()
            .to_string(),
    )
    .unwrap();
    document = agent
        .create_document_and_load(
            &document_string,
            vec![raw_fixture("mobius.jpeg").to_string_lossy().to_string()].into(),
            Some(true),
        )
        .unwrap();
    document_key = document.getkey();
    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    if save {
        let export_embedded = true;
        _ = agent.save_document(&document_key, None, Some(export_embedded), None);
    }
}

#[cfg(test)]
pub fn generate_new_docs() {
    let mut agent = load_test_agent_one();
    let mut document_string = load_local_document(
        &raw_fixture("favorite-fruit.json")
            .to_string_lossy()
            .to_string(),
    )
    .unwrap();
    let mut document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    let mut document_key = document.getkey();
    println!("document_key {}", document_key);
    // let mut document_ref = agent.get_document(&document_key).unwrap();
    let _ = agent.save_document(&document_key, None, None, None);

    document_string =
        load_local_document(&raw_fixture("gpt-lsd.json").to_string_lossy().to_string()).unwrap();
    document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    document_key = document.getkey();
    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    let _ = agent.save_document(&document_key, None, None, None);

    document_string =
        load_local_document(&raw_fixture("json-ld.json").to_string_lossy().to_string()).unwrap();
    document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    document_key = document.getkey();
    println!("document_key {}", document_key);
    // document_ref = agent.get_document(&document_key).unwrap();
    _ = agent.save_document(&document_key, None, None, None);
}

pub fn set_min_test_env_vars() {
    let fixtures_dir = fixtures_dir_string();
    let keys_dir = fixtures_keys_dir_string();
    unsafe {
        env::set_var(PASSWORD_ENV_VAR, TEST_PASSWORD_LEGACY);
        env::set_var("JACS_KEY_DIRECTORY", &keys_dir);
        env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "agent-one.private.pem");
        env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "agent-one.public.pem");
        env::set_var("JACS_DATA_DIRECTORY", &fixtures_dir);
        // Enable filesystem schema loading for tests that use custom schemas
        env::set_var("JACS_ALLOW_FILESYSTEM_SCHEMAS", "true");
    }
}

#[cfg(test)]
pub fn load_test_agent_one() -> Agent {
    set_min_test_env_vars();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let agentid = AGENTONE.to_string();
    let result = agent.load_by_id(agentid);
    match result {
        Ok(_) => {
            debug!(
                "AGENT ONE LOADED {} {} ",
                agent.get_id().unwrap(),
                agent.get_version().unwrap()
            );
        }
        Err(e) => {
            eprintln!("Error loading agent: {}", e);
            panic!("Agent loading failed");
        }
    }
    agent
}

#[cfg(test)]
pub fn load_test_agent_two() -> Agent {
    set_min_test_env_vars();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    debug!("load_test_agent_two: function called");
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    debug!("load_test_agent_two: agent instantiated");

    // let _ = agent.fs_preload_keys(
    //     &"agent-two.private.pem".to_string(),
    //     &"agent-two.public.pem".to_string(),
    //     Some("RSA-PSS".to_string()),
    // );

    // created agent two with agent one keys
    let _ = agent.fs_preload_keys(
        &"agent-one.private.pem".to_string(),
        &"agent-one.public.pem".to_string(),
        Some("RSA-PSS".to_string()),
    );

    debug!("load_test_agent_two: keys preloaded");
    let result = agent.load_by_id(AGENTTWO.to_string());
    match result {
        Ok(_) => {
            debug!(
                "AGENT TWO LOADED {} {} ",
                agent.get_id().unwrap(),
                agent.get_version().unwrap()
            );
        }
        Err(e) => {
            eprintln!("Error loading agent: {}", e);
            panic!("Agent loading failed");
        }
    }
    agent
}

#[cfg(test)]
pub fn load_local_document(filepath: &String) -> Result<String, Box<dyn Error>> {
    let current_dir = env::current_dir()?;
    let document_path: PathBuf = current_dir.join(filepath);
    let json_data = fs::read_to_string(document_path);
    match json_data {
        Ok(data) => {
            debug!("testing data {}", data);
            Ok(data.to_string())
        }
        Err(e) => {
            panic!("Failed to find file: {} {}", filepath, e);
        }
    }
}

#[cfg(test)]
pub fn set_test_env_vars() {
    let keys_dir = fixtures_keys_dir_string();
    unsafe {
        env::set_var("JACS_USE_SECURITY", "false");
        env::set_var("JACS_DATA_DIRECTORY", ".");
        env::set_var("JACS_KEY_DIRECTORY", &keys_dir);
        env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "rsa_pss_private.pem");
        env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "rsa_pss_public.pem");
        env::set_var("JACS_AGENT_KEY_ALGORITHM", "RSA-PSS");
        env::set_var(PASSWORD_ENV_VAR, TEST_PASSWORD);
        env::set_var(
            "JACS_AGENT_ID_AND_VERSION",
            "123e4567-e89b-12d3-a456-426614174000:123e4567-e89b-12d3-a456-426614174001",
        );
        // Enable filesystem schema loading for tests that use custom schemas
        env::set_var("JACS_ALLOW_FILESYSTEM_SCHEMAS", "true");
    }
}

#[cfg(test)]
pub fn clear_test_env_vars() {
    // Clear from both actual env and the thread-safe override store
    let vars = [
        "JACS_USE_SECURITY",
        "JACS_DATA_DIRECTORY",
        "JACS_KEY_DIRECTORY",
        "JACS_AGENT_PRIVATE_KEY_FILENAME",
        "JACS_AGENT_PUBLIC_KEY_FILENAME",
        "JACS_AGENT_KEY_ALGORITHM",
        PASSWORD_ENV_VAR,
        "JACS_AGENT_ID_AND_VERSION",
        "JACS_DEFAULT_STORAGE",
        "JACS_AGENT_DOMAIN",
        "JACS_DNS_VALIDATE",
        "JACS_DNS_STRICT",
        "JACS_DNS_REQUIRED",
        "JACS_ALLOW_FILESYSTEM_SCHEMAS",
    ];
    for var in vars {
        // Clear from thread-safe override store (used by jenv)
        let _ = jacs::storage::jenv::clear_env_var(var);
        // Also clear from actual process environment (fallback reads)
        unsafe {
            env::remove_var(var);
        }
    }
}

// ============================================================================
// Centralized test agent creation helpers for JACS test suite.
//
// These helpers consolidate the repeated patterns of creating agents
// with specific configurations, reducing boilerplate in test files.
// ============================================================================

/// Default schema versions used by most tests.
pub const DEFAULT_AGENT_VERSION: &str = "v1";
pub const DEFAULT_HEADER_VERSION: &str = "v1";
pub const DEFAULT_SIGNATURE_VERSION: &str = "v1";

/// Creates a new Agent with the default v1 schema versions.
///
/// This is the most common test setup pattern. The agent is instantiated
/// but not loaded with any identity or keys.
///
/// # Example
/// ```ignore
/// let mut agent = create_agent_v1().unwrap();
/// agent.load_by_config(config_path)?;
/// ```
#[cfg(test)]
pub fn create_agent_v1() -> Result<Agent, Box<dyn Error>> {
    create_agent(
        DEFAULT_AGENT_VERSION,
        DEFAULT_HEADER_VERSION,
        DEFAULT_SIGNATURE_VERSION,
    )
}

/// Creates a new Agent with the specified schema versions.
///
/// # Arguments
/// * `agent_version` - Agent schema version (e.g., "v1")
/// * `header_version` - Header schema version (e.g., "v1")
/// * `signature_version` - Signature schema version (e.g., "v1")
#[cfg(test)]
pub fn create_agent(
    agent_version: &str,
    header_version: &str,
    signature_version: &str,
) -> Result<Agent, Box<dyn Error>> {
    let agent = Agent::new(
        &agent_version.to_string(),
        &header_version.to_string(),
        &signature_version.to_string(),
    )?;
    Ok(agent)
}

/// Returns the path to the ring config file and sets up the password env var.
///
/// This sets `JACS_PRIVATE_KEY_PASSWORD` to the fixture password that was
/// used to encrypt the ring test keys.
#[cfg(test)]
pub fn get_ring_config() -> String {
    unsafe {
        env::set_var(PASSWORD_ENV_VAR, TEST_PASSWORD_FIXTURES);
    }
    raw_fixture("ring.jacs.config.json")
        .to_string_lossy()
        .to_string()
}

/// Returns the path to the pq-dilithium config file and sets up the password env var.
///
/// This sets `JACS_PRIVATE_KEY_PASSWORD` to the fixture password that was
/// used to encrypt the pq test keys.
#[cfg(test)]
pub fn get_pq_config() -> String {
    unsafe {
        env::remove_var(PASSWORD_ENV_VAR);
        env::set_var(PASSWORD_ENV_VAR, TEST_PASSWORD_FIXTURES);
    }
    raw_fixture("pq.jacs.config.json")
        .to_string_lossy()
        .to_string()
}

/// Creates and configures an Agent for ring/Ed25519 tests.
///
/// This helper:
/// 1. Creates a v1 agent
/// 2. Sets up the password environment variable
/// 3. Loads the ring configuration
///
/// # Example
/// ```ignore
/// let mut agent = create_ring_test_agent()?;
/// let json_data = read_new_agent_fixture()?;
/// agent.create_agent_and_load(&json_data, false, None)?;
/// ```
#[cfg(test)]
pub fn create_ring_test_agent() -> Result<Agent, Box<dyn Error>> {
    let mut agent = create_agent_v1()?;
    agent.load_by_config(get_ring_config())?;
    Ok(agent)
}

/// Creates and configures an Agent for pq-dilithium tests.
///
/// This helper:
/// 1. Sets up isolated pq-dilithium test environment variables
/// 2. Creates a v1 agent
/// 3. Applies pq-dilithium config directly from env values
///
/// # Example
/// ```ignore
/// let mut agent = create_pq_test_agent()?;
/// let json_data = read_new_agent_fixture()?;
/// agent.create_agent_and_load(&json_data, false, None)?;
/// ```
#[cfg(test)]
pub fn create_pq_test_agent() -> Result<Agent, Box<dyn Error>> {
    // Use isolated scratch paths for pq-dilithium tests so they do not rely on
    // committed fixture keys (which may have legacy formats).
    unsafe {
        env::set_var("JACS_USE_SECURITY", "false");
        env::set_var("JACS_DATA_DIRECTORY", "tests/scratch/pq_dilithium_data");
        env::set_var("JACS_KEY_DIRECTORY", "tests/scratch/pq_dilithium_keys");
        env::set_var(
            "JACS_AGENT_PRIVATE_KEY_FILENAME",
            "pq_dilithium_private.bin.enc",
        );
        env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "pq_dilithium_public.bin");
        env::set_var("JACS_AGENT_KEY_ALGORITHM", "pq-dilithium");
        env::set_var(PASSWORD_ENV_VAR, TEST_PASSWORD_ALT);
        env::set_var("JACS_ALLOW_FILESYSTEM_SCHEMAS", "true");
    }

    let mut agent = create_agent_v1()?;

    // Build config directly from explicit env values to avoid unrelated env
    // leakage from other tests.
    let config = Config::new(
        Some("false".to_string()),
        Some(std::env::var("JACS_DATA_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_KEY_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PRIVATE_KEY_FILENAME").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PUBLIC_KEY_FILENAME").unwrap_or_default()),
        Some("pq-dilithium".to_string()),
        Some(std::env::var(PASSWORD_ENV_VAR).unwrap_or_default()),
        None,
        Some("fs".to_string()),
    );
    agent.config = Some(config);

    Ok(agent)
}

/// Sets up the environment for pq2025 (ML-DSA-87) tests.
///
/// This configures environment variables for the post-quantum 2025 algorithm.
#[cfg(test)]
pub fn setup_pq2025_env() {
    unsafe {
        env::set_var("JACS_USE_SECURITY", "false");
        env::set_var("JACS_DATA_DIRECTORY", "tests/scratch/pq2025_data");
        env::set_var("JACS_KEY_DIRECTORY", "tests/scratch/pq2025_keys");
        env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "pq2025_private.bin.enc");
        env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "pq2025_public.bin");
        env::set_var("JACS_AGENT_KEY_ALGORITHM", "pq2025");
        env::set_var(PASSWORD_ENV_VAR, TEST_PASSWORD);
    }
}

/// Creates and configures an Agent for pq2025 (ML-DSA-87) tests.
///
/// This helper:
/// 1. Sets up pq2025 environment variables
/// 2. Creates a v1 agent
/// 3. Configures it with pq2025 algorithm settings
///
/// # Example
/// ```ignore
/// let mut agent = create_pq2025_test_agent()?;
/// agent.generate_keys()?;
/// let signature = agent.sign_string(&"test data".to_string())?;
/// ```
#[cfg(test)]
pub fn create_pq2025_test_agent() -> Result<Agent, Box<dyn Error>> {
    setup_pq2025_env();
    let mut agent = create_agent_v1()?;

    // Override config with env vars for pq2025 testing
    let config = Config::new(
        Some("false".to_string()), // jacs_use_security
        Some(std::env::var("JACS_DATA_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_KEY_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PRIVATE_KEY_FILENAME").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PUBLIC_KEY_FILENAME").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_KEY_ALGORITHM").unwrap_or_default()),
        Some(std::env::var(PASSWORD_ENV_VAR).unwrap_or_default()),
        None,                   // jacs_agent_id_and_version
        Some("fs".to_string()), // jacs_default_storage
    );
    agent.config = Some(config);

    Ok(agent)
}

/// Reads the standard new agent fixture file (myagent.new.json).
///
/// This is the most common fixture used for creating new test agents.
///
/// # Example
/// ```ignore
/// let mut agent = create_ring_test_agent()?;
/// let json_data = read_new_agent_fixture()?;
/// agent.create_agent_and_load(&json_data, false, None)?;
/// ```
#[cfg(test)]
pub fn read_new_agent_fixture() -> Result<String, Box<dyn Error>> {
    let path = raw_fixture("myagent.new.json");
    let content = fs::read_to_string(&path)?;
    Ok(content)
}

/// Reads a fixture file from the raw fixtures directory.
///
/// # Arguments
/// * `filename` - Name of the file in the fixtures/raw directory
///
/// # Example
/// ```ignore
/// let json_data = read_raw_fixture("mysecondagent.new.json")?;
/// ```
#[cfg(test)]
pub fn read_raw_fixture(filename: &str) -> Result<String, Box<dyn Error>> {
    let path = raw_fixture(filename);
    let content = fs::read_to_string(&path)?;
    Ok(content)
}
