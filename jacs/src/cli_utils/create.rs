// Allow deprecated config functions during 12-Factor migration (see task ARCH-005)
#![allow(deprecated)]

use crate::agent::boilerplate::BoilerPlate;
use crate::config::{Config, check_env_vars, set_env_vars};
use crate::create_minimal_blank_agent;
use crate::crypt::KeyManager;
use crate::dns::bootstrap as dns_bootstrap;
use crate::get_empty_agent;
use crate::storage::MultiStorage;
use crate::storage::jenv::set_env_var;
use rpassword::read_password;
use serde_json::{Value, json};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process;

use crate::simple::{AgentInfo, CreateAgentParams, SimpleAgent};

/// Programmatic agent creation for non-interactive use.
///
/// Accepts pre-built `CreateAgentParams` and delegates to `SimpleAgent::create_with_params()`.
/// Use this when integrating CLI commands with the programmatic API.
pub fn handle_agent_create_programmatic(params: CreateAgentParams) -> Result<AgentInfo, Box<dyn Error>> {
    let (_agent, info) = SimpleAgent::create_with_params(params)
        .map_err(|e| -> Box<dyn Error> { Box::new(e) })?;
    Ok(info)
}

fn request_string(message: &str, default: &str) -> String {
    let mut input = String::new();
    println!("{}: (default: {})", message, default);

    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                default.to_string() // Return default if no input
            } else {
                trimmed.to_string() // Return trimmed input if there's any
            }
        }
        Err(_) => default.to_string(), // Return default on error
    }
}

// Function to handle the 'config create' logic
pub fn handle_config_create() -> Result<(), Box<dyn Error>> {
    println!("Welcome to the JACS Config Generator!");
    let storage: MultiStorage = MultiStorage::default_new().expect("Failed to initialize storage");

    println!("Enter the path to the agent file if it already exists (leave empty to skip):");
    let mut agent_filename = String::new();
    io::stdin().read_line(&mut agent_filename).unwrap();
    agent_filename = agent_filename.trim().to_string();

    let jacs_agent_id_and_version = if !agent_filename.is_empty() {
        // Use storage to check and read the agent file
        match storage.file_exists(&agent_filename, None) {
            Ok(true) => match storage.get_file(&agent_filename, None) {
                Ok(agent_content_bytes) => match String::from_utf8(agent_content_bytes) {
                    Ok(agent_content) => match serde_json::from_str::<Value>(&agent_content) {
                        Ok(agent_json) => {
                            let jacs_id = agent_json["jacsId"].as_str().unwrap_or("");
                            let jacs_version = agent_json["jacsVersion"].as_str().unwrap_or("");
                            format!("{}:{}", jacs_id, jacs_version)
                        }
                        Err(e) => {
                            println!("Error parsing agent JSON from {}: {}", agent_filename, e);
                            String::new()
                        }
                    },
                    Err(e) => {
                        println!(
                            "Error converting agent file content to UTF-8 {}: {}",
                            agent_filename, e
                        );
                        String::new()
                    }
                },
                Err(e) => {
                    println!("Failed to read agent file {}: {}", agent_filename, e);
                    String::new()
                }
            },
            Ok(false) => {
                println!(
                    "Agent file {} not found in storage. Skipping...",
                    agent_filename
                );
                String::new()
            }
            Err(e) => {
                println!(
                    "Error checking existence of agent file {}: {}",
                    agent_filename, e
                );
                String::new()
            }
        }
    } else {
        String::new()
    };

    // --- Check if config file already exists ---
    let config_path = "jacs.config.json";
    if Path::new(config_path).exists() {
        println!(
            "Configuration file '{}' already exists. Please remove or rename it if you want to create a new one.",
            config_path
        );
        process::exit(0); // Exit gracefully
    }
    // --- End check ---

    let jacs_agent_private_key_filename =
        request_string("Enter the private key filename:", "jacs.private.pem.enc");
    let jacs_agent_public_key_filename =
        request_string("Enter the public key filename:", "jacs.public.pem");
    let jacs_agent_key_algorithm = request_string(
        "Enter the agent key algorithm (pq2025, ring-Ed25519, or RSA-PSS)",
        "pq2025",
    );
    let jacs_default_storage = request_string("Enter the default storage (fs, aws, hai)", "fs");

    // Check for password in environment variable first
    let jacs_private_key_password = match env::var("JACS_PRIVATE_KEY_PASSWORD") {
        Ok(env_password) if !env_password.is_empty() => {
            println!("Using password from JACS_PRIVATE_KEY_PASSWORD environment variable.");
            env_password // Use password from env var
        }
        _ => {
            // Environment variable not set or empty, prompt user interactively.
            println!("\n{}", crate::crypt::aes_encrypt::password_requirements());
            loop {
                println!("Please enter a password (used to encrypt private key):");
                let password = match read_password() {
                    Ok(pass) => pass,
                    Err(e) => {
                        eprintln!("Error reading password: {}. Please try again.", e);
                        continue;
                    }
                };

                if password.is_empty() {
                    eprintln!("Password cannot be empty. Please try again.");
                    continue;
                }

                println!("Please confirm the password:");
                let password_confirm = match read_password() {
                    Ok(pass) => pass,
                    Err(e) => {
                        eprintln!(
                            "Error reading confirmation password: {}. Please start over.",
                            e
                        );
                        continue; // Ask again from the beginning
                    }
                };

                if password == password_confirm {
                    break password; // Passwords match and are not empty, exit loop
                } else {
                    eprintln!("Passwords do not match. Please try again.");
                    // Loop continues
                }
            }
        }
    };

    let jacs_use_security = request_string("Use experimental security features", "false");
    let jacs_data_directory = request_string("Directory for data storage", "./jacs");
    let jacs_key_directory = request_string("Directory for keys", "./jacs_keys");
    let jacs_agent_domain = request_string(
        "Agent domain for DNSSEC fingerprint (optional, e.g., example.com)",
        "",
    );

    let mut config = Config::new(
        Some(jacs_use_security),
        Some(jacs_data_directory),
        Some(jacs_key_directory),
        Some(jacs_agent_private_key_filename),
        Some(jacs_agent_public_key_filename),
        Some(jacs_agent_key_algorithm),
        Some(jacs_private_key_password),
        Some(jacs_agent_id_and_version),
        Some(jacs_default_storage),
    );

    // insert optional domain if provided
    if !jacs_agent_domain.trim().is_empty() {
        // Serialize to Value, add field, then write
        let mut v = serde_json::to_value(&config).unwrap_or(serde_json::json!({}));
        if let Some(obj) = v.as_object_mut() {
            obj.insert(
                "jacs_agent_domain".to_string(),
                serde_json::Value::String(jacs_agent_domain.trim().to_string()),
            );
        }
        config = serde_json::from_value(v).unwrap_or(config);
    }

    // Serialize, but ensure we omit any null fields that may have slipped through
    let mut value = serde_json::to_value(&config).unwrap_or(serde_json::json!({}));
    if let Some(obj) = value.as_object_mut() {
        // Remove optional domain if it ended up as null
        if obj.get("jacs_agent_domain").is_some_and(|v| v.is_null()) {
            obj.remove("jacs_agent_domain");
        }
    }
    let serialized = serde_json::to_string_pretty(&value).unwrap();

    // Keep using std::fs for config file backup and writing
    // The check and backup logic below is no longer needed as we exit earlier if the file exists.
    /*
    let config_path = "jacs.config.json"; // This line is already defined above
    if metadata(config_path).is_ok() {
        // Keep std::fs::metadata
        let now: DateTime<Local> = Local::now();
        let backup_path = format!("{}-backup-jacs.config.json", now.format("%Y%m%d%H%M%S"));
        rename(config_path, backup_path.clone()).unwrap(); // Keep std::fs::rename
        println!("Backed up existing jacs.config.json to {}", backup_path);
    }
    */

    let mut file = File::create(config_path)
        .map_err(|e| format!("Failed to create config file '{}': {}", config_path, e))?;
    file.write_all(serialized.as_bytes())
        .map_err(|e| format!("Failed to write to config file '{}': {}", config_path, e))?;

    println!("jacs.config.json file generated successfully!");
    Ok(())
}

// Function to handle the 'agent create' logic
pub fn handle_agent_create(
    filename: Option<&String>,
    create_keys: bool,
) -> Result<(), Box<dyn Error>> {
    let storage: MultiStorage = MultiStorage::default_new().expect("Failed to initialize storage");
    // Initialize storage using MultiStorage::new - Note: storage is passed in now

    // Try to load config file and set environment variables from it
    let config_path_str = "jacs.config.json";
    let _ = if Path::new(config_path_str).exists() {
        match std::fs::read_to_string(config_path_str) {
            Ok(content) => {
                println!("Loading configuration from {}...", config_path_str);
                // Call set_env_vars with the content, don't override existing env vars,
                // and consider the agent ID from the config file initially.
                set_env_vars(false, Some(&content), false)
            }
            Err(e) => {
                eprintln!("Warning: Could not read {}: {}", config_path_str, e);
                // Proceed without config file content, let set_env_vars handle defaults
                set_env_vars(false, None, false)
            }
        }
    } else {
        println!(
            "{} not found, proceeding with defaults or environment variables.",
            config_path_str
        );
        // Config file doesn't exist, let set_env_vars handle defaults/env vars
        set_env_vars(false, None, false)
    };

    // -- Get user input for agent type and SERVICE descriptions --
    let agent_type = request_string("Agent Type (e.g., ai, person, service, device)", "ai"); // Default to ai
    if agent_type.is_empty() {
        eprintln!("Agent type cannot be empty.");
        process::exit(1);
    }
    // TODO: Validate agent_type against schema enum: ["human", "human-org", "hybrid", "ai"]

    let service_description = request_string(
        "Service Description",
        "Describe a service the agent provides",
    );
    let success_description = request_string(
        "Service Success Description",
        "Describe a success of the service",
    );
    let failure_description = request_string(
        "Service Failure Description",
        "Describe what failure is of the service",
    );

    // Variables for service descriptions when creating minimal agent
    let (minimal_service_desc, minimal_success_desc, minimal_failure_desc) = if filename.is_none() {
        // Use descriptions collected from user only if creating minimal agent
        (
            Some(service_description),
            Some(success_description),
            Some(failure_description),
        )
    } else {
        // If loading from file, pass None (template should contain service info)
        (None, None, None)
    };

    // TODO output instructions for updating agent definition

    // Load or create base agent string
    let agent_template_string = match filename {
        Some(fname) => {
            let content_bytes = storage
                .get_file(fname, None)
                .map_err(|e| format!("Failed to load agent template file '{}': {}", fname, e))?;
            String::from_utf8(content_bytes)
                .map_err(|e| format!("Agent template file {} is not valid UTF-8: {}", fname, e))?
        }
        _ => create_minimal_blank_agent(
            agent_type.clone(),   // Pass the collected agent_type
            minimal_service_desc, // Pass collected service description
            minimal_success_desc, // Pass collected success description
            minimal_failure_desc, // Pass collected failure description
        )
        .map_err(|e| format!("Failed to create minimal agent template: {}", e))?,
    };

    // -- Modify the agent template with remaining user input (agent_type) --
    let mut agent_json: Value = serde_json::from_str(&agent_template_string).map_err(|e| {
        format!(
            "Failed to parse agent template JSON: {}\nTemplate content:\n{}",
            e, agent_template_string
        )
    })?;

    // Add or update fields - ONLY agent_type remains needed here as name/desc removed
    if let Some(obj) = agent_json.as_object_mut() {
        // obj.insert("jacsName".to_string(), json!(agent_name)); // Removed
        // obj.insert("jacsDescription".to_string(), json!(agent_description)); // Removed
        obj.insert("jacsAgentType".to_string(), json!(agent_type)); // Use jacsAgentType based on schema
    } else {
        return Err("Agent template is not a valid JSON object.".into());
    }

    let modified_agent_string = serde_json::to_string(&agent_json)?;

    // Proceed with agent creation using modified string
    let mut agent = get_empty_agent();
    // NOTE: We previously called set_env_vars here. Now it's called earlier when loading the config.
    // We might still need to call check_env_vars or ensure the agent uses the loaded config.
    // For now, let's assume the environment is set correctly by the earlier call.
    // Let's remove the redundant set_env_vars call here.
    /*
    let configs = set_env_vars(true, None, true).unwrap_or_else(|e| {
        // Ignore agent id initially
        eprintln!("Warning: Failed to set some environment variables: {}", e);
        Config::default().to_string()
    });
    println!("Creating agent with config {}", configs);
    */
    println!("Proceeding with agent creation using loaded configuration/environment variables.");

    if create_keys {
        println!("Creating keys...");
        agent.generate_keys()?;
        println!(
            "Keys created in {}. Don't loose them! Keep them in a safe place. ",
            agent
                .config
                .as_ref()
                .unwrap()
                .jacs_key_directory()
                .as_deref()
                .unwrap_or_default()
        );
        // If a domain is configured, emit DNS fingerprint instructions (non-strict at creation time)
        agent.set_dns_strict(false);
        if let Some(domain) = agent
            .config
            .as_ref()
            .and_then(|c| c.jacs_agent_domain().clone())
            .filter(|s| !s.is_empty())
            && let Ok(pk) = agent.get_public_key()
        {
            let agent_id = agent.get_id().unwrap_or_else(|_| "".to_string());
            let digest = dns_bootstrap::pubkey_digest_b64(&pk);
            let rr = dns_bootstrap::build_dns_record(
                &domain,
                3600,
                &agent_id,
                &digest,
                dns_bootstrap::DigestEncoding::Base64,
            );
            println!("\nDNS (BIND):\n{}\n", dns_bootstrap::emit_plain_bind(&rr));
            println!(
                "Use 'jacs agent dns --domain {} --provider <plain|aws|azure|cloudflare>' for provider-specific commands.",
                domain
            );
            println!("Reminder: enable DNSSEC for the zone and publish DS at the registrar.");
        }
    }

    // Use the modified agent string here
    agent.create_agent_and_load(&modified_agent_string, false, None)?;

    let agent_id_version = agent.get_lookup_id()?;
    println!("Agent {} created successfully!", agent_id_version);

    agent.save()?;

    // -- Ask user if they want to update the config using request_string --
    let prompt_message = format!(
        "Do you want to set {} as the default agent in jacs.config.json and environment variable? (yes/no)",
        agent_id_version
    );
    let update_confirmation = request_string(&prompt_message, "no"); // Default to no

    if update_confirmation.trim().to_lowercase() == "yes"
        || update_confirmation.trim().to_lowercase() == "y"
    {
        println!("Updating configuration...");
        let config_path_str = "jacs.config.json";
        let config_path = Path::new(config_path_str);

        // Use std::fs for reading
        let mut current_config: Value = match std::fs::read_to_string(config_path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
                println!(
                    "Warning: Could not parse {}, creating default. Error: {}",
                    config_path_str, e
                );
                json!({}) // Start with empty object if parse fails or file empty
            }),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                println!("Warning: {} not found, creating default.", config_path_str);
                json!({}) // Start with empty object if file doesn't exist
            }
            Err(e) => {
                eprintln!("Error reading {}: {}. Cannot update.", config_path_str, e);
                return Ok(()); // Exit this block gracefully if read fails for other reasons
            }
        };

        if !current_config.is_object() {
            println!(
                "Warning: {} content is not a JSON object. Overwriting with default structure.",
                config_path_str
            );
            current_config = json!({});
        }

        if let Some(obj) = current_config.as_object_mut() {
            obj.insert(
                "jacs_agent_id_and_version".to_string(),
                json!(agent_id_version),
            );
            if !obj.contains_key("$schema") {
                obj.insert(
                    "$schema".to_string(),
                    json!("https://hai.ai/schemas/jacs.config.schema.json"),
                );
            }
        }

        // Use std::fs for writing
        match std::fs::write(
            config_path,
            serde_json::to_string_pretty(&current_config).unwrap(),
        ) {
            Ok(_) => println!("Successfully updated {}.", config_path_str),
            Err(e) => eprintln!("Error writing {}: {}", config_path_str, e),
        }

        // Update environment variables for the current session
        match set_env_var("JACS_AGENT_ID_AND_VERSION", &agent_id_version) {
            Ok(_) => {
                println!("Updated JACS_AGENT_ID_AND_VERSION environment variable for this session.")
            }
            Err(e) => eprintln!(
                "Failed to update JACS_AGENT_ID_AND_VERSION environment variable: {}",
                e
            ),
        }
        match check_env_vars(false) {
            Ok(report) => println!("Environment Variable Check:\n{}", report),
            Err(e) => {
                eprintln!("Error checking environment variables after update: {}", e)
            }
        }
    } else {
        println!("Skipping configuration update.");
    }
    Ok(())
}
