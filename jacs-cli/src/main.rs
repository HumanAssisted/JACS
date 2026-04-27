// The clap `Command` tree lives in `src/cli_builder.rs` (re-exported by
// `src/lib.rs` as `jacs_cli::build_cli`). main.rs is a thin entry point
// that consumes the parsed `ArgMatches` — see Issue 017 / Issue 023.
use jacs_cli::build_cli;

mod agent_loader;

use agent_loader::{load_agent, load_agent_with_cli_dns_policy};
use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::cli_utils::create::{
    handle_agent_create, handle_agent_create_auto, handle_config_create,
};
use jacs::cli_utils::default_set_file_list;
use jacs::cli_utils::document::{
    check_agreement, create_agreement, create_documents, extract_documents, sign_documents,
    update_documents, verify_documents,
};
use jacs::create_task; // re-enabled: may be used by a2a later
use jacs::dns::bootstrap as dns_bootstrap;
use jacs::shutdown::{ShutdownGuard, install_signal_handler};
use jacs_cli::password_bootstrap::{
    ensure_cli_private_key_password, quickstart_password_bootstrap_help,
    wrap_quickstart_error_with_password_help,
};

use rpassword::read_password;
use std::env;
use std::error::Error;
use std::process;


// install/download functions removed — MCP is now built into the CLI
// build_cli moved to src/cli_builder.rs (re-exported by lib.rs)

pub fn main() -> Result<(), Box<dyn Error>> {
    // Install signal handler for graceful shutdown (Ctrl+C, SIGTERM)
    install_signal_handler();

    // Create shutdown guard to ensure cleanup on exit (including early returns)
    let _shutdown_guard = ShutdownGuard::new();
    let matches = build_cli().arg_required_else_help(true).get_matches();

    match matches.subcommand() {
        Some(("version", _sub_matches)) => {
            println!("{}", env!("CARGO_PKG_DESCRIPTION"));
            println!(
                "{} version: {}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }
        Some(("config", config_matches)) => match config_matches.subcommand() {
            Some(("create", _create_matches)) => {
                // Call the refactored handler function
                handle_config_create()?;
            }
            Some(("read", _read_matches)) => {
                let config_path = "./jacs.config.json";
                match jacs::config::Config::from_file(config_path) {
                    Ok(mut config) => {
                        config.apply_env_overrides();
                        println!("{}", config);
                    }
                    Err(e) => {
                        eprintln!("Could not load config from '{}': {}", config_path, e);
                        process::exit(1);
                    }
                }
            }
            _ => println!("please enter subcommand see jacs config --help"),
        },
        Some(("agent", agent_matches)) => match agent_matches.subcommand() {
            Some(("dns", sub_m)) => {
                let domain = sub_m.get_one::<String>("domain").cloned();
                let agent_id_arg = sub_m.get_one::<String>("agent-id").cloned();
                let ttl = *sub_m.get_one::<u32>("ttl").unwrap();
                let enc = sub_m
                    .get_one::<String>("encoding")
                    .map(|s| s.as_str())
                    .unwrap_or("base64");
                let provider = sub_m
                    .get_one::<String>("provider")
                    .map(|s| s.as_str())
                    .unwrap_or("plain");

                // Load agent from optional path, supporting non-strict DNS for propagation
                let _agent_file = sub_m.get_one::<String>("agent-file").cloned();
                let non_strict = *sub_m.get_one::<bool>("no-dns").unwrap_or(&false);
                let ignore_dns = *sub_m.get_one::<bool>("ignore-dns").unwrap_or(&false);
                let require_strict = *sub_m
                    .get_one::<bool>("require-strict-dns")
                    .unwrap_or(&false);
                let require_dns = *sub_m.get_one::<bool>("require-dns").unwrap_or(&false);
                let agent: Agent = load_agent_with_cli_dns_policy(
                    ignore_dns,
                    require_strict,
                    require_dns,
                    non_strict,
                )
                .expect("Failed to load agent from config");
                let agent_id = agent_id_arg.unwrap_or_else(|| agent.get_id().unwrap_or_default());
                let pk = agent.get_public_key().expect("public key");
                let digest = match enc {
                    "hex" => dns_bootstrap::pubkey_digest_hex(&pk),
                    _ => dns_bootstrap::pubkey_digest_b64(&pk),
                };
                let domain_final = domain
                    .or_else(|| {
                        agent
                            .config
                            .as_ref()
                            .and_then(|c| c.jacs_agent_domain().clone())
                    })
                    .expect("domain required via --domain or jacs_agent_domain in config");

                let rr = dns_bootstrap::build_dns_record(
                    &domain_final,
                    ttl,
                    &agent_id,
                    &digest,
                    if enc == "hex" {
                        dns_bootstrap::DigestEncoding::Hex
                    } else {
                        dns_bootstrap::DigestEncoding::Base64
                    },
                );

                println!("Plain/BIND:\n{}", dns_bootstrap::emit_plain_bind(&rr));
                match provider {
                    "aws" => println!(
                        "\nRoute53 change-batch JSON:\n{}",
                        dns_bootstrap::emit_route53_change_batch(&rr)
                    ),
                    "azure" => println!(
                        "\nAzure CLI:\n{}",
                        dns_bootstrap::emit_azure_cli(
                            &rr,
                            "$RESOURCE_GROUP",
                            &domain_final,
                            "_v1.agent.jacs"
                        )
                    ),
                    "cloudflare" => println!(
                        "\nCloudflare curl:\n{}",
                        dns_bootstrap::emit_cloudflare_curl(&rr, "$ZONE_ID")
                    ),
                    _ => {}
                }
                println!(
                    "\nChecklist: Ensure DNSSEC is enabled for {domain} and DS is published at registrar.",
                    domain = domain_final
                );
            }
            Some(("create", create_matches)) => {
                // Parse args for the specific agent create command
                let filename = create_matches.get_one::<String>("filename");
                let create_keys = *create_matches.get_one::<bool>("create-keys").unwrap();

                // Call the refactored handler function
                handle_agent_create(filename, create_keys)?;
            }
            Some(("verify", verify_matches)) => {
                let _agentfile = verify_matches.get_one::<String>("agent-file");
                let non_strict = *verify_matches.get_one::<bool>("no-dns").unwrap_or(&false);
                let require_dns = *verify_matches
                    .get_one::<bool>("require-dns")
                    .unwrap_or(&false);
                let require_strict = *verify_matches
                    .get_one::<bool>("require-strict-dns")
                    .unwrap_or(&false);
                let ignore_dns = *verify_matches
                    .get_one::<bool>("ignore-dns")
                    .unwrap_or(&false);
                let mut agent: Agent = load_agent_with_cli_dns_policy(
                    ignore_dns,
                    require_strict,
                    require_dns,
                    non_strict,
                )
                .expect("Failed to load agent from config");
                agent
                    .verify_self_signature()
                    .expect("signature verification");
                println!(
                    "Agent {} signature verified OK.",
                    agent.get_lookup_id().expect("jacsId")
                );
            }
            Some(("lookup", lookup_matches)) => {
                let domain = lookup_matches
                    .get_one::<String>("domain")
                    .expect("domain required");
                let skip_dns = *lookup_matches.get_one::<bool>("no-dns").unwrap_or(&false);
                let strict_dns = *lookup_matches.get_one::<bool>("strict").unwrap_or(&false);

                println!("Agent Lookup: {}\n", domain);

                // Fetch public key from well-known endpoint
                println!("Public Key (/.well-known/jacs-pubkey.json):");
                let url = format!("https://{}/.well-known/jacs-pubkey.json", domain);
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .expect("HTTP client");
                match client.get(&url).send() {
                    Ok(response) => {
                        if response.status().is_success() {
                            match response.json::<serde_json::Value>() {
                                Ok(json) => {
                                    println!(
                                        "  Agent ID: {}",
                                        json.get("agentId")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Not specified")
                                    );
                                    println!(
                                        "  Algorithm: {}",
                                        json.get("algorithm")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Not specified")
                                    );
                                    println!(
                                        "  Public Key Hash: {}",
                                        json.get("publicKeyHash")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Not specified")
                                    );
                                    if let Some(pk) = json.get("publicKey").and_then(|v| v.as_str())
                                    {
                                        let preview = if pk.len() > 60 {
                                            format!("{}...", &pk[..60])
                                        } else {
                                            pk.to_string()
                                        };
                                        println!("  Public Key: {}", preview);
                                    }
                                }
                                Err(e) => println!("  Error parsing response: {}", e),
                            }
                        } else {
                            println!("  HTTP error: {}", response.status());
                        }
                    }
                    Err(e) => println!("  Error fetching: {}", e),
                }

                println!();

                // DNS TXT record lookup
                if !skip_dns {
                    println!("DNS TXT Record (_v1.agent.jacs.{}):", domain);
                    let owner = format!("_v1.agent.jacs.{}", domain.trim_end_matches('.'));
                    let lookup_result = if strict_dns {
                        dns_bootstrap::resolve_txt_dnssec(&owner)
                    } else {
                        dns_bootstrap::resolve_txt_insecure(&owner)
                    };
                    match lookup_result {
                        Ok(txt) => {
                            // Parse the TXT record
                            match dns_bootstrap::parse_agent_txt(&txt) {
                                Ok(parsed) => {
                                    println!("  Version: {}", parsed.v);
                                    println!("  Agent ID: {}", parsed.jacs_agent_id);
                                    println!("  Algorithm: {:?}", parsed.alg);
                                    println!("  Encoding: {:?}", parsed.enc);
                                    println!("  Public Key Hash: {}", parsed.digest);
                                }
                                Err(e) => println!("  Error parsing TXT: {}", e),
                            }
                            println!("  Raw TXT: {}", txt);
                        }
                        Err(e) => {
                            println!("  No DNS TXT record found: {}", e);
                            if strict_dns {
                                println!("  (Strict DNSSEC validation was required)");
                            }
                        }
                    }
                } else {
                    println!("DNS TXT Record: Skipped (--no-dns)");
                }
            }
            Some(("rotate-keys", sub_m)) => {
                use jacs::simple::SimpleAgent;

                let config_path = sub_m.get_one::<String>("config").map(|s| s.as_str());
                let algorithm = sub_m.get_one::<String>("algorithm").map(|s| s.as_str());

                let agent =
                    SimpleAgent::load(config_path, None).map_err(|e| -> Box<dyn Error> {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to load agent: {}", e),
                        ))
                    })?;

                let result = jacs::simple::advanced::rotate(&agent, algorithm).map_err(
                    |e| -> Box<dyn Error> {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Key rotation failed: {}", e),
                        ))
                    },
                )?;

                println!("Key rotation successful.");
                println!("  Agent ID:          {}", result.jacs_id);
                println!("  Old version:       {}", result.old_version);
                println!("  New version:       {}", result.new_version);
                println!("  New key hash:      {}", result.new_public_key_hash);
                if result.transition_proof.is_some() {
                    println!("  Transition proof:  present");
                }
            }
            Some(("keys-list", sub_m)) => {
                let config_path = sub_m.get_one::<String>("config");
                let config_p = config_path
                    .map(|s| s.as_str())
                    .unwrap_or("./jacs.config.json");

                let config =
                    jacs::config::Config::from_file(config_p).map_err(|e| -> Box<dyn Error> {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to load config: {}", e),
                        ))
                    })?;

                let key_dir = config
                    .jacs_key_directory()
                    .as_deref()
                    .unwrap_or("./jacs_keys");
                let algo = config
                    .jacs_agent_key_algorithm()
                    .as_deref()
                    .unwrap_or("unknown");
                let pub_name = config
                    .jacs_agent_public_key_filename()
                    .as_deref()
                    .unwrap_or("jacs.public.pem");

                // Show active key
                let active_path = std::path::Path::new(key_dir).join(pub_name);
                if active_path.exists() {
                    let meta = std::fs::metadata(&active_path).ok();
                    let modified = meta
                        .and_then(|m| m.modified().ok())
                        .map(|t| {
                            let duration =
                                t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                            format!("{}s since epoch", duration.as_secs())
                        })
                        .unwrap_or_else(|| "unknown".to_string());
                    println!(
                        "Active:   {} (algorithm: {}, modified: {})",
                        active_path.display(),
                        algo,
                        modified
                    );
                } else {
                    println!(
                        "Active:   (no public key found at {})",
                        active_path.display()
                    );
                }

                // Scan for archived keys
                let mut archived: Vec<(String, String)> = Vec::new();
                if let Ok(entries) = std::fs::read_dir(key_dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        // Archived keys look like: jacs.public.{uuid}.pem
                        if name.ends_with(".pem")
                            && name.starts_with("jacs.public.")
                            && name != pub_name
                        {
                            let modified = entry
                                .metadata()
                                .ok()
                                .and_then(|m| m.modified().ok())
                                .map(|t| {
                                    let duration =
                                        t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                                    format!("{}s since epoch", duration.as_secs())
                                })
                                .unwrap_or_else(|| "unknown".to_string());
                            archived.push((name, modified));
                        }
                    }
                }

                if archived.is_empty() {
                    println!("Archived: (none)");
                } else {
                    archived.sort_by(|a, b| b.1.cmp(&a.1));
                    for (name, modified) in &archived {
                        println!("Archived: {}/{} (modified: {})", key_dir, name, modified);
                    }
                }
            }
            Some(("repair", sub_m)) => {
                use jacs::keystore::RotationJournal;
                use jacs::simple::SimpleAgent;

                let config_path = sub_m.get_one::<String>("config");
                let config_p = config_path
                    .map(|s| s.as_str())
                    .unwrap_or("./jacs.config.json");

                let config =
                    jacs::config::Config::from_file(config_p).map_err(|e| -> Box<dyn Error> {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to load config: {}", e),
                        ))
                    })?;

                let key_dir = config
                    .jacs_key_directory()
                    .as_deref()
                    .unwrap_or("./jacs_keys");

                let journal_path = RotationJournal::journal_path(key_dir);
                if RotationJournal::load(&journal_path).is_some() {
                    println!(
                        "Incomplete rotation detected (journal at {}). Loading agent to trigger auto-repair...",
                        journal_path
                    );
                    // Loading the agent triggers warn_if_config_tampered -> auto-repair
                    let _agent =
                        SimpleAgent::load(Some(config_p), None).map_err(|e| -> Box<dyn Error> {
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Repair failed: {}", e),
                            ))
                        })?;
                    // Check if journal was cleaned up
                    if RotationJournal::load(&journal_path).is_none() {
                        println!("Config repaired successfully. Journal cleaned up.");
                    } else {
                        println!(
                            "Warning: Journal still present after load. Manual intervention may be needed."
                        );
                    }
                } else {
                    println!("No incomplete rotation detected. Nothing to repair.");
                }
            }
            _ => println!("please enter subcommand see jacs agent --help"),
        },

        Some(("task", task_matches)) => match task_matches.subcommand() {
            Some(("create", create_matches)) => {
                let _agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent().expect("failed to load agent for task create");
                let name = create_matches
                    .get_one::<String>("name")
                    .expect("task name is required");
                let description = create_matches
                    .get_one::<String>("description")
                    .expect("task description is required");
                println!(
                    "{}",
                    create_task(&mut agent, name.to_string(), description.to_string()).unwrap()
                );
            }
            Some(("update", update_matches)) => {
                let mut agent: Agent = load_agent().expect("failed to load agent for task update");
                let task_key = update_matches
                    .get_one::<String>("task-key")
                    .expect("task key is required");
                let filename = update_matches
                    .get_one::<String>("filename")
                    .expect("filename is required");
                let updated_json = std::fs::read_to_string(filename)
                    .unwrap_or_else(|e| panic!("Failed to read '{}': {}", filename, e));
                println!(
                    "{}",
                    jacs::update_task(&mut agent, task_key, &updated_json).unwrap()
                );
            }
            _ => println!("please enter subcommand see jacs task --help"),
        },
        Some(("document", document_matches)) => match document_matches.subcommand() {
            Some(("create", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let outputfilename = create_matches.get_one::<String>("output");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let _agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches
                    .get_one::<String>("attach")
                    .map(|s| s.as_str());
                let embed: Option<bool> = create_matches.get_one::<bool>("embed").copied();

                let mut agent: Agent = load_agent().expect("REASON");

                let _attachment_links = agent.parse_attachement_arg(attachments);
                let _ = create_documents(
                    &mut agent,
                    filename,
                    directory,
                    outputfilename,
                    attachments,
                    embed,
                    no_save,
                    schema,
                );
            }
            // TODO copy for sharing
            // Some(("copy", create_matches)) => {
            Some(("update", create_matches)) => {
                let new_filename = create_matches.get_one::<String>("new").unwrap();
                let original_filename = create_matches.get_one::<String>("filename").unwrap();
                let outputfilename = create_matches.get_one::<String>("output");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let _agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches
                    .get_one::<String>("attach")
                    .map(|s| s.as_str());
                let embed: Option<bool> = create_matches.get_one::<bool>("embed").copied();

                let mut agent: Agent = load_agent().expect("REASON");

                let attachment_links = agent.parse_attachement_arg(attachments);
                update_documents(
                    &mut agent,
                    new_filename,
                    original_filename,
                    outputfilename,
                    attachment_links,
                    embed,
                    no_save,
                    schema,
                )?;
            }
            Some(("sign-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let _agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent().expect("REASON");
                let schema = create_matches.get_one::<String>("schema");
                let _no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);

                // Use updated set_file_list with storage
                sign_documents(&mut agent, schema, filename, directory)?;
            }
            Some(("check-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent().expect("REASON");
                let schema = create_matches.get_one::<String>("schema");

                // Use updated set_file_list with storage
                let _files: Vec<String> = default_set_file_list(filename, directory, None)
                    .expect("Failed to determine file list");
                check_agreement(&mut agent, schema, filename, directory)?;
            }
            Some(("create-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let _agentfile = create_matches.get_one::<String>("agent-file");

                let schema = create_matches.get_one::<String>("schema");
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentids: Vec<String> = create_matches // Corrected reference to create_matches
                    .get_many::<String>("agentids")
                    .unwrap_or_default()
                    .map(|s| s.to_string())
                    .collect();

                let mut agent: Agent = load_agent().expect("REASON");
                // Use updated set_file_list with storage
                let _ =
                    create_agreement(&mut agent, agentids, filename, schema, no_save, directory);
            }

            Some(("verify", verify_matches)) => {
                let filename = verify_matches.get_one::<String>("filename");
                let directory = verify_matches.get_one::<String>("directory");
                let _verbose = *verify_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let _agentfile = verify_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent().expect("REASON");
                let schema = verify_matches.get_one::<String>("schema");
                // Use updated set_file_list with storage
                verify_documents(&mut agent, schema, filename, directory)?;
            }

            Some(("extract", extract_matches)) => {
                let filename = extract_matches.get_one::<String>("filename");
                let directory = extract_matches.get_one::<String>("directory");
                let _verbose = *extract_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let _agentfile = extract_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent().expect("REASON");
                let schema = extract_matches.get_one::<String>("schema");
                // Use updated set_file_list with storage
                let _files: Vec<String> = default_set_file_list(filename, directory, None)
                    .expect("Failed to determine file list");
                // extract the contents but do not save
                extract_documents(&mut agent, schema, filename, directory)?;
            }

            _ => println!("please enter subcommand see jacs document --help"),
        },
        Some(("key", key_matches)) => match key_matches.subcommand() {
            Some(("reencrypt", _reencrypt_matches)) => {
                use jacs::crypt::aes_encrypt::password_requirements;
                use jacs::simple::SimpleAgent;

                // Load the agent first to find the key file
                let agent = SimpleAgent::load(None, None).map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to load agent: {}", e),
                    ))
                })?;

                println!("Re-encrypting private key.\n");

                // Get old password
                println!("Enter current password:");
                let old_password = read_password().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Error reading password: {}", e),
                    ))
                })?;

                if old_password.is_empty() {
                    eprintln!("Error: current password cannot be empty.");
                    process::exit(1);
                }

                // Get new password
                println!("\n{}", password_requirements());
                println!("\nEnter new password:");
                let new_password = read_password().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Error reading password: {}", e),
                    ))
                })?;

                println!("Confirm new password:");
                let new_password_confirm = read_password().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Error reading password: {}", e),
                    ))
                })?;

                if new_password != new_password_confirm {
                    eprintln!("Error: new passwords do not match.");
                    process::exit(1);
                }

                jacs::simple::advanced::reencrypt_key(&agent, &old_password, &new_password)
                    .map_err(|e| -> Box<dyn Error> {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Re-encryption failed: {}", e),
                        ))
                    })?;

                println!("Private key re-encrypted successfully.");
            }
            _ => println!("please enter subcommand see jacs key --help"),
        },
        #[cfg(feature = "mcp")]
        Some(("mcp", mcp_matches)) => match mcp_matches.subcommand() {
            Some(("install", _)) => {
                eprintln!("`jacs mcp install` is no longer needed.");
                eprintln!("MCP is built into the jacs binary. Use `jacs mcp` to serve.");
                process::exit(0);
            }
            Some(("run", _)) => {
                eprintln!("`jacs mcp run` is no longer needed.");
                eprintln!("Use `jacs mcp` directly to start the MCP server.");
                process::exit(0);
            }
            _ => {
                let profile_str = mcp_matches.get_one::<String>("profile").map(|s| s.as_str());
                let profile = jacs_mcp::Profile::resolve(profile_str);
                let (agent, info) = jacs_mcp::load_agent_from_config_env_with_info()?;
                let state_roots = info["data_directory"]
                    .as_str()
                    .map(std::path::PathBuf::from)
                    .into_iter()
                    .collect();
                let server = jacs_mcp::JacsMcpServer::with_profile_and_state_roots(
                    agent,
                    profile,
                    state_roots,
                );
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(jacs_mcp::serve_stdio(server))?;
            }
        },
        #[cfg(not(feature = "mcp"))]
        Some(("mcp", _)) => {
            eprintln!(
                "MCP support not compiled. Install with default features: cargo install jacs-cli"
            );
            process::exit(1);
        }
        Some(("a2a", a2a_matches)) => match a2a_matches.subcommand() {
            Some(("assess", assess_matches)) => {
                use jacs::a2a::AgentCard;
                use jacs::a2a::trust::{A2ATrustPolicy, assess_a2a_agent};

                let source = assess_matches.get_one::<String>("source").unwrap();
                let policy_str = assess_matches
                    .get_one::<String>("policy")
                    .map(|s| s.as_str())
                    .unwrap_or("verified");
                let json_output = *assess_matches.get_one::<bool>("json").unwrap_or(&false);

                let policy = A2ATrustPolicy::from_str_loose(policy_str)
                    .map_err(|e| Box::<dyn Error>::from(format!("Invalid policy: {}", e)))?;

                // Load the Agent Card from file or URL
                let card_json = if source.starts_with("http://") || source.starts_with("https://") {
                    let client = reqwest::blocking::Client::builder()
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .map_err(|e| format!("HTTP client error: {}", e))?;
                    client
                        .get(source.as_str())
                        .send()
                        .map_err(|e| format!("Fetch failed: {}", e))?
                        .text()
                        .map_err(|e| format!("Read body failed: {}", e))?
                } else {
                    std::fs::read_to_string(source)
                        .map_err(|e| format!("Read file failed: {}", e))?
                };

                let card: AgentCard = serde_json::from_str(&card_json)
                    .map_err(|e| format!("Invalid Agent Card JSON: {}", e))?;

                // Create an empty agent for assessment context
                let agent = jacs::get_empty_agent();
                let assessment = assess_a2a_agent(&agent, &card, policy);

                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&assessment)
                            .expect("assessment serialization")
                    );
                } else {
                    println!("Agent:       {}", card.name);
                    println!(
                        "Agent ID:    {}",
                        assessment.agent_id.as_deref().unwrap_or("(not specified)")
                    );
                    println!("Policy:      {}", assessment.policy);
                    println!("Trust Level: {}", assessment.trust_level);
                    println!(
                        "Allowed:     {}",
                        if assessment.allowed { "YES" } else { "NO" }
                    );
                    println!("JACS Ext:    {}", assessment.jacs_registered);
                    println!("Reason:      {}", assessment.reason);
                    if !assessment.allowed {
                        process::exit(1);
                    }
                }
            }
            Some(("trust", trust_matches)) => {
                use jacs::a2a::AgentCard;
                use jacs::trust;

                let source = trust_matches.get_one::<String>("source").unwrap();

                // Load the Agent Card from file or URL
                let card_json = if source.starts_with("http://") || source.starts_with("https://") {
                    let client = reqwest::blocking::Client::builder()
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .map_err(|e| format!("HTTP client error: {}", e))?;
                    client
                        .get(source.as_str())
                        .send()
                        .map_err(|e| format!("Fetch failed: {}", e))?
                        .text()
                        .map_err(|e| format!("Read body failed: {}", e))?
                } else {
                    std::fs::read_to_string(source)
                        .map_err(|e| format!("Read file failed: {}", e))?
                };

                let card: AgentCard = serde_json::from_str(&card_json)
                    .map_err(|e| format!("Invalid Agent Card JSON: {}", e))?;

                // Extract agent ID and version from metadata
                let agent_id = card
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("jacsId"))
                    .and_then(|v| v.as_str())
                    .ok_or("Agent Card has no jacsId in metadata")?;
                let agent_version = card
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("jacsVersion"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let key = format!("{}:{}", agent_id, agent_version);

                // Add to trust store with the card JSON as the public key PEM
                // (the trust store stores agent metadata; public key comes from
                //  well-known endpoints or DNS in practice)
                trust::trust_a2a_card(&key, &card_json)?;

                println!(
                    "Saved unverified A2A Agent Card bookmark '{}' ({})",
                    card.name, agent_id
                );
                println!("  Version: {}", agent_version);
                println!("  Bookmark key: {}", key);
                println!(
                    "  This entry is not cryptographically trusted until verified JACS identity material is added."
                );
            }
            Some(("discover", discover_matches)) => {
                use jacs::a2a::AgentCard;
                use jacs::a2a::trust::{A2ATrustPolicy, assess_a2a_agent};

                let base_url = discover_matches.get_one::<String>("url").unwrap();
                let json_output = *discover_matches.get_one::<bool>("json").unwrap_or(&false);
                let policy_str = discover_matches
                    .get_one::<String>("policy")
                    .map(|s| s.as_str())
                    .unwrap_or("verified");

                let policy = A2ATrustPolicy::from_str_loose(policy_str)
                    .map_err(|e| Box::<dyn Error>::from(format!("Invalid policy: {}", e)))?;

                // Construct the well-known URL
                let trimmed = base_url.trim_end_matches('/');
                let card_url = format!("{}/.well-known/agent-card.json", trimmed);

                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .map_err(|e| format!("HTTP client error: {}", e))?;

                let response = client
                    .get(&card_url)
                    .send()
                    .map_err(|e| format!("Failed to fetch {}: {}", card_url, e))?;

                if !response.status().is_success() {
                    eprintln!(
                        "Failed to discover agent at {}: HTTP {}",
                        card_url,
                        response.status()
                    );
                    process::exit(1);
                }

                let card_json = response
                    .text()
                    .map_err(|e| format!("Read body failed: {}", e))?;

                let card: AgentCard = serde_json::from_str(&card_json)
                    .map_err(|e| format!("Invalid Agent Card JSON at {}: {}", card_url, e))?;

                if json_output {
                    // Print the full Agent Card
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&card).expect("card serialization")
                    );
                } else {
                    // Human-readable summary
                    println!("Discovered A2A Agent: {}", card.name);
                    println!("  Description: {}", card.description);
                    println!("  Version:     {}", card.version);
                    println!("  Protocol:    {}", card.protocol_versions.join(", "));

                    // Show interfaces
                    for iface in &card.supported_interfaces {
                        println!("  Endpoint:    {} ({})", iface.url, iface.protocol_binding);
                    }

                    // Show skills
                    if !card.skills.is_empty() {
                        println!("  Skills:");
                        for skill in &card.skills {
                            println!("    - {} ({})", skill.name, skill.id);
                        }
                    }

                    // JACS extension check
                    let has_jacs = card
                        .capabilities
                        .extensions
                        .as_ref()
                        .map(|exts| exts.iter().any(|e| e.uri == jacs::a2a::JACS_EXTENSION_URI))
                        .unwrap_or(false);
                    println!("  JACS:        {}", if has_jacs { "YES" } else { "NO" });

                    // Trust assessment
                    let agent = jacs::get_empty_agent();
                    let assessment = assess_a2a_agent(&agent, &card, policy);
                    println!(
                        "  Trust:       {} ({})",
                        assessment.trust_level, assessment.reason
                    );
                    if !assessment.allowed {
                        println!(
                            "  WARNING:     Agent not allowed under '{}' policy",
                            policy_str
                        );
                    }
                }
            }
            Some(("serve", serve_matches)) => {
                let port = *serve_matches.get_one::<u16>("port").unwrap();
                let host = serve_matches
                    .get_one::<String>("host")
                    .map(|s| s.as_str())
                    .unwrap_or("127.0.0.1");

                // Load or quickstart the agent
                ensure_cli_private_key_password().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::other(format!(
                        "Password bootstrap failed: {}\n\n{}",
                        e,
                        quickstart_password_bootstrap_help()
                    )))
                })?;
                let (agent, info) = jacs::simple::advanced::quickstart(
                    "jacs-agent",
                    "localhost",
                    Some("JACS A2A agent"),
                    None,
                    None,
                )
                .map_err(|e| wrap_quickstart_error_with_password_help("Failed to load agent", e))?;

                // Export the Agent Card for display
                let agent_card = jacs::a2a::simple::export_agent_card(&agent).map_err(
                    |e| -> Box<dyn Error> {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to export Agent Card: {}", e),
                        ))
                    },
                )?;

                // Generate well-known documents via public API
                let documents = jacs::a2a::simple::generate_well_known_documents(&agent, None)
                    .map_err(|e| -> Box<dyn Error> {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to generate well-known documents: {}", e),
                        ))
                    })?;

                // Build a lookup map: path -> JSON body
                let mut routes: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                for (path, value) in &documents {
                    routes.insert(
                        path.clone(),
                        serde_json::to_string_pretty(value).unwrap_or_default(),
                    );
                }

                let addr = format!("{}:{}", host, port);
                let server = tiny_http::Server::http(&addr)
                    .map_err(|e| format!("Failed to start server on {}: {}", addr, e))?;

                println!("Serving A2A well-known endpoints at http://{}", addr);
                println!("  Agent: {} ({})", agent_card.name, info.agent_id);
                println!("  Endpoints:");
                for path in routes.keys() {
                    println!("    http://{}{}", addr, path);
                }
                println!("\nPress Ctrl+C to stop.");

                for request in server.incoming_requests() {
                    let url = request.url().to_string();
                    if let Some(body) = routes.get(&url) {
                        let response = tiny_http::Response::from_string(body.clone()).with_header(
                            tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/json"[..],
                            )
                            .unwrap(),
                        );
                        let _ = request.respond(response);
                    } else {
                        let response =
                            tiny_http::Response::from_string("{\"error\": \"not found\"}")
                                .with_status_code(404)
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        &b"Content-Type"[..],
                                        &b"application/json"[..],
                                    )
                                    .unwrap(),
                                );
                        let _ = request.respond(response);
                    }
                }
            }
            Some(("quickstart", qs_matches)) => {
                let port = *qs_matches.get_one::<u16>("port").unwrap();
                let host = qs_matches
                    .get_one::<String>("host")
                    .map(|s| s.as_str())
                    .unwrap_or("127.0.0.1");
                let algorithm = qs_matches
                    .get_one::<String>("algorithm")
                    .map(|s| s.as_str());
                let name = qs_matches
                    .get_one::<String>("name")
                    .map(|s| s.as_str())
                    .unwrap_or("jacs-agent");
                let domain = qs_matches
                    .get_one::<String>("domain")
                    .map(|s| s.as_str())
                    .unwrap_or("localhost");
                let description = qs_matches
                    .get_one::<String>("description")
                    .map(|s| s.as_str());

                // Create or load the agent via quickstart
                ensure_cli_private_key_password().map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::other(format!(
                        "Password bootstrap failed: {}\n\n{}",
                        e,
                        quickstart_password_bootstrap_help()
                    )))
                })?;
                let (agent, info) =
                    jacs::simple::advanced::quickstart(name, domain, description, algorithm, None)
                        .map_err(|e| {
                            wrap_quickstart_error_with_password_help(
                                "Failed to quickstart agent",
                                e,
                            )
                        })?;

                // Export the Agent Card
                let agent_card = jacs::a2a::simple::export_agent_card(&agent).map_err(
                    |e| -> Box<dyn Error> {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to export Agent Card: {}", e),
                        ))
                    },
                )?;

                // Generate well-known documents
                let documents = jacs::a2a::simple::generate_well_known_documents(&agent, None)
                    .map_err(|e| -> Box<dyn Error> {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to generate well-known documents: {}", e),
                        ))
                    })?;

                // Build route map
                let mut routes: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                for (path, value) in &documents {
                    routes.insert(
                        path.clone(),
                        serde_json::to_string_pretty(value).unwrap_or_default(),
                    );
                }

                let addr = format!("{}:{}", host, port);
                let server = tiny_http::Server::http(&addr)
                    .map_err(|e| format!("Failed to start server on {}: {}", addr, e))?;

                println!("A2A Quickstart");
                println!("==============");
                println!("Agent: {} ({})", agent_card.name, info.agent_id);
                println!("Algorithm: {}", algorithm.unwrap_or("pq2025"));
                println!();
                println!("Discovery URL: http://{}/.well-known/agent-card.json", addr);
                println!();
                println!("Endpoints:");
                for path in routes.keys() {
                    println!("  http://{}{}", addr, path);
                }
                println!();
                println!("Press Ctrl+C to stop.");

                for request in server.incoming_requests() {
                    let url = request.url().to_string();
                    if let Some(body) = routes.get(&url) {
                        let response = tiny_http::Response::from_string(body.clone()).with_header(
                            tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/json"[..],
                            )
                            .unwrap(),
                        );
                        let _ = request.respond(response);
                    } else {
                        let response =
                            tiny_http::Response::from_string("{\"error\": \"not found\"}")
                                .with_status_code(404)
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        &b"Content-Type"[..],
                                        &b"application/json"[..],
                                    )
                                    .unwrap(),
                                );
                        let _ = request.respond(response);
                    }
                }
            }
            _ => println!("please enter subcommand see jacs a2a --help"),
        },
        Some(("quickstart", qs_matches)) => {
            let algorithm = qs_matches
                .get_one::<String>("algorithm")
                .map(|s| s.as_str());
            let name = qs_matches
                .get_one::<String>("name")
                .map(|s| s.as_str())
                .unwrap_or("jacs-agent");
            let domain = qs_matches
                .get_one::<String>("domain")
                .map(|s| s.as_str())
                .unwrap_or("localhost");
            let description = qs_matches
                .get_one::<String>("description")
                .map(|s| s.as_str());
            let do_sign = *qs_matches.get_one::<bool>("sign").unwrap_or(&false);
            let sign_file = qs_matches.get_one::<String>("file");

            // Try to resolve password from existing sources (env var, password file, legacy file).
            // If none found, prompt interactively and store in OS keychain.
            if let Err(e) = ensure_cli_private_key_password() {
                eprintln!("Note: {}", e);
            }

            // If still no password available, prompt interactively
            if env::var("JACS_PRIVATE_KEY_PASSWORD")
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                eprintln!("{}", jacs::crypt::aes_encrypt::password_requirements());
                let password = loop {
                    eprintln!("Enter a password for your JACS private key:");
                    let pw =
                        read_password().map_err(|e| format!("Failed to read password: {}", e))?;
                    if pw.trim().is_empty() {
                        eprintln!("Password cannot be empty. Please try again.");
                        continue;
                    }
                    eprintln!("Confirm password:");
                    let pw2 =
                        read_password().map_err(|e| format!("Failed to read password: {}", e))?;
                    if pw != pw2 {
                        eprintln!("Passwords do not match. Please try again.");
                        continue;
                    }
                    break pw;
                };

                // SAFETY: CLI is single-threaded at this point
                unsafe {
                    env::set_var("JACS_PRIVATE_KEY_PASSWORD", &password);
                }

                // Note: keychain storage is handled by quickstart() after agent
                // creation, when the agent_id is known.
            }

            let (agent, info) =
                jacs::simple::advanced::quickstart(name, domain, description, algorithm, None)
                    .map_err(|e| {
                        wrap_quickstart_error_with_password_help("Quickstart failed", e)
                    })?;

            if do_sign {
                // Sign mode: read JSON, sign it, print signed document
                let input = if let Some(file_path) = sign_file {
                    std::fs::read_to_string(file_path)?
                } else {
                    use std::io::Read;
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf)?;
                    buf
                };

                let value: serde_json::Value = serde_json::from_str(&input)
                    .map_err(|e| format!("Invalid JSON input: {}", e))?;

                let signed = agent.sign_message(&value).map_err(|e| -> Box<dyn Error> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Signing failed: {}", e),
                    ))
                })?;

                println!("{}", signed.raw);
            } else {
                // Info mode: print agent details
                println!("JACS agent ready ({})", info.algorithm);
                println!("  Agent ID: {}", info.agent_id);
                println!("  Version:  {}", info.version);
                println!("  Config:   {}", info.config_path);
                println!("  Keys:     {}", info.key_directory);
                println!();
                println!("Sign something:");
                println!("  echo '{{\"hello\":\"world\"}}' | jacs quickstart --sign");
            }
        }
        #[cfg(feature = "attestation")]
        Some(("attest", attest_matches)) => {
            use jacs::attestation::types::*;
            use jacs::simple::SimpleAgent;

            match attest_matches.subcommand() {
                Some(("create", create_matches)) => {
                    // Ensure password is available for signing
                    ensure_cli_private_key_password()?;

                    // Load agent
                    let agent = match SimpleAgent::load(None, None) {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!("Failed to load agent: {}", e);
                            eprintln!("Run `jacs quickstart` first to create an agent.");
                            process::exit(1);
                        }
                    };

                    // Parse claims (required)
                    let claims_str = create_matches
                        .get_one::<String>("claims")
                        .expect("claims is required");
                    let claims: Vec<Claim> = serde_json::from_str(claims_str).map_err(|e| {
                        format!(
                            "Invalid claims JSON: {}. \
                             Provide a JSON array like '[{{\"name\":\"reviewed\",\"value\":true}}]'",
                            e
                        )
                    })?;

                    // Parse optional evidence
                    let evidence: Vec<EvidenceRef> =
                        if let Some(ev_str) = create_matches.get_one::<String>("evidence") {
                            serde_json::from_str(ev_str)
                                .map_err(|e| format!("Invalid evidence JSON: {}", e))?
                        } else {
                            vec![]
                        };

                    let att_json = if let Some(doc_path) =
                        create_matches.get_one::<String>("from-document")
                    {
                        // Lift from existing signed document
                        let doc_content = std::fs::read_to_string(doc_path).map_err(|e| {
                            format!("Failed to read document '{}': {}", doc_path, e)
                        })?;
                        let result = jacs::attestation::simple::lift(&agent, &doc_content, &claims)
                            .map_err(|e| {
                                format!("Failed to lift document to attestation: {}", e)
                            })?;
                        result.raw
                    } else {
                        // Build from scratch: need subject-type, subject-id, subject-digest
                        let subject_type_str = create_matches
                            .get_one::<String>("subject-type")
                            .ok_or("--subject-type is required when not using --from-document")?;
                        let subject_id = create_matches
                            .get_one::<String>("subject-id")
                            .ok_or("--subject-id is required when not using --from-document")?;
                        let subject_digest = create_matches
                            .get_one::<String>("subject-digest")
                            .ok_or("--subject-digest is required when not using --from-document")?;

                        let subject_type = match subject_type_str.as_str() {
                            "agent" => SubjectType::Agent,
                            "artifact" => SubjectType::Artifact,
                            "workflow" => SubjectType::Workflow,
                            "identity" => SubjectType::Identity,
                            other => {
                                return Err(format!("Unknown subject type: '{}'", other).into());
                            }
                        };

                        let subject = AttestationSubject {
                            subject_type,
                            id: subject_id.clone(),
                            digests: DigestSet {
                                sha256: subject_digest.clone(),
                                sha512: None,
                                additional: std::collections::HashMap::new(),
                            },
                        };

                        let result = jacs::attestation::simple::create(
                            &agent, &subject, &claims, &evidence, None, None,
                        )
                        .map_err(|e| format!("Failed to create attestation: {}", e))?;
                        result.raw
                    };

                    // Output to file or stdout
                    if let Some(output_path) = create_matches.get_one::<String>("output") {
                        std::fs::write(output_path, &att_json).map_err(|e| {
                            format!("Failed to write output file '{}': {}", output_path, e)
                        })?;
                        eprintln!("Attestation written to {}", output_path);
                    } else {
                        println!("{}", att_json);
                    }
                }
                Some(("verify", verify_matches)) => {
                    let file_path = verify_matches
                        .get_one::<String>("file")
                        .expect("file is required");
                    let full = *verify_matches.get_one::<bool>("full").unwrap_or(&false);
                    let json_output = *verify_matches.get_one::<bool>("json").unwrap_or(&false);
                    let key_dir = verify_matches.get_one::<String>("key-dir");
                    let max_depth = verify_matches.get_one::<u32>("max-depth");

                    // Set key directory if specified
                    if let Some(kd) = key_dir {
                        // SAFETY: CLI is single-threaded at this point
                        unsafe { std::env::set_var("JACS_KEY_DIRECTORY", kd) };
                    }

                    // Set max derivation depth if specified
                    if let Some(depth) = max_depth {
                        // SAFETY: CLI is single-threaded at this point
                        unsafe {
                            std::env::set_var("JACS_MAX_DERIVATION_DEPTH", depth.to_string())
                        };
                    }

                    // Read the attestation file
                    let att_content = std::fs::read_to_string(file_path).map_err(|e| {
                        format!("Failed to read attestation file '{}': {}", file_path, e)
                    })?;

                    // Load or create ephemeral agent for verification
                    ensure_cli_private_key_password().ok();
                    let agent = match SimpleAgent::load(None, None) {
                        Ok(a) => a,
                        Err(_) => {
                            let (a, _) = SimpleAgent::ephemeral(Some("ed25519"))
                                .map_err(|e| format!("Failed to create verifier: {}", e))?;
                            a
                        }
                    };

                    // Load the attestation document into agent storage first
                    let att_value: serde_json::Value = serde_json::from_str(&att_content)
                        .map_err(|e| format!("Invalid attestation JSON: {}", e))?;
                    let doc_key = format!(
                        "{}:{}",
                        att_value["jacsId"].as_str().unwrap_or("unknown"),
                        att_value["jacsVersion"].as_str().unwrap_or("unknown")
                    );

                    // We need to store the document so verify can find it by key.
                    // Use verify() which parses and stores the doc, then verify attestation.
                    let verify_result = agent.verify(&att_content);
                    if let Err(e) = &verify_result {
                        if json_output {
                            let out = serde_json::json!({
                                "valid": false,
                                "error": e.to_string(),
                            });
                            println!("{}", serde_json::to_string_pretty(&out).unwrap());
                        } else {
                            eprintln!("Verification error: {}", e);
                        }
                        process::exit(1);
                    }

                    // Now do attestation-specific verification
                    let att_result = if full {
                        jacs::attestation::simple::verify_full(&agent, &doc_key)
                    } else {
                        jacs::attestation::simple::verify(&agent, &doc_key)
                    };

                    match att_result {
                        Ok(r) => {
                            if json_output {
                                println!("{}", serde_json::to_string_pretty(&r).unwrap());
                            } else {
                                println!(
                                    "Status:    {}",
                                    if r.valid { "VALID" } else { "INVALID" }
                                );
                                println!(
                                    "Signature: {}",
                                    if r.crypto.signature_valid {
                                        "valid"
                                    } else {
                                        "INVALID"
                                    }
                                );
                                println!(
                                    "Hash:      {}",
                                    if r.crypto.hash_valid {
                                        "valid"
                                    } else {
                                        "INVALID"
                                    }
                                );
                                if !r.crypto.signer_id.is_empty() {
                                    println!("Signer:    {}", r.crypto.signer_id);
                                }
                                if !r.evidence.is_empty() {
                                    println!("Evidence:  {} items checked", r.evidence.len());
                                }
                                if !r.errors.is_empty() {
                                    for err in &r.errors {
                                        eprintln!("  Error: {}", err);
                                    }
                                }
                            }
                            if !r.valid {
                                process::exit(1);
                            }
                        }
                        Err(e) => {
                            if json_output {
                                let out = serde_json::json!({
                                    "valid": false,
                                    "error": e.to_string(),
                                });
                                println!("{}", serde_json::to_string_pretty(&out).unwrap());
                            } else {
                                eprintln!("Attestation verification error: {}", e);
                            }
                            process::exit(1);
                        }
                    }
                }
                Some(("export-dsse", export_matches)) => {
                    let file_path = export_matches
                        .get_one::<String>("file")
                        .expect("file argument required");
                    let output_path = export_matches.get_one::<String>("output");

                    let attestation_json = std::fs::read_to_string(file_path).unwrap_or_else(|e| {
                        eprintln!("Cannot read {}: {}", file_path, e);
                        process::exit(1);
                    });

                    let (_agent, _info) = SimpleAgent::ephemeral(Some("ring-Ed25519"))
                        .unwrap_or_else(|e| {
                            eprintln!("Failed to create agent: {}", e);
                            process::exit(1);
                        });

                    match jacs::attestation::simple::export_dsse(&attestation_json) {
                        Ok(envelope_json) => {
                            if let Some(out_path) = output_path {
                                std::fs::write(out_path, &envelope_json).unwrap_or_else(|e| {
                                    eprintln!("Cannot write to {}: {}", out_path, e);
                                    process::exit(1);
                                });
                                println!("DSSE envelope written to {}", out_path);
                            } else {
                                println!("{}", envelope_json);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to export DSSE envelope: {}", e);
                            process::exit(1);
                        }
                    }
                }
                _ => {
                    eprintln!(
                        "Use 'jacs attest create', 'jacs attest verify', or 'jacs attest export-dsse'. See --help."
                    );
                    process::exit(1);
                }
            }
        }
        Some(("verify", verify_matches)) => {
            use jacs::simple::SimpleAgent;
            use serde_json::json;

            let file_path = verify_matches.get_one::<String>("file");
            let remote_url = verify_matches.get_one::<String>("remote");
            let json_output = *verify_matches.get_one::<bool>("json").unwrap_or(&false);
            let key_dir = verify_matches.get_one::<String>("key-dir");

            // Optionally set key directory env var so the agent resolves keys from there
            if let Some(kd) = key_dir {
                // SAFETY: CLI is single-threaded at this point
                unsafe { std::env::set_var("JACS_KEY_DIRECTORY", kd) };
            }

            // Get the document content
            let document = if let Some(url) = remote_url {
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .build()
                    .map_err(|e| format!("HTTP client error: {}", e))?;
                let resp = client
                    .get(url)
                    .send()
                    .map_err(|e| format!("Fetch failed: {}", e))?;
                if !resp.status().is_success() {
                    eprintln!("HTTP error: {}", resp.status());
                    process::exit(1);
                }
                resp.text()
                    .map_err(|e| format!("Read body failed: {}", e))?
            } else if let Some(path) = file_path {
                std::fs::read_to_string(path).map_err(|e| format!("Read file failed: {}", e))?
            } else {
                eprintln!("Provide a file path or --remote <url>");
                process::exit(1);
            };

            // Try to load an existing agent (from config in cwd or env vars).
            // This gives access to the agent's own keys for verifying self-signed docs.
            // Fall back to an ephemeral agent if no config is available.
            let agent = if std::path::Path::new("./jacs.config.json").exists() {
                if let Err(e) = ensure_cli_private_key_password() {
                    eprintln!("Warning: Password bootstrap failed: {}", e);
                    eprintln!("{}", quickstart_password_bootstrap_help());
                }
                match SimpleAgent::load(None, None) {
                    Ok(a) => a,
                    Err(e) => {
                        let lower = e.to_string().to_lowercase();
                        if lower.contains("password")
                            || lower.contains("decrypt")
                            || lower.contains("private key")
                        {
                            eprintln!(
                                "Warning: Could not load local agent from ./jacs.config.json: {}",
                                e
                            );
                            eprintln!("{}", quickstart_password_bootstrap_help());
                        }
                        let (a, _) = SimpleAgent::ephemeral(Some("ed25519"))
                            .map_err(|e| format!("Failed to create verifier: {}", e))?;
                        a
                    }
                }
            } else {
                let (a, _) = SimpleAgent::ephemeral(Some("ed25519"))
                    .map_err(|e| format!("Failed to create verifier: {}", e))?;
                a
            };

            match agent.verify(&document) {
                Ok(r) => {
                    if json_output {
                        let out = json!({
                            "valid": r.valid,
                            "signerId": r.signer_id,
                            "timestamp": r.timestamp,
                        });
                        println!("{}", serde_json::to_string_pretty(&out).unwrap());
                    } else {
                        println!("Status:    {}", if r.valid { "VALID" } else { "INVALID" });
                        println!(
                            "Signer:    {}",
                            if r.signer_id.is_empty() {
                                "(unknown)"
                            } else {
                                &r.signer_id
                            }
                        );
                        if !r.timestamp.is_empty() {
                            println!("Signed at: {}", r.timestamp);
                        }
                    }
                    if !r.valid {
                        process::exit(1);
                    }
                }
                Err(e) => {
                    if json_output {
                        let out = json!({
                            "valid": false,
                            "error": e.to_string(),
                        });
                        println!("{}", serde_json::to_string_pretty(&out).unwrap());
                    } else {
                        eprintln!("Verification error: {}", e);
                    }
                    process::exit(1);
                }
            }
        }
        Some(("sign-text", sub)) => {
            handle_sign_text(sub);
        }
        Some(("verify-text", sub)) => {
            handle_verify_text(sub);
        }
        Some(("sign-image", sub)) => {
            handle_sign_image(sub);
        }
        Some(("verify-image", sub)) => {
            handle_verify_image(sub);
        }
        Some(("extract-media-signature", sub)) => {
            handle_extract_media_signature(sub);
        }
        Some(("convert", convert_matches)) => {
            use jacs::convert::{html_to_jacs, jacs_to_html, jacs_to_yaml, yaml_to_jacs};

            let target_format = convert_matches.get_one::<String>("to").unwrap();
            let source_format = convert_matches.get_one::<String>("from");
            let file_path = convert_matches.get_one::<String>("file").unwrap();
            let output_path = convert_matches.get_one::<String>("output");

            // Auto-detect source format from extension if not explicitly provided
            let is_stdin = file_path == "-";
            let detected_format = if let Some(fmt) = source_format {
                fmt.clone()
            } else if is_stdin {
                eprintln!(
                    "When reading from stdin (-f -), --from is required to specify the source format."
                );
                process::exit(1);
            } else {
                let ext = std::path::Path::new(file_path)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                match ext {
                    "json" => "json".to_string(),
                    "yaml" | "yml" => "yaml".to_string(),
                    "html" | "htm" => "html".to_string(),
                    _ => {
                        eprintln!(
                            "Cannot auto-detect format for extension '{}'. Use --from to specify.",
                            ext
                        );
                        process::exit(1);
                    }
                }
            };

            // Read input (from file or stdin)
            let input = if is_stdin {
                let mut buf = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                    .map_err(|e| format!("Failed to read from stdin: {}", e))?;
                buf
            } else {
                std::fs::read_to_string(file_path)
                    .map_err(|e| format!("Failed to read '{}': {}", file_path, e))?
            };

            // Convert
            let output = match (detected_format.as_str(), target_format.as_str()) {
                ("json", "yaml") => jacs_to_yaml(&input).map_err(|e| format!("{}", e))?,
                ("yaml", "json") => yaml_to_jacs(&input).map_err(|e| format!("{}", e))?,
                ("json", "html") => jacs_to_html(&input).map_err(|e| format!("{}", e))?,
                ("html", "json") => html_to_jacs(&input).map_err(|e| format!("{}", e))?,
                ("yaml", "html") => {
                    let json = yaml_to_jacs(&input).map_err(|e| format!("{}", e))?;
                    jacs_to_html(&json).map_err(|e| format!("{}", e))?
                }
                ("html", "yaml") => {
                    let json = html_to_jacs(&input).map_err(|e| format!("{}", e))?;
                    jacs_to_yaml(&json).map_err(|e| format!("{}", e))?
                }
                (src, dst) if src == dst => {
                    // Same format -- just pass through
                    input
                }
                (src, dst) => {
                    eprintln!("Unsupported conversion: {} -> {}", src, dst);
                    process::exit(1);
                }
            };

            // Write output
            if let Some(out_path) = output_path {
                std::fs::write(out_path, &output)
                    .map_err(|e| format!("Failed to write '{}': {}", out_path, e))?;
                eprintln!("Written to {}", out_path);
            } else {
                print!("{}", output);
            }
        }
        Some(("init", init_matches)) => {
            let auto_yes = *init_matches.get_one::<bool>("yes").unwrap_or(&false);
            println!("--- Running Config Creation ---");
            handle_config_create()?;
            println!("\n--- Running Agent Creation (with keys) ---");
            handle_agent_create_auto(None, true, auto_yes)?;
            println!("\n--- JACS Initialization Complete ---");
        }
        #[cfg(feature = "keychain")]
        Some(("keychain", keychain_matches)) => {
            use jacs::keystore::keychain;

            match keychain_matches.subcommand() {
                Some(("set", sub)) => {
                    let agent_id = sub.get_one::<String>("agent-id").unwrap();
                    let password = if let Some(pw) = sub.get_one::<String>("password") {
                        pw.clone()
                    } else {
                        eprintln!("Enter password to store in keychain:");
                        read_password().map_err(|e| format!("Failed to read password: {}", e))?
                    };
                    if password.trim().is_empty() {
                        eprintln!("Error: password cannot be empty.");
                        process::exit(1);
                    }
                    // Validate password strength before storing
                    if let Err(e) = jacs::crypt::aes_encrypt::check_password_strength(&password) {
                        eprintln!("Error: {}", e);
                        process::exit(1);
                    }
                    keychain::store_password(agent_id, &password)?;
                    eprintln!("Password stored in OS keychain for agent {}.", agent_id);
                }
                Some(("get", sub)) => {
                    let agent_id = sub.get_one::<String>("agent-id").unwrap();
                    match keychain::get_password(agent_id)? {
                        Some(pw) => println!("{}", pw),
                        None => {
                            eprintln!("No password found in OS keychain for agent {}.", agent_id);
                            process::exit(1);
                        }
                    }
                }
                Some(("delete", sub)) => {
                    let agent_id = sub.get_one::<String>("agent-id").unwrap();
                    keychain::delete_password(agent_id)?;
                    eprintln!("Password removed from OS keychain for agent {}.", agent_id);
                }
                Some(("status", sub)) => {
                    let agent_id = sub.get_one::<String>("agent-id").unwrap();
                    if keychain::is_available() {
                        match keychain::get_password(agent_id) {
                            Ok(Some(_)) => {
                                eprintln!("Keychain backend: available");
                                eprintln!("Agent: {}", agent_id);
                                eprintln!("Password: stored");
                            }
                            Ok(None) => {
                                eprintln!("Keychain backend: available");
                                eprintln!("Agent: {}", agent_id);
                                eprintln!("Password: not stored");
                            }
                            Err(e) => {
                                eprintln!("Keychain backend: error ({})", e);
                            }
                        }
                    } else {
                        eprintln!("Keychain backend: not available (feature disabled)");
                    }
                }
                _ => {
                    eprintln!("Unknown keychain subcommand. Use: set, get, delete, status");
                    process::exit(1);
                }
            }
        }
        _ => {
            // This branch should ideally be unreachable after adding arg_required_else_help(true)
            eprintln!("Invalid command or no subcommand provided. Use --help for usage.");
            process::exit(1); // Exit with error if this branch is reached
        }
    }

    Ok(())
}

// =============================================================================
// Inline-text + media verb handlers (Task 08).
// =============================================================================

/// Load an agent for sign operations: prefer the local config; fall back to a
/// fresh ephemeral agent if none exists. Mirrors the resolution logic of the
/// top-level `verify` handler so behaviour is consistent.
fn load_or_ephemeral_signer() -> jacs::simple::SimpleAgent {
    use jacs::simple::SimpleAgent;
    if std::path::Path::new("./jacs.config.json").exists() {
        if let Err(e) = ensure_cli_private_key_password() {
            eprintln!("Warning: Password bootstrap failed: {}", e);
            eprintln!("{}", quickstart_password_bootstrap_help());
        }
        match SimpleAgent::load(None, None) {
            Ok(a) => a,
            Err(e) => {
                let lower = e.to_string().to_lowercase();
                if lower.contains("password")
                    || lower.contains("decrypt")
                    || lower.contains("private key")
                {
                    eprintln!(
                        "Warning: Could not load local agent from ./jacs.config.json: {}",
                        wrap_quickstart_error_with_password_help("loading agent", &e)
                    );
                }
                let (a, _) = SimpleAgent::ephemeral(Some("ed25519")).unwrap_or_else(|err| {
                    eprintln!("Failed to create ephemeral agent: {}", err);
                    process::exit(1);
                });
                a
            }
        }
    } else {
        let (a, _) = SimpleAgent::ephemeral(Some("ed25519")).unwrap_or_else(|err| {
            eprintln!("Failed to create ephemeral agent: {}", err);
            process::exit(1);
        });
        a
    }
}

fn handle_sign_text(sub: &clap::ArgMatches) {
    use jacs::simple::advanced::sign_text_file;
    use jacs::simple::types::SignTextOptions;
    use serde_json::json;

    let file_path = sub.get_one::<String>("file").expect("file required");
    let no_backup = *sub.get_one::<bool>("no-backup").unwrap_or(&false);
    let json_output = *sub.get_one::<bool>("json").unwrap_or(&false);

    // PRD §4.1.1: refuse to sign content that already contains a column-zero
    // signature marker pair whose YAML body does not deserialize as a
    // well-formed `SignatureBlockYaml`. This catches pre-poisoned inputs
    // (bogus YAML, partial blocks). Documented workaround: indent the marker
    // (it stays in code blocks) so the column-zero scan misses it.
    if let Ok(content) = std::fs::read_to_string(file_path)
        && let Some(offset) = column_zero_marker_collision(&content)
    {
        eprintln!(
            "refusing to sign {}: input contains a column-zero JACS signature marker with a bogus body at byte offset {} (PRD §4.1.1). \
             If you are writing about JACS, indent the marker by at least one space so it stops matching column-zero.",
            file_path, offset
        );
        process::exit(1);
    }

    let agent = load_or_ephemeral_signer();
    let opts = SignTextOptions {
        backup: !no_backup,
        ..Default::default()
    };

    match sign_text_file(&agent, file_path, opts) {
        Ok(outcome) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "path": outcome.path,
                        "signers_added": outcome.signers_added,
                        "backup_path": outcome.backup_path,
                    }))
                    .unwrap()
                );
            } else if outcome.signers_added > 0 {
                println!("Signed: {}", outcome.path);
                if let Some(bak) = &outcome.backup_path {
                    println!("Backup: {}", bak);
                }
            } else {
                println!(
                    "No new signature: {} already signed by this agent",
                    outcome.path
                );
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("refusing to sign") || msg.contains("marker") {
                eprintln!("refusing to sign {}: {}", file_path, msg);
            } else {
                eprintln!("sign-text error: {}", msg);
            }
            process::exit(1);
        }
    }
}

/// PRD §4.1.1: scan a text body for column-zero `-----BEGIN JACS SIGNATURE-----`
/// markers paired with `-----END JACS SIGNATURE-----` markers whose body
/// does not look like a `jacs::inline::SignatureBlockYaml`. Returns the
/// byte offset of the first such offending block, or None if none found.
///
/// We check for required field presence (`signer:` and either
/// `signature_block_version:` or `signatureBlockVersion:`) without doing
/// a full YAML deserialize — we don't want to pull serde_yaml_ng into
/// jacs-cli just for this check. A block that's missing these required
/// markers is treated as bogus.
fn column_zero_marker_collision(content: &str) -> Option<usize> {
    const BEGIN: &str = "-----BEGIN JACS SIGNATURE-----";
    const END: &str = "-----END JACS SIGNATURE-----";

    let mut search_from = 0usize;
    while search_from < content.len() {
        // Find the next BEGIN occurrence at column zero (i.e. either at
        // index 0 or immediately after an LF).
        let begin_idx = match content[search_from..].find(BEGIN) {
            Some(rel) => search_from + rel,
            None => return None,
        };
        let at_column_zero =
            begin_idx == 0 || content.as_bytes().get(begin_idx.wrapping_sub(1)) == Some(&b'\n');
        if !at_column_zero {
            search_from = begin_idx + BEGIN.len();
            continue;
        }
        let after_begin = begin_idx + BEGIN.len();
        // Expect a trailing newline.
        let body_start = match content[after_begin..].find('\n') {
            Some(n) => after_begin + n + 1,
            None => return None, // Missing newline — the lib will reject this on its own.
        };
        // Find the matching END marker.
        let end_offset = match content[body_start..].find(END) {
            Some(n) => body_start + n,
            None => return None, // No END — the lib will reject.
        };
        let body = content[body_start..end_offset].trim();
        // Required-field heuristic. A real SignatureBlockYaml always has
        // both `signer` and `signature_block_version` (or its camelCase
        // alias). Reject anything missing both anchors.
        let has_signer = body.lines().any(|line| {
            let t = line.trim_start();
            t.starts_with("signer:") || t.starts_with("\"signer\":")
        });
        let has_version = body.lines().any(|line| {
            let t = line.trim_start();
            t.starts_with("signature_block_version:")
                || t.starts_with("signatureBlockVersion:")
                || t.starts_with("\"signature_block_version\":")
                || t.starts_with("\"signatureBlockVersion\":")
        });
        if !has_signer || !has_version {
            return Some(begin_idx);
        }
        // Block looks structurally plausible; the lib will catch deeper
        // crypt/signer issues. Continue scanning past END.
        search_from = end_offset + END.len();
    }
    None
}

fn handle_verify_text(sub: &clap::ArgMatches) {
    use jacs::inline::{SignatureStatus, VerifyOptions, VerifyTextResult};
    use jacs::simple::advanced::verify_text_file;
    use serde_json::json;
    use std::path::PathBuf;

    let file_path = sub.get_one::<String>("file").expect("file required");
    let key_dir = sub.get_one::<String>("key-dir").map(PathBuf::from);
    let json_output = *sub.get_one::<bool>("json").unwrap_or(&false);
    let strict = *sub.get_one::<bool>("strict").unwrap_or(&false);

    let agent = load_or_ephemeral_signer();
    let opts = VerifyOptions { strict, key_dir };

    match verify_text_file(&agent, file_path, opts) {
        Ok(VerifyTextResult::Signed { signatures }) => {
            let any_failed = signatures
                .iter()
                .any(|s| s.status != SignatureStatus::Valid);
            if json_output {
                emit_verify_text_signed_json(&signatures);
            } else {
                for entry in &signatures {
                    let status = match &entry.status {
                        SignatureStatus::Valid => "VALID".to_string(),
                        SignatureStatus::InvalidSignature => "INVALID".to_string(),
                        SignatureStatus::HashMismatch => "HASH MISMATCH".to_string(),
                        SignatureStatus::KeyNotFound => "KEY NOT FOUND".to_string(),
                        SignatureStatus::UnsupportedAlgorithm => {
                            "UNSUPPORTED ALGORITHM".to_string()
                        }
                        SignatureStatus::Malformed(s) => format!("MALFORMED ({})", s),
                    };
                    println!("Signer:    {}", entry.signer_id);
                    println!("Algorithm: {}", entry.algorithm);
                    println!("Status:    {}", status);
                    if !entry.timestamp.is_empty() {
                        println!("Signed at: {}", entry.timestamp);
                    }
                }
            }
            if any_failed {
                process::exit(1);
            }
        }
        Ok(VerifyTextResult::MissingSignature) => {
            // Permissive only: strict path returns Err.
            eprintln!("no JACS signature found in {}", file_path);
            if json_output {
                println!("{}", json!({"status": "missing_signature"}));
            }
            process::exit(2);
        }
        Ok(VerifyTextResult::Malformed(detail)) => {
            if json_output {
                println!("{}", json!({"status": "malformed", "error": detail}));
            } else {
                eprintln!("malformed signature block in {}: {}", file_path, detail);
            }
            process::exit(1);
        }
        Err(jacs::error::JacsError::MissingSignature(p)) => {
            // Strict mode: missing-signature is a hard failure (exit 1).
            let msg = format!("no JACS signature found in {}", p);
            if json_output {
                eprintln!(
                    "{}",
                    json!({"error": msg, "error_kind": "MissingSignature"})
                );
            } else {
                eprintln!("{}", msg);
            }
            process::exit(1);
        }
        Err(e) => {
            if json_output {
                eprintln!(
                    "{}",
                    json!({"error": e.to_string(), "error_kind": "Generic"})
                );
            } else {
                eprintln!("verify-text error: {}", e);
            }
            process::exit(1);
        }
    }
}

fn emit_verify_text_signed_json(signatures: &[jacs::inline::SignatureEntry]) {
    use jacs::inline::SignatureStatus;
    use serde_json::json;
    let entries: Vec<serde_json::Value> = signatures
        .iter()
        .map(|e| {
            let (status_str, error) = match &e.status {
                SignatureStatus::Valid => ("valid", None),
                SignatureStatus::InvalidSignature => ("invalid_signature", None),
                SignatureStatus::HashMismatch => ("hash_mismatch", None),
                SignatureStatus::KeyNotFound => ("key_not_found", None),
                SignatureStatus::UnsupportedAlgorithm => ("unsupported_algorithm", None),
                SignatureStatus::Malformed(s) => ("malformed", Some(s.clone())),
            };
            let mut o = json!({
                "signer_id": e.signer_id,
                "algorithm": e.algorithm,
                "timestamp": e.timestamp,
                "status": status_str,
            });
            if let Some(err) = error {
                o["error"] = serde_json::Value::String(err);
            }
            o
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"status": "signed", "signatures": entries})).unwrap()
    );
}

fn handle_sign_image(sub: &clap::ArgMatches) {
    use jacs::simple::advanced::sign_image;
    use jacs::simple::types::SignImageOptions;
    use serde_json::json;

    let in_path = sub.get_one::<String>("input").expect("input required");
    let out_path = sub.get_one::<String>("out").expect("out required");
    let robust = *sub.get_one::<bool>("robust").unwrap_or(&false);
    let format_hint = sub.get_one::<String>("format").cloned();
    let refuse_overwrite = *sub.get_one::<bool>("refuse-overwrite").unwrap_or(&false);
    let json_output = *sub.get_one::<bool>("json").unwrap_or(&false);

    let agent = load_or_ephemeral_signer();
    let opts = SignImageOptions {
        robust,
        format_hint,
        refuse_overwrite,
        ..Default::default()
    };

    match sign_image(&agent, in_path, out_path, opts) {
        Ok(signed) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "out_path": signed.out_path,
                        "signer_id": signed.signer_id,
                        "format": signed.format,
                        "robust": signed.robust,
                        "backup_path": signed.backup_path,
                    }))
                    .unwrap()
                );
            } else {
                println!("Signed: {}", signed.out_path);
                println!("Signer: {}", signed.signer_id);
                println!("Format: {}", signed.format);
                if let Some(bak) = &signed.backup_path {
                    println!("Backup: {}", bak);
                }
            }
        }
        Err(e) => {
            eprintln!("sign-image error: {}", e);
            process::exit(1);
        }
    }
}

fn handle_verify_image(sub: &clap::ArgMatches) {
    use jacs::inline::VerifyOptions;
    use jacs::simple::advanced::verify_image;
    use jacs::simple::types::{MediaVerifyStatus, VerifyImageOptions};
    use serde_json::json;
    use std::path::PathBuf;

    let file_path = sub.get_one::<String>("file").expect("file required");
    let key_dir = sub.get_one::<String>("key-dir").map(PathBuf::from);
    let json_output = *sub.get_one::<bool>("json").unwrap_or(&false);
    let strict = *sub.get_one::<bool>("strict").unwrap_or(&false);
    let scan_robust = *sub.get_one::<bool>("robust").unwrap_or(&false);

    let agent = load_or_ephemeral_signer();
    let opts = VerifyImageOptions {
        base: VerifyOptions { strict, key_dir },
        scan_robust,
    };

    match verify_image(&agent, file_path, opts) {
        Ok(result) => match result.status {
            MediaVerifyStatus::Valid => {
                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "status": "valid",
                            "signer_id": result.signer_id,
                            "algorithm": result.algorithm,
                            "format": result.format,
                            "embedding_channels": result.embedding_channels,
                        }))
                        .unwrap()
                    );
                } else {
                    println!("Status:    VALID");
                    if let Some(s) = result.signer_id {
                        println!("Signer:    {}", s);
                    }
                    if let Some(a) = result.algorithm {
                        println!("Algorithm: {}", a);
                    }
                }
            }
            MediaVerifyStatus::MissingSignature => {
                eprintln!("no JACS signature found in {}", file_path);
                if json_output {
                    println!("{}", json!({"status": "missing_signature"}));
                }
                process::exit(2);
            }
            MediaVerifyStatus::Malformed(detail) => {
                if json_output {
                    println!("{}", json!({"status": "malformed", "error": detail}));
                } else {
                    eprintln!("malformed image signature in {}: {}", file_path, detail);
                }
                process::exit(1);
            }
            other => {
                let status_str = match &other {
                    MediaVerifyStatus::InvalidSignature => "invalid_signature",
                    MediaVerifyStatus::HashMismatch => "hash_mismatch",
                    MediaVerifyStatus::KeyNotFound => "key_not_found",
                    MediaVerifyStatus::UnsupportedFormat => "unsupported_format",
                    _ => "invalid_signature",
                };
                if json_output {
                    println!(
                        "{}",
                        json!({
                            "status": status_str,
                            "signer_id": result.signer_id,
                            "format": result.format,
                        })
                    );
                } else {
                    eprintln!("Status: {}", status_str.replace('_', " ").to_uppercase());
                }
                process::exit(1);
            }
        },
        Err(jacs::error::JacsError::MissingSignature(p)) => {
            let msg = format!("no JACS signature found in {}", p);
            if json_output {
                eprintln!(
                    "{}",
                    json!({"error": msg, "error_kind": "MissingSignature"})
                );
            } else {
                eprintln!("{}", msg);
            }
            process::exit(1);
        }
        Err(e) => {
            if json_output {
                eprintln!(
                    "{}",
                    json!({"error": e.to_string(), "error_kind": "Generic"})
                );
            } else {
                eprintln!("verify-image error: {}", e);
            }
            process::exit(1);
        }
    }
}

fn handle_extract_media_signature(sub: &clap::ArgMatches) {
    use jacs::simple::advanced::{
        extract_media_signature_raw_with_options, extract_media_signature_with_options,
    };
    use jacs::simple::types::ExtractMediaOptions;
    use std::io::Write;

    let file_path = sub.get_one::<String>("file").expect("file required");
    let raw_payload = *sub.get_one::<bool>("raw-payload").unwrap_or(&false);
    // R-011: opt-in LSB scan fallback (mirrors verify-image --robust).
    let scan_robust = *sub.get_one::<bool>("robust").unwrap_or(&false);
    let opts = ExtractMediaOptions { scan_robust };

    let result = if raw_payload {
        extract_media_signature_raw_with_options(file_path, opts)
    } else {
        extract_media_signature_with_options(file_path, opts)
    };
    match result {
        Ok(Some(payload)) => {
            // Write directly to stdout without a trailing newline so that
            // base64url output round-trips byte-for-byte; tests for decoded
            // JSON tolerate either with or without trailing newline.
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            let _ = handle.write_all(payload.as_bytes());
        }
        Ok(None) => {
            // No signature present — exit 2, empty stdout, message on stderr.
            eprintln!("no JACS signature found in {}", file_path);
            process::exit(2);
        }
        Err(e) => {
            eprintln!("extract-media-signature error: {}", e);
            process::exit(1);
        }
    }
}
