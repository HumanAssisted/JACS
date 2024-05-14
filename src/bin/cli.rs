use chrono::DateTime;
use chrono::Local;
use clap::{value_parser, Arg, ArgAction, Command};
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::Agent;
use jacs::agent::AGENT_AGREEMENT_FIELDNAME;
use jacs::config::{set_env_vars, Config};
use jacs::create_minimal_blank_agent;
use jacs::create_task;
use jacs::load_agent;
use jacs::shared::document_add_agreement;
use jacs::shared::document_check_agreement;
use jacs::shared::document_create;
use jacs::shared::document_load_and_save;
use jacs::shared::document_sign_agreement;
use jacs::shared::get_file_list;

use rpassword::read_password;
use serde_json::Value;
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

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

fn main() {
    set_env_vars();
    let matches = Command::new("jacs")
        .subcommand(
            Command::new("config")
                .about(" work with JACS configuration")
                .subcommand(
                    Command::new("create")
                        .about(" create a config file")
                )
                .subcommand(
                    Command::new("read")
                    .about("read configuration and display to screen. This includes both the config file and the env variables.")
                ),
        )
        .subcommand(
            Command::new("agent")
                .about(" work with a JACS agent")
                .subcommand(
                    Command::new("create")
                        .about(" create an agent")
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .help("Name of the json file with agent schema and jacsAgentType")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("create-keys")
                                .long("create-keys")
                                .required(true)
                                .help("Create keys or not if they already exist. Configure key type in jacs.config.json")
                                .value_parser(value_parser!(bool)),
                        ),
                )
                .subcommand(
                    Command::new("verify")
                    .about(" verify an agent")
                    .arg(
                        Arg::new("agent-file")
                            .short('a')
                            .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                            .value_parser(value_parser!(String)),
                    ),
                ),
        )

        .subcommand(
            Command::new("task")
            .about(" work with a JACS  Agent task")
            .subcommand(
                Command::new("create")
                    .about(" create a new JACS Task file, either by embedding or parsing a document")
                    .arg(
                        Arg::new("agent-file")
                            .short('a')
                            .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("filename")
                            .short('f')
                            .help("Path to input file. Must be JSON")
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("name")
                            .short('n')
                            .required(true)
                            .help("name of task")
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("description")
                            .short('d')
                            .required(true)
                            .help("description of task")
                            .value_parser(value_parser!(String)),
                    )
                )
            )

        .subcommand(
            Command::new("document")
                .about(" work with a general JACS document")
                .subcommand(
                    Command::new("create")
                        .about(" create a new JACS file, either by embedding or parsing a document")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .help("Path to input file. Must be JSON")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .help("Output filename. ")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-save")
                                .long("no-save")
                                .short('n')
                                .help("Instead of saving files, print to stdout")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("attach")
                                .help("Path to file or directory for file attachments")
                                .long("attach")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("embed")
                                .short('e')
                                .help("Embed documents or keep the documents external")
                                .long("embed")
                                .value_parser(value_parser!(bool)),
                        ),
                )
                .subcommand(
                    Command::new("update")
                        .about("create a new version of document. requires both the original JACS file and the modified jacs metadata")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("new")
                                .short('n')
                                .required(true)
                                .help("Path to new version of document.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .required(true)
                                .help("Path to original document.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .help("Output filename. Filenames will always end with \"jacs.json\"")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-save")
                                .long("no-save")
                                .short('n')
                                .help("Instead of saving files, print to stdout")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("attach")
                                .help("Path to file or directory for file attachments")
                                .long("attach")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("embed")
                                .short('e')
                                .help("Embed documents or keep the documents external")
                                .long("embed")
                                .value_parser(value_parser!(bool)),
                        )
                        ,
                )
                .subcommand(
                    Command::new("check-agreement")
                        .about("given a document, provide alist of agents that should sign document")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .required(true)
                                .help("Path to original document.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        )

                )
                .subcommand(
                    Command::new("create-agreement")
                        .about("given a document, provide alist of agents that should sign document")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .required(true)
                                .help("Path to original document.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                                Arg::new("agentids")
                                .short('i')
                                .long("agentids")
                                .value_name("VALUES")
                                .help("Comma-separated list of agent ids")
                                .value_delimiter(',')
                                .required(true)
                                .action(clap::ArgAction::Set),
                            )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .help("Output filename. Filenames will always end with \"jacs.json\"")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-save")
                                .long("no-save")
                                .short('n')
                                .help("Instead of saving files, print to stdout")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        )

                ).subcommand(
                    Command::new("sign-agreement")
                        .about("given a document, sign the agreement section")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .required(true)
                                .help("Path to original document.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .help("Output filename. Filenames will always end with \"jacs.json\"")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-save")
                                .long("no-save")
                                .short('n')
                                .help("Instead of saving files, print to stdout")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        )

                )
                .subcommand(
                    Command::new("verify")
                        .about(" verify a documents hash, siginatures, and schema")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .help("Path to input file. Must be JSON")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to validate")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        ),
                )
                .subcommand(
                    Command::new("extract")
                        .about(" given  documents, extract embedded contents if any")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file. Otherwise use config jacs_agent_id_and_version")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .help("Path to input file. Must be JSON")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("directory")
                                .short('d')
                                .help("Path to directory of files. Files should end with .json")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("verbose")
                                .short('v')
                                .long("verbose")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to validate")
                                .long("schema")
                                .value_parser(value_parser!(String)),
                        ),
                )
        )
        .get_matches();

    match matches.subcommand() {
        Some(("config", agent_matches)) => match agent_matches.subcommand() {
            Some(("create", _create_matches)) => {
                println!("Welcome to the JACS Config Generator!");

                println!(
                    "Enter the path to the agent file if it already exists (leave empty to skip):"
                );
                let mut agent_filename = String::new();
                io::stdin().read_line(&mut agent_filename).unwrap();
                agent_filename = agent_filename.trim().to_string();

                let jacs_agent_id_and_version = if !agent_filename.is_empty() {
                    let agent_path = PathBuf::from(agent_filename);
                    if agent_path.exists() {
                        match fs::read_to_string(&agent_path) {
                            Ok(agent_content) => {
                                match serde_json::from_str::<Value>(&agent_content) {
                                    Ok(agent_json) => {
                                        let jacs_id = agent_json["jacsId"].as_str().unwrap_or("");
                                        let jacs_version =
                                            agent_json["jacsVersion"].as_str().unwrap_or("");
                                        format!("{}:{}", jacs_id, jacs_version)
                                    }
                                    Err(e) => {
                                        println!("Error parsing JSON: {}", e);
                                        String::new()
                                    }
                                }
                            }
                            Err(e) => {
                                println!("Failed to read agent file: {}", e);
                                String::new()
                            }
                        }
                    } else {
                        println!("Agent file not found. Skipping...");
                        String::new()
                    }
                } else {
                    String::new()
                };
                let jacs_agent_private_key_filename =
                    request_string("Enter the private key filename:", "jacs.private.pem.enc");
                let jacs_agent_public_key_filename =
                    request_string("Enter the public key filename:", "jacs.public.pem");
                let jacs_agent_key_algorithm = request_string(
                    "Enter the agent key algorithm (ring-Ed25519, pq-dilithium, or RSA-PSS)",
                    "RSA-PSS",
                );
                //let jacs_private_key_password = request_string("Enter the private key password for encrypting on disk (don't use in product. set env JACS_PRIVATE_KEY_PASSWORD:", "");

                println!("Please enter your password:");
                let jacs_private_key_password = match read_password() {
                    Ok(password) => {
                        // If you want to use the password here or later, it's now stored in `jacs_private_key_password`
                        password // No need for return; just pass the password directly
                    }
                    Err(e) => {
                        eprintln!("Error reading password: {}", e);
                        std::process::exit(1); // Exit if there's an error
                    }
                };

                let jacs_use_filesystem =
                    request_string("Use filesystem. If false, will print to std:io", "true");
                let jacs_use_security =
                    request_string("Use experimental security features", "false");
                let jacs_data_directory = request_string("Directory for data storage", "./jacs");
                let jacs_key_directory =
                    request_string("Directory to load keys from", "./jacs/keys");

                let config = Config::new(
                    "https://hai.ai/schemas/jacs.config.schema.json".to_string(),
                    Some(jacs_use_filesystem),
                    Some(jacs_use_security),
                    Some(jacs_data_directory),
                    Some(jacs_key_directory),
                    Some(jacs_agent_private_key_filename),
                    Some(jacs_agent_public_key_filename),
                    Some(jacs_agent_key_algorithm),
                    Some("v1".to_string()),
                    Some("v1".to_string()),
                    Some("v1".to_string()),
                    Some(jacs_private_key_password),
                    Some(jacs_agent_id_and_version),
                );

                let serialized = serde_json::to_string_pretty(&config).unwrap();

                let config_path = "jacs.config.json";
                if fs::metadata(config_path).is_ok() {
                    let now: DateTime<Local> = Local::now();
                    let backup_path =
                        format!("{}-backup-jacs.config.json", now.format("%Y%m%d%H%M%S"));
                    fs::rename(config_path, backup_path.clone()).unwrap();
                    println!("Backed up existing jacs.config.json to {}", backup_path);
                }

                let mut file = fs::File::create(config_path).unwrap();
                file.write_all(serialized.as_bytes()).unwrap();

                println!("jacs.config.json file generated successfully!");
            }
            Some(("read", _verify_matches)) => {
                // agent is loaded because of    schema.validate_config(&config).expect("config validation");
                // let _ = load_agent_by_id();
                let configs = set_env_vars();
                println!("{}", configs);
            }
            _ => println!("please enter subcommand see jacs agent --help"),
        },
        Some(("agent", agent_matches)) => match agent_matches.subcommand() {
            Some(("create", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let _create_keys = *create_matches.get_one::<bool>("create-keys").unwrap();

                let agentstring = match filename {
                    Some(filename) => {
                        fs::read_to_string(filename).expect("Failed to read agent file")
                    }
                    _ => create_minimal_blank_agent("ai".to_string()).unwrap(),
                };

                let mut agent = Agent::new(
                    &"v1".to_string(),
                    &"v1".to_string(),
                    "header_schema_url_placeholder".to_string(),
                    "document_schema_url_placeholder".to_string(),
                )
                .expect("Failed to create agent");
                agent
                    .create_agent_and_load(&agentstring)
                    .expect("Failed to create and load agent from provided JSON data");
                println!("Agent created!");
            }
            Some(("verify", verify_matches)) => {
                let agentfile = verify_matches.get_one::<String>("agent-file");
                let agent: Agent = load_agent(agentfile.cloned()).expect("Failed to load agent");

                agent
                    .verify_self_signature()
                    .expect("Failed to verify agent signature");
                println!(
                    "Agent {} signature verified OK.",
                    agent
                        .get_lookup_id()
                        .expect("Failed to get agent lookup ID")
                );
            }
            _ => println!("please enter subcommand see jacs agent --help"),
        },

        Some(("task", task_matches)) => match task_matches.subcommand() {
            Some(("create", create_matches)) => {
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent =
                    load_agent(agentfile.cloned()).expect("Failed to load agent");
                let name = create_matches
                    .get_one::<String>("name")
                    .expect("Task name required");
                let description = create_matches
                    .get_one::<String>("description")
                    .expect("Task description required");
                println!(
                    "{}",
                    create_task(&mut agent, name.to_string(), description.to_string()).unwrap()
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
                let agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches.get_one::<String>("attach");
                let embed: Option<bool> = create_matches.get_one::<bool>("embed").copied();

                let mut agent: Agent =
                    load_agent(agentfile.cloned()).expect("Failed to load agent");

                // let attachment_links = agent.parse_attachement_arg(attachments);

                if !outputfilename.is_none() && !directory.is_none() {
                    eprintln!("Error: if there is a directory you can't name the file the same for multiple files.");
                    std::process::exit(1);
                }

                // check if output filename exists and that if so it's for one file

                let files: Vec<String> = set_file_list(filename, directory, attachments);

                // iterate over filenames
                for file in &files {
                    let document_string: String = if filename.is_none() && directory.is_none() {
                        "{}".to_string()
                    } else {
                        fs::read_to_string(file).expect("document file loading")
                    };
                    let path = Path::new(file);
                    let loading_filename = path.file_name().unwrap().to_str().unwrap();
                    let _loading_filename_string = loading_filename.to_string();

                    let result = document_create(
                        &mut agent,
                        &document_string,
                        schema.cloned(),
                        outputfilename.cloned(),
                        no_save,
                        attachments,
                        embed,
                    )
                    .expect("Failed to create document");
                    if no_save {
                        println!("{}", result);
                    }
                } // end iteration
            }
            // TODO copy for sharing
            // Some(("copy", create_matches)) => {
            Some(("update", create_matches)) => {
                let new_filename = create_matches.get_one::<String>("new").unwrap();
                let original_filename = create_matches.get_one::<String>("filename").unwrap();
                let outputfilename = create_matches.get_one::<String>("output");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches.get_one::<String>("attach");
                let embed = create_matches.get_one::<bool>("embed");

                let mut agent: Agent =
                    load_agent(agentfile.cloned()).expect("Failed to load agent");

                let attachment_links = agent.parse_attachement_arg(attachments);

                if let Some(schema_file) = schema {
                    // schemastring =
                    fs::read_to_string(schema_file).expect("Failed to load schema file");

                    let _schemas = [schema_file.clone()];
                    match agent.load_custom_schemas() {
                        Ok(_) => (),
                        Err(e) => {
                            eprintln!("Failed to load custom schemas: {}", e);
                            std::process::exit(1);
                        }
                    }
                }

                let new_document_string =
                    fs::read_to_string(new_filename).expect("modified document file loading");
                let original_document_string =
                    fs::read_to_string(original_filename).expect("original document file loading");
                let original_doc = agent
                    .load_document(&original_document_string)
                    .expect("document parse of original");
                let original_doc_key = original_doc.getkey();
                let updated_document = agent
                    .update_document(
                        &original_doc_key,
                        &new_document_string,
                        attachment_links.clone(),
                        embed.copied(),
                    )
                    .expect("update document");

                let path = Path::new(new_filename);
                let loading_filename = path.file_name().unwrap().to_str().unwrap();
                let loading_filename_string = loading_filename.to_string();

                let new_document_key = updated_document.getkey();
                // let document_key_string = new_document_key.to_string();

                let intermediate_filename = match outputfilename {
                    Some(filename) => filename,
                    None => &loading_filename_string,
                };

                if let Some(schema_file) = schema {
                    //let document_ref = agent.get_document(&document_key).unwrap();

                    let validate_result = agent.validate_document_with_custom_schema(
                        &schema_file,
                        &updated_document.getvalue(),
                    );
                    match validate_result {
                        Ok(_doc) => {
                            println!("document specialised schema {} validated", new_document_key);
                        }
                        Err(e) => {
                            eprintln!(
                                "document specialised schema {} validation failed {}",
                                new_document_key, e
                            );
                        }
                    }
                }

                if no_save {
                    println!("{}", new_document_key.to_string());
                } else {
                    agent
                        .save_document(
                            &new_document_key,
                            format!("{}", intermediate_filename).into(),
                            None,
                            None,
                        )
                        .expect("save document");
                    println!("created doc {}", new_document_key.to_string());
                }
            }
            Some(("sign-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent =
                    load_agent(agentfile.cloned()).expect("Failed to load agent");
                let schema = create_matches.get_one::<String>("schema");
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);

                let files: Vec<String> = set_file_list(filename, directory, None);

                for file in &files {
                    let document_string = fs::read_to_string(file).expect("document file loading ");
                    let result = document_sign_agreement(
                        &mut agent,
                        &document_string,
                        schema.cloned(),
                        None,
                        None,
                        None,
                        no_save,
                        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
                    )
                    .expect("Failed to sign agreement");
                    println!("{}", result);
                }
            }
            Some(("check-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent =
                    load_agent(agentfile.cloned()).expect("Failed to load agent");
                let schema = create_matches.get_one::<String>("schema");

                let files: Vec<String> = set_file_list(filename, directory, None);

                for file in &files {
                    let document_string = fs::read_to_string(file).expect("document file loading ");
                    let result = document_check_agreement(
                        &mut agent,
                        &document_string,
                        schema.cloned(),
                        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
                    )
                    .expect("Failed to check agreement");
                    println!("{}", result);
                }
            }
            Some(("create-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent =
                    load_agent(agentfile.cloned()).expect("Failed to load agent");
                let schema = create_matches.get_one::<String>("schema");
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentids: Vec<String> = matches
                    .get_many::<String>("agentids")
                    .unwrap_or_default()
                    .map(|s| s.to_string())
                    .collect();

                let files: Vec<String> = set_file_list(filename, directory, None);

                for file in &files {
                    let document_string = fs::read_to_string(file).expect("document file loading ");
                    let result = document_add_agreement(
                        &mut agent,
                        &document_string,
                        agentids.clone(),
                        schema.cloned(),
                        None,
                        None,
                        None,
                        None,
                        None,
                        no_save,
                        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
                    )
                    .expect("Failed to create agreement");
                    println!("{}", result);
                }
            }

            Some(("verify", verify_matches)) => {
                let filename = verify_matches.get_one::<String>("filename");
                let directory = verify_matches.get_one::<String>("directory");
                let _verbose = *verify_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = verify_matches.get_one::<String>("agent-file");
                let mut agent: Agent =
                    load_agent(agentfile.cloned()).expect("Failed to load agent");
                let schema = verify_matches.get_one::<String>("schema");
                let files: Vec<String> = set_file_list(filename, directory, None);

                for file in &files {
                    let load_only = true;
                    let document_string = fs::read_to_string(file).expect("document file loading ");
                    let result = document_load_and_save(
                        &mut agent,
                        &document_string,
                        schema.cloned(),
                        None,
                        None,
                        None,
                        load_only,
                    )
                    .expect("Failed to verify document");
                    println!("{}", result);
                }
            }

            Some(("extract", extract_matches)) => {
                let filename = extract_matches.get_one::<String>("filename");
                let directory = extract_matches.get_one::<String>("directory");
                let _verbose = *extract_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = extract_matches.get_one::<String>("agent-file");
                let mut agent: Agent =
                    load_agent(agentfile.cloned()).expect("Failed to load agent");
                let schema = extract_matches.get_one::<String>("schema");
                let files: Vec<String> = set_file_list(filename, directory, None);
                // let mut schemastring: String = "".to_string();
                // extract the contents but do not save
                let load_only = false;
                for file in &files {
                    let document_string = fs::read_to_string(file).expect("document file loading ");
                    let result = document_load_and_save(
                        &mut agent,
                        &document_string,
                        schema.cloned(),
                        None,
                        Some(true),
                        Some(true),
                        load_only,
                    )
                    .expect("Failed to extract document");
                    println!("{}", result);
                }
            }

            _ => println!("please enter subcommand see jacs document --help"),
        },
        _ => println!("please enter command see jacs --help"),
    }
}

fn set_file_list(
    filename: Option<&String>,
    directory: Option<&String>,
    attachments: Option<&String>,
) -> Vec<String> {
    let mut files: Vec<String> = Vec::new();
    if filename.is_none() && directory.is_none() && attachments.is_none() {
        eprintln!(
            "Error: You must specify either a filename or a directory or create from attachments."
        );
        std::process::exit(1);
    } else if filename.is_none() && directory.is_none() {
        files.push("no filepath given".to_string()); // hack to get the iterator to open
    } else if let Some(file) = filename {
        files = get_file_list(file.to_string()).expect("Failed to get file list");
    } else if let Some(dir) = directory {
        // Traverse the directory and store filenames ending with .json
        files = get_file_list(dir.to_string()).expect("Failed to get file list from directory");
    }
    return files;
}
