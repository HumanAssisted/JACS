use chrono::DateTime;
use chrono::Local;
use clap::{value_parser, Arg, ArgAction, Command};
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::Agent;
use jacs::config::{set_env_vars, Config};
use jacs::crypt::KeyManager;
use regex::Regex;
use serde_json::Value;
use std::env;
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

fn get_agent() -> Agent {
    Agent::new(
        &env::var("JACS_AGENT_SCHEMA_VERSION").unwrap(),
        &env::var("JACS_HEADER_SCHEMA_VERSION").unwrap(),
        &env::var("JACS_SIGNATURE_SCHEMA_VERSION").unwrap(),
    )
    .expect("Failed to init Agent")
}

fn load_agent(filepath: String) -> Agent {
    let mut agent = get_agent();
    let agentstring = fs::read_to_string(filepath.clone()).expect("agent file loading");
    let _ = agent.load(&agentstring);
    agent
}

fn load_agent_by_id() -> Agent {
    let mut agent = get_agent();
    let _ = agent.load_by_id(None, None);
    agent
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
                                .required(true)
                                 .help("Name of the file")
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
            Command::new("document")
                .about(" work with a JACS document")
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
                                .help("Path to new version of modification.")
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .required(true)
                                .help("Path to original file.")
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
        )
        .get_matches();

    match matches.subcommand() {
        Some(("config", agent_matches)) => match agent_matches.subcommand() {
            Some(("create", create_matches)) => {
                println!("Welcome to the JACS Config Generator!");

                println!("Enter the path to the agent file (leave empty to skip):");
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
                    request_string("Enter the private key filename:", "jacs.private.pem");
                let jacs_agent_public_key_filename =
                    request_string("Enter the public key filename:", "jacs.public.pem");
                let jacs_agent_key_algorithm = request_string("Enter the agent key algorithm (ring-Ed25519, pq-dilithium, or RSA-PSS) no default:", "");
                let jacs_private_key_password = request_string("Enter the private key password for encrypting on disk (don't use in product. set env JACS_PRIVATE_KEY_PASSWORD:", "");

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
            Some(("read", verify_matches)) => {
                // agent is loaded because of    schema.validate_config(&config).expect("config validation");
                let _ = load_agent_by_id();
                let configs = set_env_vars();
                println!("{}", configs);
            }
            _ => println!("please enter subcommand see jacs agent --help"),
        },
        Some(("agent", agent_matches)) => match agent_matches.subcommand() {
            Some(("create", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename").unwrap();
                let create_keys = *create_matches.get_one::<bool>("create-keys").unwrap();
                let agentstring = fs::read_to_string(filename.clone()).expect("agent file loading");
                let mut agent = get_agent();
                agent
                    .create_agent_and_load(&agentstring, false, None)
                    .expect("agent creation failed");
                println!("Agent {} created!", agent.get_lookup_id().expect("id"));

                if create_keys {
                    agent.generate_keys().expect("Reason");
                    println!(
                        "keys created in {}",
                        env::var("JACS_KEY_DIRECTORY").expect("JACS_KEY_DIRECTORY")
                    )
                }

                let _ = agent.save();
            }
            Some(("verify", verify_matches)) => {
                let agentfile = verify_matches.get_one::<String>("agent-file");
                let mut agent: Agent = if let Some(file) = agentfile {
                    load_agent(file.to_string())
                } else {
                    load_agent_by_id()
                };

                agent
                    .verify_self_signature()
                    .expect("signature verification");
                println!(
                    "Agent {} signature verified OK.",
                    agent.get_lookup_id().expect("jacsId")
                );
            }
            _ => println!("please enter subcommand see jacs agent --help"),
        },
        Some(("document", document_matches)) => match document_matches.subcommand() {
            Some(("create", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let outputfilename = create_matches.get_one::<String>("output");
                let directory = create_matches.get_one::<String>("directory");
                let verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches.get_one::<String>("attach");
                let embed = create_matches.get_one::<bool>("embed");

                let mut agent: Agent = if let Some(file) = agentfile {
                    load_agent(file.to_string())
                } else {
                    load_agent_by_id()
                };

                let attachment_links = agent.parse_attachement_arg(attachments);

                if !outputfilename.is_none() && !directory.is_none() {
                    eprintln!("Error: if there is a directory you can't name the file the same for multiple files.");
                    std::process::exit(1);
                }

                // check if output filename exists and that if so it's for one file

                let mut files: Vec<String> = Vec::new();
                if filename.is_none() && directory.is_none() && attachments.is_none() {
                    eprintln!("Error: You must specify either a filename or a directory or create from attachments.");
                    std::process::exit(1);
                } else if filename.is_none() && directory.is_none() {
                    files.push("no filepath given".to_string()); // hack to get the iterator to open
                } else if let Some(file) = filename {
                    files.push(file.to_string());
                } else if let Some(dir) = directory {
                    // Traverse the directory and store filenames ending with .json
                    for entry in fs::read_dir(dir).expect("Failed to read directory") {
                        if let Ok(entry) = entry {
                            let path = entry.path();
                            if path.is_file() && path.extension().map_or(false, |ext| ext == "json")
                            {
                                files.push(path.to_str().unwrap().to_string());
                            }
                        }
                    }
                }

                // let mut schemastring: String = "".to_string();

                if let Some(schema_file) = schema {
                    // schemastring =
                    fs::read_to_string(schema_file).expect("Failed to load schema file");

                    let schemas = [schema_file.clone()];
                    agent.load_custom_schemas(&schemas);
                }

                // iterate over filenames
                for file in &files {
                    let document_string: String = if filename.is_none() && directory.is_none() {
                        "{}".to_string()
                    } else {
                        fs::read_to_string(file).expect("document file loading")
                    };
                    let path = Path::new(file);
                    let loading_filename = path.file_name().unwrap().to_str().unwrap();
                    let loading_filename_string = loading_filename.to_string();
                    let result = agent.create_document_and_load(
                        &document_string,
                        attachment_links.clone(),
                        embed.copied(),
                    );

                    match result {
                        Ok(ref document) => {
                            let document_key = document.getkey();
                            let document_key_string = document_key.to_string();

                            let intermediate_filename = match outputfilename {
                                Some(filename) => filename,
                                None => &loading_filename_string,
                            };

                            if no_save {
                                println!("{}", document_key.to_string());
                            } else {
                                let re = Regex::new(r"(\.[^.]+)$").unwrap();
                                let signed_filename =
                                    re.replace(intermediate_filename, ".jacs$1").to_string();
                                agent
                                    .save_document(
                                        &document_key,
                                        format!("{}", signed_filename).into(),
                                        None,
                                    )
                                    .expect("save document");
                                println!("created doc {}", document_key.to_string());
                            }

                            if let Some(schema_file) = schema {
                                //let document_ref = agent.get_document(&document_key).unwrap();

                                let validate_result = agent.validate_document_with_custom_schema(
                                    &schema_file,
                                    &document.getvalue(),
                                );
                                match validate_result {
                                    Ok(_doc) => {
                                        println!(
                                            "document specialised schema {} validated",
                                            document_key
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "document specialised schema {} validation failed {}",
                                            document_key, e
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("document creation   {}   {}", file, e);
                        }
                    }
                } // end iteration
            }
            // TODO copy for sharing
            // Some(("copy", create_matches)) => {
            Some(("update", create_matches)) => {
                let new_filename = create_matches.get_one::<String>("new").unwrap();
                let original_filename = create_matches.get_one::<String>("filename").unwrap();
                let outputfilename = create_matches.get_one::<String>("output");
                let verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches.get_one::<String>("attach");
                let embed = create_matches.get_one::<bool>("embed");

                let mut agent: Agent = if let Some(file) = agentfile {
                    load_agent(file.to_string())
                } else {
                    load_agent_by_id()
                };

                let attachment_links = agent.parse_attachement_arg(attachments);

                if let Some(schema_file) = schema {
                    // schemastring =
                    fs::read_to_string(schema_file).expect("Failed to load schema file");

                    let schemas = [schema_file.clone()];
                    agent.load_custom_schemas(&schemas);
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

                if no_save {
                    println!("{}", new_document_key.to_string());
                } else {
                    // let re = Regex::new(r"(\.[^.]+)$").unwrap();
                    // //let re = Regex::new(r"\.([^.]+)$").unwrap();
                    // let signed_filename = re.replace(intermediate_filename, ".jacs.$1").to_string();
                    //  println!("output filename is {}", signed_filename);

                    let re = Regex::new(r"(\.[^.]+)$").unwrap();
                    let signed_filename = re.replace(intermediate_filename, ".jacs$1").to_string();
                    println!("output cl filename is {}", signed_filename);
                    agent
                        .save_document(
                            &new_document_key,
                            format!("{}", signed_filename).into(),
                            None,
                        )
                        .expect("save document");
                    println!("created doc {}", new_document_key.to_string());
                }

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
            }

            Some(("verify", verify_matches)) => {
                let filename = verify_matches.get_one::<String>("filename");
                let directory = verify_matches.get_one::<String>("directory");
                let verbose = *verify_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = verify_matches.get_one::<String>("agent-file");
                let mut agent: Agent = if let Some(file) = agentfile {
                    load_agent(file.to_string())
                } else {
                    load_agent_by_id()
                };
                let schema = verify_matches.get_one::<String>("schema");
                let mut files: Vec<String> = Vec::new();
                if filename.is_none() && directory.is_none() {
                    eprintln!("Error: You must specify either a filename or a directory.");
                    std::process::exit(1);
                } else if let Some(file) = filename {
                    files.push(file.to_string());
                } else if let Some(dir) = directory {
                    // Traverse the directory and store filenames ending with .json
                    for entry in fs::read_dir(dir).expect("Failed to read directory") {
                        if let Ok(entry) = entry {
                            let path = entry.path();
                            if path.is_file() && path.extension().map_or(false, |ext| ext == "json")
                            {
                                files.push(path.to_str().unwrap().to_string());
                            }
                        }
                    }
                }
                // let mut schemastring: String = "".to_string();

                if let Some(schema_file) = schema {
                    // schemastring =
                    //     fs::read_to_string(schema_file).expect("Failed to load schema file");
                    let schemas = [schema_file.clone()];
                    agent.load_custom_schemas(&schemas);
                }

                for file in &files {
                    let document_string = fs::read_to_string(file).expect("document file loading ");
                    let docresult = agent.load_document(&document_string);
                    match docresult {
                        Ok(ref document) => {
                            let document_key = document.getkey();
                            println!("document {} validated", document_key);

                            if let Some(schema_file) = schema {
                                // todo don't unwrap but warn instead
                                let document_key = document.getkey();
                                let result = agent.validate_document_with_custom_schema(
                                    &schema_file,
                                    &document.getvalue(),
                                );
                                match result {
                                    Ok(doc) => {
                                        println!(
                                            "document specialised schema {} validated",
                                            document_key
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "document specialised schema {} validation failed {}",
                                            document_key, e
                                        );
                                        std::process::exit(1);
                                    }
                                }
                            }
                        }
                        Err(ref e) => {
                            eprintln!("document {} validation failed {}", file, e);
                            std::process::exit(1);
                        }
                    }
                }
            }

            _ => println!("please enter subcommand see jacs document --help"),
        },
        _ => println!("please enter command see jacs --help"),
    }
}
