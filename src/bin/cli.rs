use clap::{value_parser, Arg, ArgAction, Command};
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::Agent;
use jacs::config::set_env_vars;
use jacs::crypt::KeyManager;

use std::env;
use std::fs;

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

fn main() {
    set_env_vars();
    let matches = Command::new("jacs")
        .subcommand(
            Command::new("agent")
                .subcommand(
                    Command::new("create")
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
                    Command::new("verify").arg(
                        Arg::new("agent-file")
                            .short('a')
                            .help("Path to the agent file")
                            .required(true)
                            .value_parser(value_parser!(String)),
                    ),
                ),
        )
        .subcommand(
            Command::new("document")
                .subcommand(
                    Command::new("create")

                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file")
                                .required(true)
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .help("Path to file. Must be JSON")
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
                        ),
                )
                .subcommand(
                    Command::new("verify")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .help("Path to the agent file")
                                .required(true)
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("filename")
                                .short('f')
                                .help("Path to file. Must be JSON")
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
            }
            Some(("verify", verify_matches)) => {
                let agentfile = verify_matches.get_one::<String>("agent-file").unwrap();
                let mut agent = load_agent(agentfile.to_string());
                agent
                    .verify_self_signature()
                    .expect("signature verification");
                println!(
                    "Agent {} signature verified OK.",
                    agent.get_lookup_id().expect("id")
                );
            }
            _ => println!("please enter subcommand see jacs agent --help"),
        },
        Some(("document", document_matches)) => match document_matches.subcommand() {
            Some(("create", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file").unwrap();
                let schema = create_matches.get_one::<String>("schema");
                let mut agent = load_agent(agentfile.to_string());
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

                let mut schemastring: String = "".to_string();

                if let Some(schema_file) = schema {
                    schemastring =
                        fs::read_to_string(schema_file).expect("Failed to load schema file");
                    let schemas = [schemastring.clone()];
                    agent.load_custom_schemas(&schemas);
                }

                // iterate over filenames
                for file in &files {
                    let document_string = fs::read_to_string(file).expect("document file loading");
                    let document = agent.create_document_and_load(&document_string).unwrap();
                    let document_key = document.getkey();
                    if no_save {
                        println!("{}", document_key.to_string());
                    } else {
                        agent.save_document(&document_key).expect("save document");
                    }

                    if let Some(schema_file) = schema {
                        let document_ref = agent.get_document(&document_key).unwrap();

                        // todo don't unwrap but warn instead
                        agent
                            .validate_document_with_custom_schema(
                                &schemastring,
                                &document.getvalue(),
                            )
                            .unwrap();
                    }
                } // end iteration
            }
            Some(("verify", verify_matches)) => {
                let filename = verify_matches.get_one::<String>("filename");
                let directory = verify_matches.get_one::<String>("directory");
                let verbose = *verify_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = verify_matches.get_one::<String>("agent-file").unwrap();
                let mut agent = load_agent(agentfile.to_string());
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
                let mut schemastring: String = "".to_string();

                if let Some(schema_file) = schema {
                    schemastring =
                        fs::read_to_string(schema_file).expect("Failed to load schema file");
                    let schemas = [schemastring.clone()];
                    agent.load_custom_schemas(&schemas);
                }

                for file in &files {
                    let document_string = fs::read_to_string(file).expect("document file loading ");
                    let document = agent.load_document(&document_string).unwrap();
                    let document_key = document.getkey();

                    if let Some(schema_file) = schema {
                        // todo don't unwrap but warn instead
                        agent
                            .validate_document_with_custom_schema(
                                &schemastring,
                                &document.getvalue(),
                            )
                            .unwrap();
                    }

                    println!("document {} validated", document_key);
                }
            }

            _ => println!("please enter subcommand see jacs document --help"),
        },
        _ => println!("please enter command see jacs --help"),
    }
}
