use clap::{Arg, ArgAction, Command, crate_name, value_parser};
use jacs::agent::AGENT_AGREEMENT_FIELDNAME;
use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::cli_utils::create::handle_agent_create;
use jacs::cli_utils::create::handle_config_create;
use jacs::config::find_config;
use jacs::create_task;
use jacs::load_agent;
use jacs::shared::document_add_agreement;
use jacs::shared::document_check_agreement;
use jacs::shared::document_create;
use jacs::shared::document_load_and_save;
use jacs::shared::document_sign_agreement;
use jacs::storage::MultiStorage;
use std::env;
use std::error::Error;
use std::process;

fn main() -> Result<(), Box<dyn Error>> {
    let matches = Command::new(crate_name!())
        .subcommand(
            Command::new("version")
                .about("Prints version and build information")
        )
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
                                .help("Output filename. Filenames will always end with \"json\"")
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
                                .help("Output filename. Filenames will always end with \"json\"")
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
                                .help("Output filename. Filenames will always end with \"json\"")
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
        .subcommand(
            Command::new("init")
                .about("Initialize JACS by creating both config and agent (with keys)")
        )
        .arg_required_else_help(true)
        .get_matches();

    let mut storage: Option<MultiStorage> = None;

    if matches.subcommand_name() != Some("version") {
        storage = Some(MultiStorage::default_new().expect("Failed to initialize storage"));
    }

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
                handle_config_create(&storage)?;
            }
            Some(("read", verify_matches)) => {
                let config = find_config("./".to_string())?;
                println!("{}", config);
            }
            _ => println!("please enter subcommand see jacs config --help"),
        },
        Some(("agent", agent_matches)) => match agent_matches.subcommand() {
            Some(("create", create_matches)) => {
                // Parse args for the specific agent create command
                let filename = create_matches.get_one::<String>("filename");
                let create_keys = *create_matches.get_one::<bool>("create-keys").unwrap();

                // Call the refactored handler function
                handle_agent_create(&storage, filename, create_keys)?;
            }
            Some(("verify", verify_matches)) => {
                let agentfile = verify_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");

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

        Some(("task", task_matches)) => match task_matches.subcommand() {
            Some(("create", create_matches)) => {
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let name = create_matches.get_one::<String>("name").expect("REASON");
                let description = create_matches
                    .get_one::<String>("description")
                    .expect("REASON");
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
                let verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches.get_one::<String>("attach");
                let embed: Option<bool> = create_matches.get_one::<bool>("embed").copied();

                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");

                // let attachment_links = agent.parse_attachement_arg(attachments);

                if !outputfilename.is_none() && !directory.is_none() {
                    eprintln!(
                        "Error: if there is a directory you can't name the file the same for multiple files."
                    );
                    process::exit(1);
                }

                // Use updated set_file_list with storage
                let files: Vec<String> =
                    set_file_list(storage.as_ref().unwrap(), filename, directory, attachments)
                        .expect("Failed to determine file list");

                // iterate over filenames
                for file in &files {
                    let document_string: String =
                        if filename.is_none() && directory.is_none() && attachments.is_some() {
                            "{}".to_string()
                        } else if !file.is_empty() {
                            // Use storage to read the input document file
                            let content_bytes = storage
                                .as_ref()
                                .expect("Storage must be initialized for this command")
                                .get_file(file, None)
                                .expect(&format!("Failed to load document file: {}", file));
                            String::from_utf8(content_bytes)
                                .expect(&format!("Document file {} is not valid UTF-8", file))
                        } else {
                            eprintln!("Warning: Empty file path encountered in loop.");
                            "{}".to_string()
                        };
                    let result = document_create(
                        &mut agent,
                        &document_string,
                        schema.cloned(),
                        outputfilename.cloned(),
                        no_save,
                        attachments,
                        embed,
                    )
                    .expect("document_create");
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
                let verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches.get_one::<String>("attach");
                let embed = create_matches.get_one::<bool>("embed");

                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");

                let attachment_links = agent.parse_attachement_arg(attachments);

                if let Some(schema_file) = schema {
                    // Use storage to read the schema file
                    let schema_bytes = storage
                        .as_ref()
                        .expect("Storage must be initialized for this command")
                        .get_file(schema_file, None)
                        .expect(&format!("Failed to load schema file: {}", schema_file));
                    let _schemastring = String::from_utf8(schema_bytes)
                        .expect(&format!("Schema file {} is not valid UTF-8", schema_file));
                    let schemas = [schema_file.clone()]; // Still need the path string for agent
                    agent.load_custom_schemas(&schemas);
                }

                // Use storage to read the document files
                let new_doc_bytes = storage
                    .as_ref()
                    .expect("Storage must be initialized for this command")
                    .get_file(new_filename, None)
                    .expect(&format!(
                        "Failed to load new document file: {}",
                        new_filename
                    ));
                let new_document_string = String::from_utf8(new_doc_bytes).expect(&format!(
                    "New document file {} is not valid UTF-8",
                    new_filename
                ));

                let original_doc_bytes = storage
                    .as_ref()
                    .expect("Storage must be initialized for this command")
                    .get_file(original_filename, None)
                    .expect(&format!(
                        "Failed to load original document file: {}",
                        original_filename
                    ));
                let original_document_string =
                    String::from_utf8(original_doc_bytes).expect(&format!(
                        "Original document file {} is not valid UTF-8",
                        original_filename
                    ));

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

                let new_document_key = updated_document.getkey();
                let new_document_filename = format!("{}.json", new_document_key.clone());

                let intermediate_filename = match outputfilename {
                    Some(filename) => filename,
                    None => &new_document_filename,
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
                    println!("{}", &updated_document.getvalue());
                } else {
                    agent
                        .save_document(
                            &new_document_key,
                            format!("{}", intermediate_filename).into(),
                            None,
                            None,
                        )
                        .expect("save document");
                    println!("created doc {}", intermediate_filename);
                }
            }
            Some(("sign-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = create_matches.get_one::<String>("schema");
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);

                // Use updated set_file_list with storage
                let files: Vec<String> =
                    set_file_list(storage.as_ref().unwrap(), filename, directory, None)
                        .expect("Failed to determine file list");

                for file in &files {
                    // Use storage to read the input document file
                    let content_bytes = storage
                        .as_ref()
                        .expect("Storage must be initialized for this command")
                        .get_file(file, None)
                        .expect(&format!("Failed to load document file: {}", file));
                    let document_string = String::from_utf8(content_bytes)
                        .expect(&format!("Document file {} is not valid UTF-8", file));
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
                    .expect("reason");
                    println!("{}", result);
                }
            }
            Some(("check-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = create_matches.get_one::<String>("schema");

                // Use updated set_file_list with storage
                let files: Vec<String> =
                    set_file_list(storage.as_ref().unwrap(), filename, directory, None)
                        .expect("Failed to determine file list");

                for file in &files {
                    // Use storage to read the input document file
                    let content_bytes = storage
                        .as_ref()
                        .expect("Storage must be initialized for this command")
                        .get_file(file, None)
                        .expect(&format!("Failed to load document file: {}", file));
                    let document_string = String::from_utf8(content_bytes)
                        .expect(&format!("Document file {} is not valid UTF-8", file));
                    let result = document_check_agreement(
                        &mut agent,
                        &document_string,
                        schema.cloned(),
                        Some(AGENT_AGREEMENT_FIELDNAME.to_string()),
                    )
                    .expect("reason");
                    println!("{}", result);
                }
            }
            Some(("create-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = create_matches.get_one::<String>("schema");
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentids: Vec<String> = create_matches // Corrected reference to create_matches
                    .get_many::<String>("agentids")
                    .unwrap_or_default()
                    .map(|s| s.to_string())
                    .collect();

                // Use updated set_file_list with storage
                let files: Vec<String> =
                    set_file_list(storage.as_ref().unwrap(), filename, directory, None)
                        .expect("Failed to determine file list");

                for file in &files {
                    // Use storage to read the input document file
                    let content_bytes = storage
                        .as_ref()
                        .expect("Storage must be initialized for this command")
                        .get_file(file, None)
                        .expect(&format!("Failed to load document file: {}", file));
                    let document_string = String::from_utf8(content_bytes)
                        .expect(&format!("Document file {} is not valid UTF-8", file));
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
                    .expect("reason");
                    println!("{}", result);
                }
            }

            Some(("verify", verify_matches)) => {
                let filename = verify_matches.get_one::<String>("filename");
                let directory = verify_matches.get_one::<String>("directory");
                let verbose = *verify_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = verify_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = verify_matches.get_one::<String>("schema");
                // Use updated set_file_list with storage
                let files: Vec<String> =
                    set_file_list(storage.as_ref().unwrap(), filename, directory, None)
                        .expect("Failed to determine file list");

                for file in &files {
                    let load_only = true;
                    // Use storage to read the input document file
                    let content_bytes = storage
                        .as_ref()
                        .expect("Storage must be initialized for this command")
                        .get_file(file, None)
                        .expect(&format!("Failed to load document file: {}", file));
                    let document_string = String::from_utf8(content_bytes)
                        .expect(&format!("Document file {} is not valid UTF-8", file));
                    let result = document_load_and_save(
                        &mut agent,
                        &document_string,
                        schema.cloned(),
                        None,
                        None,
                        None,
                        load_only,
                    )
                    .expect("reason");
                    println!("{}", result);
                }
            }

            Some(("extract", extract_matches)) => {
                let filename = extract_matches.get_one::<String>("filename");
                let directory = extract_matches.get_one::<String>("directory");
                let verbose = *extract_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = extract_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = extract_matches.get_one::<String>("schema");
                // Use updated set_file_list with storage
                let files: Vec<String> =
                    set_file_list(storage.as_ref().unwrap(), filename, directory, None)
                        .expect("Failed to determine file list");
                // extract the contents but do not save
                let load_only = false;
                for file in &files {
                    // Use storage to read the input document file
                    let content_bytes = storage
                        .as_ref()
                        .expect("Storage must be initialized for this command")
                        .get_file(file, None)
                        .expect(&format!("Failed to load document file: {}", file));
                    let document_string = String::from_utf8(content_bytes)
                        .expect(&format!("Document file {} is not valid UTF-8", file));
                    let result = document_load_and_save(
                        &mut agent,
                        &document_string,
                        schema.cloned(),
                        None,
                        Some(true),
                        Some(true),
                        load_only,
                    )
                    .expect("reason");
                    println!("{}", result);
                }
            }

            _ => println!("please enter subcommand see jacs document --help"),
        },
        Some(("init", _init_matches)) => {
            println!("--- Running Config Creation ---");
            handle_config_create(&storage)?;
            println!("\n--- Running Agent Creation (with keys) ---");
            // Call agent create handler with None for filename and true for create_keys
            handle_agent_create(&storage, None, true)?;
            println!("\n--- JACS Initialization Complete ---");
        }
        _ => {
            // This branch should ideally be unreachable after adding arg_required_else_help(true)
            eprintln!("Invalid command or no subcommand provided. Use --help for usage.");
            process::exit(1); // Exit with error if this branch is reached
        }
    }

    Ok(())
}

// Updated set_file_list function
fn set_file_list(
    storage: &MultiStorage,
    filename: Option<&String>,
    directory: Option<&String>,
    attachments: Option<&String>,
) -> Result<Vec<String>, Box<dyn Error>> {
    if let Some(file) = filename {
        // If filename is provided, return it as a single item list.
        // The caller will attempt fs::read_to_string on this local path.
        Ok(vec![file.clone()])
    } else if let Some(dir) = directory {
        // If directory is provided, list .json files within it using storage.
        let prefix = if dir.ends_with('/') {
            dir.clone()
        } else {
            format!("{}/", dir)
        };
        // Use storage.list to get files from the specified storage location
        let files = storage.list(&prefix, None)?;
        // Filter for .json files as originally intended for directory processing
        Ok(files.into_iter().filter(|f| f.ends_with(".json")).collect())
    } else if attachments.is_some() {
        // If only attachments are provided, the loop should run once without reading files.
        // Return an empty list; the calling loop handles creating "{}"
        Ok(Vec::new())
    } else {
        Err("You must specify either a filename, a directory, or attachments.".into())
    }
}
