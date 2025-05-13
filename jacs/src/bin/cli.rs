use clap::{Arg, ArgAction, Command, crate_name, value_parser};

use crate::cli_utils::set_file_list;
use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::cli_utils::create::handle_agent_create;
use jacs::cli_utils::create::handle_config_create;
use jacs::cli_utils::document::{
    check_agreement, create_agreement, create_documents, extract_documents, sign_documents,
    update_documents, verify_documents,
};
use jacs::config::find_config;
use jacs::create_task;
use jacs::load_agent;

use std::env;
use std::error::Error;
use std::os::unix::fs::DirBuilderExt;
use std::process;

pub fn main() -> Result<(), Box<dyn Error>> {
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

        // Some(("task", task_matches)) => match task_matches.subcommand() {
        //     Some(("create", create_matches)) => {
        //         let agentfile = create_matches.get_one::<String>("agent-file");
        //         let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
        //         let name = create_matches.get_one::<String>("name").expect("REASON");
        //         let description = create_matches
        //             .get_one::<String>("description")
        //             .expect("REASON");
        //         println!(
        //             "{}",
        //             create_task(&mut agent, name.to_string(), description.to_string()).unwrap()
        //         );
        //     }
        //     _ => println!("please enter subcommand see jacs task --help"),
        // },
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

                let attachment_links = agent.parse_attachement_arg(attachments);
                create_documents(
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
                let verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");
                let schema = create_matches.get_one::<String>("schema");
                let attachments = create_matches.get_one::<String>("attach");
                let embed = create_matches.get_one::<bool>("embed");

                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");

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
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = create_matches.get_one::<String>("schema");
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);

                // Use updated set_file_list with storage
                sign_documents(agent, schema, filename, directory)?;
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
                check_agreement(agent, schema, filename, directory)?;
            }
            Some(("create-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let _verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file");

                let schema = create_matches.get_one::<String>("schema");
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentids: Vec<String> = create_matches // Corrected reference to create_matches
                    .get_many::<String>("agentids")
                    .unwrap_or_default()
                    .map(|s| s.to_string())
                    .collect();

                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                // Use updated set_file_list with storage
                create_agreement(&mut agent, agentids, filename, schema, no_save, directory);
            }

            Some(("verify", verify_matches)) => {
                let filename = verify_matches.get_one::<String>("filename");
                let directory = verify_matches.get_one::<String>("directory");
                let verbose = *verify_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = verify_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = verify_matches.get_one::<String>("schema");
                // Use updated set_file_list with storage
                verify_documents(agent, schema, filename, directory)?;
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
                extract_documents(agent, schema, filename, directory)?;
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
