use clap::{value_parser, Arg, ArgAction, Command};
use jacs::agent::boilerplate::BoilerPlate;
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
                                .help("Instead of saving files, print to stdout")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("schema")
                                .short('s')
                                .help("Path to JSON schema file to use to create")
                                .long("no-save")
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
                                .long("no-save")
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
            _ => unreachable!(),
        },
        Some(("document", document_matches)) => match document_matches.subcommand() {
            Some(("create", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let verbose = *create_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let no_save = *create_matches.get_one::<bool>("no-save").unwrap_or(&false);
                let agentfile = create_matches.get_one::<String>("agent-file").unwrap();
                let schema = create_matches.get_one::<String>("schema").unwrap();
                let agent = load_agent(agentfile.to_string());
                if filename.is_none() && directory.is_none() {
                    eprintln!("Error: You must specify either a filename or a directory.");
                    std::process::exit(1);
                }
            }
            Some(("verify", verify_matches)) => {
                let filename = verify_matches.get_one::<String>("filename");
                let directory = verify_matches.get_one::<String>("directory");
                let verbose = *verify_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = verify_matches.get_one::<String>("agent-file").unwrap();
                let agent = load_agent(agentfile.to_string());
                let schema = verify_matches.get_one::<String>("schema").unwrap();
                if filename.is_none() && directory.is_none() {
                    eprintln!("Error: You must specify either a filename or a directory.");
                    std::process::exit(1);
                }
            }

            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}
