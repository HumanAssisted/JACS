use clap::{Arg, ArgAction, Command, crate_name, value_parser};

use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::cli_utils::create::handle_agent_create;
use jacs::cli_utils::create::handle_config_create;
use jacs::cli_utils::default_set_file_list;
use jacs::cli_utils::document::{
    check_agreement, create_agreement, create_documents, extract_documents, sign_documents,
    update_documents, verify_documents,
};
use jacs::config::find_config;
// use jacs::create_task; // unused
use jacs::dns::bootstrap as dns_bootstrap;
use jacs::{load_agent, load_agent_with_dns_strict};

use std::env;
use std::error::Error;
// use std::os::unix::fs::DirBuilderExt; // unused
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
                    Command::new("dns")
                        .about("emit DNS TXT commands for publishing agent fingerprint")
                        .arg(
                            Arg::new("agent-file")
                                .short('a')
                                .long("agent-file")
                                .value_parser(value_parser!(String))
                                .help("Path to agent JSON (optional; defaults via config)"),
                        )
                        .arg(
                            Arg::new("no-dns")
                                .long("no-dns")
                                .help("Disable DNS validation; rely on embedded fingerprint")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("require-dns")
                                .long("require-dns")
                                .help("Require DNS validation; if domain missing, fail. Not strict (no DNSSEC required).")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("require-strict-dns")
                                .long("require-strict-dns")
                                .help("Require strict DNSSEC validation; if domain missing, fail.")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("ignore-dns")
                                .long("ignore-dns")
                                .help("Ignore DNS validation entirely.")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(Arg::new("domain").long("domain").value_parser(value_parser!(String)))
                        .arg(Arg::new("agent-id").long("agent-id").value_parser(value_parser!(String)))
                        .arg(Arg::new("ttl").long("ttl").value_parser(value_parser!(u32)).default_value("3600"))
                        .arg(Arg::new("encoding").long("encoding").value_parser(["base64","hex"]).default_value("base64"))
                        .arg(Arg::new("provider").long("provider").value_parser(["plain","aws","azure","cloudflare"]).default_value("plain"))
                )
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
                    )
                    .arg(
                        Arg::new("no-dns")
                            .long("no-dns")
                            .help("Disable DNS validation; rely on embedded fingerprint")
                            .action(ArgAction::SetTrue),
                    )
                    .arg(
                        Arg::new("require-dns")
                            .long("require-dns")
                            .help("Require DNS validation; if domain missing, fail. Not strict (no DNSSEC required).")
                            .action(ArgAction::SetTrue),
                    )
                    .arg(
                        Arg::new("require-strict-dns")
                            .long("require-strict-dns")
                            .help("Require strict DNSSEC validation; if domain missing, fail.")
                            .action(ArgAction::SetTrue),
                    )
                    .arg(
                        Arg::new("ignore-dns")
                            .long("ignore-dns")
                            .help("Ignore DNS validation entirely.")
                            .action(ArgAction::SetTrue),
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
            Some(("read", verify_matches)) => {
                let config = find_config("./".to_string())?;
                println!("{}", config);
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
                let agent_file = sub_m.get_one::<String>("agent-file").cloned();
                let non_strict = *sub_m.get_one::<bool>("no-dns").unwrap_or(&false);
                let mut agent: Agent = if let Some(path) = agent_file.clone() {
                    if non_strict {
                        load_agent_with_dns_strict(path, false)
                            .expect("failed to load agent (non-strict)")
                    } else {
                        load_agent(Some(path)).expect("failed to load agent")
                    }
                } else {
                    load_agent(None)
                        .expect("Provide --agent-file or ensure config points to a readable agent")
                };
                if *sub_m.get_one::<bool>("ignore-dns").unwrap_or(&false) {
                    agent.set_dns_validate(false);
                    agent.set_dns_required(false);
                    agent.set_dns_strict(false);
                } else if *sub_m
                    .get_one::<bool>("require-strict-dns")
                    .unwrap_or(&false)
                {
                    agent.set_dns_validate(true);
                    agent.set_dns_required(true);
                    agent.set_dns_strict(true);
                } else if *sub_m.get_one::<bool>("require-dns").unwrap_or(&false) {
                    agent.set_dns_validate(true);
                    agent.set_dns_required(true);
                    agent.set_dns_strict(false);
                } else if non_strict {
                    agent.set_dns_validate(true);
                    agent.set_dns_required(false);
                    agent.set_dns_strict(false);
                }
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
                let agentfile = verify_matches.get_one::<String>("agent-file");
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
                let mut agent: Agent = if let Some(path) = agentfile.cloned() {
                    if non_strict {
                        load_agent_with_dns_strict(path, false).expect("agent file")
                    } else {
                        load_agent(Some(path)).expect("agent file")
                    }
                } else {
                    // No path provided; use default loader
                    load_agent(None).expect("agent file")
                };
                if ignore_dns {
                    agent.set_dns_validate(false);
                    agent.set_dns_required(false);
                    agent.set_dns_strict(false);
                } else if require_strict {
                    agent.set_dns_validate(true);
                    agent.set_dns_required(true);
                    agent.set_dns_strict(true);
                } else if require_dns {
                    agent.set_dns_validate(true);
                    agent.set_dns_required(true);
                    agent.set_dns_strict(false);
                } else if non_strict {
                    agent.set_dns_validate(true);
                    agent.set_dns_required(false);
                    agent.set_dns_strict(false);
                }
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
                let attachments = create_matches
                    .get_one::<String>("attach")
                    .map(|s| s.as_str());
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
                let attachments = create_matches
                    .get_one::<String>("attach")
                    .map(|s| s.as_str());
                let embed: Option<bool> = create_matches.get_one::<bool>("embed").copied();

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
                sign_documents(&mut agent, schema, filename, directory)?;
            }
            Some(("check-agreement", create_matches)) => {
                let filename = create_matches.get_one::<String>("filename");
                let directory = create_matches.get_one::<String>("directory");
                let agentfile = create_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = create_matches.get_one::<String>("schema");

                // Use updated set_file_list with storage
                let files: Vec<String> = default_set_file_list(filename, directory, None)
                    .expect("Failed to determine file list");
                check_agreement(&mut agent, schema, filename, directory)?;
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
                verify_documents(&mut agent, schema, filename, directory)?;
            }

            Some(("extract", extract_matches)) => {
                let filename = extract_matches.get_one::<String>("filename");
                let directory = extract_matches.get_one::<String>("directory");
                let verbose = *extract_matches.get_one::<bool>("verbose").unwrap_or(&false);
                let agentfile = extract_matches.get_one::<String>("agent-file");
                let mut agent: Agent = load_agent(agentfile.cloned()).expect("REASON");
                let schema = extract_matches.get_one::<String>("schema");
                // Use updated set_file_list with storage
                let files: Vec<String> = default_set_file_list(filename, directory, None)
                    .expect("Failed to determine file list");
                // extract the contents but do not save
                extract_documents(&mut agent, schema, filename, directory)?;
            }

            _ => println!("please enter subcommand see jacs document --help"),
        },
        Some(("init", _init_matches)) => {
            println!("--- Running Config Creation ---");
            handle_config_create()?;
            println!("\n--- Running Agent Creation (with keys) ---");
            // Call agent create handler with None for filename and true for create_keys
            handle_agent_create(None, true)?;
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
