//! Clap `Command` tree for the `jacs` binary.
//!
//! Extracted from `main.rs` so the library target (used by the snapshot test
//! in `tests/cli_command_snapshot.rs`) can pick it up without dragging in the
//! full binary entry point. See `src/lib.rs` for the public re-export.

use clap::{Arg, ArgAction, Command, crate_name, value_parser};

use crate::password_bootstrap::quickstart_password_bootstrap_help;

pub fn build_cli() -> Command {
    let cmd = Command::new(crate_name!())
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
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
                )
                .subcommand(
                    Command::new("lookup")
                        .about("Look up another agent's public key and DNS info from their domain")
                        .arg(
                            Arg::new("domain")
                                .required(true)
                                .help("Domain to look up (e.g., agent.example.com)"),
                        )
                        .arg(
                            Arg::new("no-dns")
                                .long("no-dns")
                                .help("Skip DNS TXT record lookup")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("strict")
                                .long("strict")
                                .help("Require DNSSEC validation for DNS lookup")
                                .action(ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("rotate-keys")
                        .about("Rotate the agent's cryptographic keys")
                        .arg(
                            Arg::new("algorithm")
                                .long("algorithm")
                                .value_parser(["ring-Ed25519", "pq2025"])
                                .help("Signing algorithm for the new keys (defaults to current)"),
                        )
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .value_parser(value_parser!(String))
                                .help("Path to jacs.config.json (default: ./jacs.config.json)"),
                        ),
                )
                .subcommand(
                    Command::new("keys-list")
                        .about("List active and archived key files")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .value_parser(value_parser!(String))
                                .help("Path to jacs.config.json (default: ./jacs.config.json)"),
                        ),
                )
                .subcommand(
                    Command::new("repair")
                        .about("Repair config after an interrupted key rotation")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .value_parser(value_parser!(String))
                                .help("Path to jacs.config.json (default: ./jacs.config.json)"),
                        ),
                ),
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
            Command::new("key")
                .about("Work with JACS cryptographic keys")
                .subcommand(
                    Command::new("reencrypt")
                        .about("Re-encrypt the private key with a new password")
                )
        )
        .subcommand(
            Command::new("mcp")
                .about("Start the built-in JACS MCP server (stdio transport)")
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .default_value("core")
                        .help("Tool profile: 'core' (default, core tools) or 'full' (all tools)"),
                )
                .subcommand(
                    Command::new("install")
                        .about("Deprecated: MCP is now built into the jacs binary")
                        .hide(true)
                )
                .subcommand(
                    Command::new("run")
                        .about("Deprecated: use `jacs mcp` directly")
                        .hide(true)
                ),
        )
        .subcommand(
            Command::new("a2a")
                .about("A2A (Agent-to-Agent) trust and discovery commands")
                .subcommand(
                    Command::new("assess")
                        .about("Assess trust level of a remote A2A Agent Card")
                        .arg(
                            Arg::new("source")
                                .required(true)
                                .help("Path to Agent Card JSON file or URL"),
                        )
                        .arg(
                            Arg::new("policy")
                                .long("policy")
                                .short('p')
                                .value_parser(["open", "verified", "strict"])
                                .default_value("verified")
                                .help("Trust policy to apply (default: verified)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .action(ArgAction::SetTrue)
                                .help("Output result as JSON"),
                        ),
                )
                .subcommand(
                    Command::new("trust")
                        .about("Add a remote A2A agent to the local trust store")
                        .arg(
                            Arg::new("source")
                                .required(true)
                                .help("Path to Agent Card JSON file or URL"),
                        ),
                )
                .subcommand(
                    Command::new("discover")
                        .about("Discover a remote A2A agent via its well-known Agent Card")
                        .arg(
                            Arg::new("url")
                                .required(true)
                                .help("Base URL of the agent (e.g. https://agent.example.com)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .action(ArgAction::SetTrue)
                                .help("Output the full Agent Card as JSON"),
                        )
                        .arg(
                            Arg::new("policy")
                                .long("policy")
                                .short('p')
                                .value_parser(["open", "verified", "strict"])
                                .default_value("verified")
                                .help("Trust policy to apply against the discovered card"),
                        ),
                )
                .subcommand(
                    Command::new("serve")
                        .about("Serve this agent's .well-known endpoints for A2A discovery")
                        .arg(
                            Arg::new("port")
                                .long("port")
                                .value_parser(value_parser!(u16))
                                .default_value("8080")
                                .help("Port to listen on (default: 8080)"),
                        )
                        .arg(
                            Arg::new("host")
                                .long("host")
                                .default_value("127.0.0.1")
                                .help("Host to bind to (default: 127.0.0.1)"),
                        ),
                )
                .subcommand(
                    Command::new("quickstart")
                        .about("Create/load an agent and start serving A2A endpoints (password required)")
                        .after_help(quickstart_password_bootstrap_help())
                        .arg(
                            Arg::new("name")
                                .long("name")
                                .value_parser(value_parser!(String))
                                .required(true)
                                .help("Agent name used for first-time quickstart creation"),
                        )
                        .arg(
                            Arg::new("domain")
                                .long("domain")
                                .value_parser(value_parser!(String))
                                .required(true)
                                .help("Agent domain used for DNS/public-key verification workflows"),
                        )
                        .arg(
                            Arg::new("description")
                                .long("description")
                                .value_parser(value_parser!(String))
                                .help("Optional human-readable agent description"),
                        )
                        .arg(
                            Arg::new("port")
                                .long("port")
                                .value_parser(value_parser!(u16))
                                .default_value("8080")
                                .help("Port to listen on (default: 8080)"),
                        )
                        .arg(
                            Arg::new("host")
                                .long("host")
                                .default_value("127.0.0.1")
                                .help("Host to bind to (default: 127.0.0.1)"),
                        )
                        .arg(
                            Arg::new("algorithm")
                                .long("algorithm")
                                .short('a')
                                .value_parser(["pq2025", "ring-Ed25519"])
                                .help("Signing algorithm (default: pq2025)"),
                        ),
                ),
        )
        .subcommand(
            Command::new("w3c")
                .about("W3C AI Agent Protocol interop helpers")
                .subcommand(
                    Command::new("did")
                        .about("Export this agent's did:wba identifier")
                        .arg(
                            Arg::new("origin")
                                .long("origin")
                                .value_parser(value_parser!(String))
                                .help("Controlling HTTPS origin for did:wba and discovery URLs"),
                        ),
                )
                .subcommand(
                    Command::new("did-document")
                        .about("Export this agent's did:wba DID document")
                        .arg(
                            Arg::new("origin")
                                .long("origin")
                                .value_parser(value_parser!(String))
                                .help("Controlling HTTPS origin for did:wba and discovery URLs"),
                        ),
                )
                .subcommand(
                    Command::new("agent-description")
                        .about("Export this agent's W3C agent description document")
                        .arg(
                            Arg::new("origin")
                                .long("origin")
                                .value_parser(value_parser!(String))
                                .help("Controlling HTTPS origin for did:wba and discovery URLs"),
                        ),
                )
                .subcommand(
                    Command::new("well-known")
                        .about("Generate W3C well-known discovery documents")
                        .arg(
                            Arg::new("origin")
                                .long("origin")
                                .value_parser(value_parser!(String))
                                .help("Controlling HTTPS origin for did:wba and discovery URLs"),
                        )
                        .arg(
                            Arg::new("out")
                                .long("out")
                                .short('o')
                                .value_parser(value_parser!(String))
                                .help("Directory to write generated discovery files into"),
                        ),
                )
                .subcommand(
                    Command::new("serve")
                        .about("Serve W3C discovery documents for local demo/testing")
                        .arg(
                            Arg::new("origin")
                                .long("origin")
                                .value_parser(value_parser!(String))
                                .help("Controlling HTTPS origin for did:wba and discovery URLs"),
                        )
                        .arg(
                            Arg::new("port")
                                .long("port")
                                .value_parser(value_parser!(u16))
                                .default_value("8081")
                                .help("Port to listen on (default: 8081)"),
                        )
                        .arg(
                            Arg::new("host")
                                .long("host")
                                .default_value("127.0.0.1")
                                .help("Host to bind to (default: 127.0.0.1)"),
                        ),
                )
                .subcommand(
                    Command::new("sign-request")
                        .about("Create a request-bound DID authentication proof")
                        .arg(
                            Arg::new("method")
                                .long("method")
                                .value_parser(value_parser!(String))
                                .required(true)
                                .help("HTTP method to bind into the proof"),
                        )
                        .arg(
                            Arg::new("url")
                                .long("url")
                                .value_parser(value_parser!(String))
                                .required(true)
                                .help("HTTP target URI to bind into the proof"),
                        )
                        .arg(
                            Arg::new("body")
                                .long("body")
                                .value_parser(value_parser!(String))
                                .conflicts_with("body-file")
                                .help("Request body bytes to digest and bind"),
                        )
                        .arg(
                            Arg::new("body-file")
                                .long("body-file")
                                .value_parser(value_parser!(String))
                                .conflicts_with("body")
                                .help("File containing request body bytes to digest and bind"),
                        )
                        .arg(
                            Arg::new("origin")
                                .long("origin")
                                .value_parser(value_parser!(String))
                                .help("Controlling HTTPS origin for the signing agent DID"),
                        )
                        .arg(
                            Arg::new("nonce")
                                .long("nonce")
                                .value_parser(value_parser!(String))
                                .help("Caller-provided nonce; generated when omitted"),
                        )
                        .arg(
                            Arg::new("created")
                                .long("created")
                                .value_parser(value_parser!(String))
                                .help("RFC3339 created time; current time when omitted"),
                        ),
                )
                .subcommand(
                    Command::new("verify-request")
                        .about("Verify a request-bound DID authentication proof")
                        .arg(
                            Arg::new("method")
                                .long("method")
                                .value_parser(value_parser!(String))
                                .help("Actual HTTP method to compare against the proof"),
                        )
                        .arg(
                            Arg::new("url")
                                .long("url")
                                .value_parser(value_parser!(String))
                                .help("Actual HTTP target URI to compare against the proof"),
                        )
                        .arg(
                            Arg::new("proof")
                                .long("proof")
                                .value_parser(value_parser!(String))
                                .required(true)
                                .help("Path to request proof JSON"),
                        )
                        .arg(
                            Arg::new("did-document")
                                .long("did-document")
                                .value_parser(value_parser!(String))
                                .required(true)
                                .help("Path to resolved DID document JSON"),
                        )
                        .arg(
                            Arg::new("body")
                                .long("body")
                                .value_parser(value_parser!(String))
                                .conflicts_with("body-file")
                                .help("Request body bytes to check against the proof digest"),
                        )
                        .arg(
                            Arg::new("body-file")
                                .long("body-file")
                                .value_parser(value_parser!(String))
                                .conflicts_with("body")
                                .help("File containing request body bytes to check"),
                        )
                        .arg(
                            Arg::new("max-age-seconds")
                                .long("max-age-seconds")
                                .value_parser(value_parser!(u64))
                                .default_value("300")
                                .help("Maximum accepted proof age in seconds"),
                        ),
                ),
        )
        .subcommand(
            Command::new("quickstart")
                .about("Create or load a persistent agent for instant sign/verify (password required)")
                .after_help(quickstart_password_bootstrap_help())
                .arg(
                    Arg::new("name")
                        .long("name")
                        .value_parser(value_parser!(String))
                        .required(true)
                        .help("Agent name used for first-time quickstart creation"),
                )
                .arg(
                    Arg::new("domain")
                        .long("domain")
                        .value_parser(value_parser!(String))
                        .required(true)
                        .help("Agent domain used for DNS/public-key verification workflows"),
                )
                .arg(
                    Arg::new("description")
                        .long("description")
                        .value_parser(value_parser!(String))
                        .help("Optional human-readable agent description"),
                )
                .arg(
                    Arg::new("algorithm")
                        .long("algorithm")
                        .short('a')
                        .value_parser(["ed25519", "pq2025"])
                        .default_value("pq2025")
                        .help("Signing algorithm (default: pq2025)"),
                )
                .arg(
                    Arg::new("sign")
                        .long("sign")
                        .help("Sign JSON from stdin and print signed document to stdout")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .value_parser(value_parser!(String))
                        .help("Sign a JSON file instead of reading from stdin (used with --sign)"),
                )
        )
        .subcommand(
            Command::new("init")
                .about("Initialize JACS by creating both config and agent (with keys)")
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .short('y')
                        .action(ArgAction::SetTrue)
                        .help("Automatically set the new agent ID in jacs.config.json without prompting"),
                )
        )
        .subcommand(
            Command::new("attest")
                .about("Create and verify attestation documents")
                .subcommand(
                    Command::new("create")
                        .about("Create a signed attestation")
                        .arg(
                            Arg::new("subject-type")
                                .long("subject-type")
                                .value_parser(["agent", "artifact", "workflow", "identity"])
                                .help("Type of subject being attested"),
                        )
                        .arg(
                            Arg::new("subject-id")
                                .long("subject-id")
                                .value_parser(value_parser!(String))
                                .help("Identifier of the subject"),
                        )
                        .arg(
                            Arg::new("subject-digest")
                                .long("subject-digest")
                                .value_parser(value_parser!(String))
                                .help("SHA-256 digest of the subject"),
                        )
                        .arg(
                            Arg::new("claims")
                                .long("claims")
                                .value_parser(value_parser!(String))
                                .required(true)
                                .help("JSON array of claims, e.g. '[{\"name\":\"reviewed\",\"value\":true}]'"),
                        )
                        .arg(
                            Arg::new("evidence")
                                .long("evidence")
                                .value_parser(value_parser!(String))
                                .help("JSON array of evidence references"),
                        )
                        .arg(
                            Arg::new("from-document")
                                .long("from-document")
                                .value_parser(value_parser!(String))
                                .help("Lift attestation from an existing signed document file"),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .long("output")
                                .value_parser(value_parser!(String))
                                .help("Write attestation to file instead of stdout"),
                        ),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verify an attestation document")
                        .arg(
                            Arg::new("file")
                                .help("Path to the attestation JSON file")
                                .required(true)
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("full")
                                .long("full")
                                .action(ArgAction::SetTrue)
                                .help("Use full verification (evidence + derivation chain)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .action(ArgAction::SetTrue)
                                .help("Output result as JSON"),
                        )
                        .arg(
                            Arg::new("key-dir")
                                .long("key-dir")
                                .value_parser(value_parser!(String))
                                .help("Directory containing public keys for verification"),
                        )
                        .arg(
                            Arg::new("max-depth")
                                .long("max-depth")
                                .value_parser(value_parser!(u32))
                                .help("Maximum derivation chain depth"),
                        ),
                )
                .subcommand(
                    Command::new("export-dsse")
                        .about("Export an attestation as a DSSE envelope for in-toto/SLSA")
                        .arg(
                            Arg::new("file")
                                .help("Path to the signed attestation JSON file")
                                .required(true)
                                .value_parser(value_parser!(String)),
                        )
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .long("output")
                                .value_parser(value_parser!(String))
                                .help("Write DSSE envelope to file instead of stdout"),
                        ),
                )
                .subcommand_required(true)
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a signed JACS document (no agent required)")
                .arg(
                    Arg::new("file")
                        .help("Path to the signed JACS JSON file")
                        .required_unless_present("remote")
                        .value_parser(value_parser!(String)),
                )
                .arg(
                    Arg::new("remote")
                        .long("remote")
                        .value_parser(value_parser!(String))
                        .help("Fetch document from URL before verifying"),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Output result as JSON"),
                )
                .arg(
                    Arg::new("key-dir")
                        .long("key-dir")
                        .value_parser(value_parser!(String))
                        .help("Directory containing public keys for verification"),
                )
        );

    // OS keychain subcommand (only when keychain feature is enabled)
    #[cfg(feature = "keychain")]
    let cmd = cmd.subcommand(
        Command::new("keychain")
            .about("Manage private key passwords in the OS keychain (per-agent)")
            .subcommand(
                Command::new("set")
                    .about("Store a password in the OS keychain for an agent")
                    .arg(
                        Arg::new("agent-id")
                            .long("agent-id")
                            .help("Agent ID to associate the password with")
                            .value_name("AGENT_ID")
                            .required(true),
                    )
                    .arg(
                        Arg::new("password")
                            .long("password")
                            .help("Password to store (if omitted, prompts interactively)")
                            .value_name("PASSWORD"),
                    ),
            )
            .subcommand(
                Command::new("get")
                    .about("Retrieve the stored password for an agent (prints to stdout)")
                    .arg(
                        Arg::new("agent-id")
                            .long("agent-id")
                            .help("Agent ID to look up")
                            .value_name("AGENT_ID")
                            .required(true),
                    ),
            )
            .subcommand(
                Command::new("delete")
                    .about("Remove the stored password for an agent from the OS keychain")
                    .arg(
                        Arg::new("agent-id")
                            .long("agent-id")
                            .help("Agent ID whose password to delete")
                            .value_name("AGENT_ID")
                            .required(true),
                    ),
            )
            .subcommand(
                Command::new("status")
                    .about("Check if a password is stored for an agent in the OS keychain")
                    .arg(
                        Arg::new("agent-id")
                            .long("agent-id")
                            .help("Agent ID to check")
                            .value_name("AGENT_ID")
                            .required(true),
                    ),
            )
            .arg_required_else_help(true),
    );

    let cmd = cmd.subcommand(
        Command::new("convert")
            .about(
                "Convert JACS documents between JSON, YAML, and HTML formats (no agent required)",
            )
            .arg(
                Arg::new("to")
                    .long("to")
                    .required(true)
                    .value_parser(["json", "yaml", "html"])
                    .help("Target format: json, yaml, or html"),
            )
            .arg(
                Arg::new("from")
                    .long("from")
                    .value_parser(["json", "yaml", "html"])
                    .help("Source format (auto-detected from extension if omitted)"),
            )
            .arg(
                Arg::new("file")
                    .short('f')
                    .long("file")
                    .required(true)
                    .value_parser(value_parser!(String))
                    .help("Input file path (use '-' for stdin)"),
            )
            .arg(
                Arg::new("output")
                    .short('o')
                    .long("output")
                    .value_parser(value_parser!(String))
                    .help("Output file path (defaults to stdout)"),
            ),
    );

    // Inline text + media verbs (Task 08, PRD §3.1 / §3.2 / §4.1 / §4.2).

    cmd.subcommand(
        Command::new("sign-text")
            .about("Sign a text/markdown file in place with an inline JACS signature")
            .arg(
                Arg::new("file")
                    .help("Path to the text file to sign in place")
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                Arg::new("no-backup")
                    .long("no-backup")
                    .action(ArgAction::SetTrue)
                    .help("Skip the automatic <path>.bak backup"),
            )
            .arg(
                Arg::new("json")
                    .long("json")
                    .action(ArgAction::SetTrue)
                    .help("Output result as JSON"),
            ),
    )
    .subcommand(
        Command::new("verify-text")
            .about("Verify inline JACS signatures in a text/markdown file")
            .arg(
                Arg::new("file")
                    .help("Path to the signed text file")
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                Arg::new("key-dir")
                    .long("key-dir")
                    .value_parser(value_parser!(String))
                    .help("Directory containing signer public keys (.public.pem)"),
            )
            .arg(
                Arg::new("json")
                    .long("json")
                    .action(ArgAction::SetTrue)
                    .help("Output result as JSON"),
            )
            .arg(
                Arg::new("strict")
                    .long("strict")
                    .action(ArgAction::SetTrue)
                    .help(
                        "Treat 'no JACS signature found' as a hard failure (exits 1 instead of 2)",
                    ),
            ),
    )
    .subcommand(
        Command::new("sign-image")
            .about("Sign an image (PNG, JPEG, WebP) by embedding a JACS signature")
            .arg(
                Arg::new("input")
                    .help("Path to the input image")
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                Arg::new("out")
                    .long("out")
                    .required(true)
                    .value_parser(value_parser!(String))
                    .help("Output image path"),
            )
            .arg(
                Arg::new("robust")
                    .long("robust")
                    .action(ArgAction::SetTrue)
                    .help("Enable LSB fallback encoding (modifies pixel data; PNG/JPEG only)"),
            )
            .arg(
                Arg::new("format")
                    .long("format")
                    .value_parser(["png", "jpeg", "webp"])
                    .help("Force a specific format (auto-detected by default)"),
            )
            .arg(
                Arg::new("refuse-overwrite")
                    .long("refuse-overwrite")
                    .action(ArgAction::SetTrue)
                    .help("Refuse to overwrite an existing JACS signature on the input"),
            )
            .arg(
                Arg::new("json")
                    .long("json")
                    .action(ArgAction::SetTrue)
                    .help("Output result as JSON"),
            ),
    )
    .subcommand(
        Command::new("verify-image")
            .about("Verify an embedded JACS signature in an image")
            .arg(
                Arg::new("file")
                    .help("Path to the signed image")
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                Arg::new("key-dir")
                    .long("key-dir")
                    .value_parser(value_parser!(String))
                    .help("Directory containing signer public keys (.public.pem)"),
            )
            .arg(
                Arg::new("json")
                    .long("json")
                    .action(ArgAction::SetTrue)
                    .help("Output result as JSON"),
            )
            .arg(
                Arg::new("strict")
                    .long("strict")
                    .action(ArgAction::SetTrue)
                    .help(
                        "Treat 'no JACS signature found' as a hard failure (exits 1 instead of 2)",
                    ),
            )
            .arg(
                Arg::new("robust")
                    .long("robust")
                    .action(ArgAction::SetTrue)
                    .help("Scan LSB channel for the robust-mode payload (default off)"),
            ),
    )
    .subcommand(
        Command::new("extract-media-signature")
            .about("Extract the embedded JACS signature payload from an image")
            .arg(
                Arg::new("file")
                    .help("Path to the image to extract from")
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                Arg::new("raw-payload")
                    .long("raw-payload")
                    .action(ArgAction::SetTrue)
                    .help("Print the raw base64url wire form instead of the decoded JSON"),
            )
            .arg(
                Arg::new("robust")
                    .long("robust")
                    .action(ArgAction::SetTrue)
                    .help(
                        "Scan the LSB channel as a fallback if the metadata channel has \
                             no payload (R-011; mirrors verify-image --robust)",
                    ),
            ),
    )
}
