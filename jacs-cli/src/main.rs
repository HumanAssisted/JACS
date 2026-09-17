use clap::Parser;
use jacs_cli::{Cli, execute, initialize_tracing};

fn main() -> std::process::ExitCode {
    initialize_tracing();
    match execute(Cli::parse()) {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE,
        Err(error) => {
            // Errors and logs never share stdout with signed JSON or MCP frames.
            tracing::warn!(code = error.code, reason = %error.message, "JACS command failed");
            std::process::ExitCode::FAILURE
        }
    }
}
