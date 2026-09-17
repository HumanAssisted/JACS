//! Local fixture exporter / public-key-only verifier for examples/a2a_v1_peer.py.
//! No server, remote signer, user keys or ambient configuration is used here.
#[path = "support/a2a_v1.rs"]
mod support;
use std::io::Read;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let output = match args.get(1).map(String::as_str) {
        Some("fixture") if args.len() == 3 => support::fixture(&args[2])?,
        Some("verify") if args.len() == 2 => {
            let mut input = Vec::new();
            std::io::stdin().take(1_048_577).read_to_end(&mut input)?;
            if input.len() > 1_048_576 {
                return Err("input exceeds fixture limit".into());
            }
            let input = jacs_core::strict_json::parse_strict_json(std::str::from_utf8(&input)?)?;
            support::verify(&input)?
        }
        _ => {
            return Err(
                "usage: a2a_v1_peer fixture <served-url> | verify < public-input.json".into(),
            );
        }
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("a2a_v1_peer: local fixture/verification operation failed");
        std::process::exit(1);
    }
}
