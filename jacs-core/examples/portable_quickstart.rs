use jacs_core::{CoreAgent, SigningAlgorithm};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Pq2025)?;
    let signed = agent.sign_message(&json!({"message": "hello"}))?;
    let verified = agent.verify(&signed)?;
    assert!(verified.valid);
    println!("PQ signature verified");
    Ok(())
}
