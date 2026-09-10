use jacs::simple::SimpleAgent;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (agent, info) = SimpleAgent::ephemeral(None)?;
    let signed = agent.sign_message(&serde_json::json!({"action": "approve"}))?;
    let result = agent.verify(&signed.raw)?;

    assert!(result.valid);
    println!(
        "verified {} signed by {}",
        signed.document_id, info.agent_id
    );
    Ok(())
}
