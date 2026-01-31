use anyhow::{Result, bail};
use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use serde_json::{Value, json};

fn extract_agent_id(req: &Value) -> Option<String> {
    req.get("agentId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn require_signed(req: &Value) -> Result<()> {
    let has_sig = req.get("signature").and_then(|v| v.as_str()).is_some();
    if !has_sig {
        bail!("unsigned request: 'signature' missing");
    }
    // Placeholder: full signature verification against JACS schema will be wired
    // using Agent::signature_verification_procedure when request carries JACS-signed payload
    Ok(())
}

fn ensure_self(agent: &Agent, req_agent_id: &str) -> Result<()> {
    let self_id = agent
        .get_id()
        .map_err(|_| anyhow::anyhow!("server agent not initialized"))?;
    if self_id != req_agent_id {
        bail!("unauthorized: agent mismatch (expected self)");
    }
    Ok(())
}

pub fn message_send(agent: &Agent, req: Value) -> Result<Value> {
    require_signed(&req)?;
    let req_agent = extract_agent_id(&req).ok_or_else(|| anyhow::anyhow!("agentId missing"))?;
    ensure_self(agent, &req_agent)?;
    Ok(json!({"status":"ok","op":"message.send","agentId": req_agent}))
}

pub fn message_update(agent: &Agent, req: Value) -> Result<Value> {
    require_signed(&req)?;
    let req_agent = extract_agent_id(&req).ok_or_else(|| anyhow::anyhow!("agentId missing"))?;
    ensure_self(agent, &req_agent)?;
    Ok(json!({"status":"ok","op":"message.update","agentId": req_agent}))
}

pub fn message_agree(agent: &Agent, req: Value) -> Result<Value> {
    require_signed(&req)?;
    let req_agent = extract_agent_id(&req).ok_or_else(|| anyhow::anyhow!("agentId missing"))?;
    ensure_self(agent, &req_agent)?;
    Ok(json!({"status":"ok","op":"message.agree","agentId": req_agent}))
}

pub fn message_receive(_agent: &Agent, req: Value) -> Result<Value> {
    require_signed(&req)?;
    // Public endpoint: do not enforce self, but still require signature
    let from_agent = extract_agent_id(&req).unwrap_or_else(|| "unknown".to_string());
    Ok(json!({"status":"ok","op":"message.receive","from": from_agent}))
}
