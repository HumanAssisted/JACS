use crate::agent::Agent;
use crate::error::JacsError;
use crate::public_agent::PublicAgentProjection;
use crate::w3c::agent_description::export_agent_description_with_options;
use crate::w3c::did_wba::{W3cDidOptions, export_did_document, parts_for_projection};
use serde_json::{Value, json};

pub fn generate_w3c_well_known_documents(
    agent: &Agent,
    options: W3cDidOptions,
) -> Result<Vec<(String, Value)>, JacsError> {
    let projection = PublicAgentProjection::from_agent(agent)?;
    let parts = parts_for_projection(&projection, &options)?;
    let did_document = export_did_document(agent, options.clone())?;
    let agent_description = export_agent_description_with_options(&projection, options)?;
    let description_url = format!("{}{}", parts.origin, parts.agent_description_path);

    let collection = json!({
        "@context": {
            "@vocab": "https://schema.org/",
            "did": "https://w3id.org/did#",
            "ad": "https://agent-network-protocol.com/ad#"
        },
        "@type": "CollectionPage",
        "url": format!("{}/.well-known/agent-descriptions", parts.origin),
        "items": [
            {
                "@type": "ad:AgentDescription",
                "name": projection.name.clone(),
                "@id": description_url,
                "did": parts.did
            }
        ]
    });

    Ok(vec![
        ("/.well-known/agent-descriptions".to_string(), collection),
        (parts.agent_description_path, agent_description),
        (parts.did_document_path, did_document),
    ])
}
