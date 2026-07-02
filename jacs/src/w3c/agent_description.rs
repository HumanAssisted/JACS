use crate::agent::Agent;
use crate::error::JacsError;
use crate::public_agent::PublicAgentProjection;
use crate::w3c::did_wba::{W3cDidOptions, parts_for_projection};
use serde_json::{Value, json};
use tracing::info;

pub fn export_agent_description(agent: &Agent, options: W3cDidOptions) -> Result<Value, JacsError> {
    let projection = PublicAgentProjection::from_agent(agent)?;
    export_agent_description_with_options(&projection, options)
}

pub fn export_agent_description_with_options(
    projection: &PublicAgentProjection,
    options: W3cDidOptions,
) -> Result<Value, JacsError> {
    let parts = parts_for_projection(projection, &options)?;
    let description_url = format!("{}{}", parts.origin, parts.agent_description_path);

    // P2 observability: the W3C agent identity (AgentDescription) export.
    // No exporter consumes the `w3c-agent-identity` binding scope yet —
    // this export carries native (not ES256) key material and is not
    // scope-gated — but the event completes the six-format bijection so
    // operators see every ecosystem-facing identity export in one stream.
    info!(
        event = "ecosystem_export_generated",
        format = "w3c-agent-identity",
        did = %parts.did,
        "W3C agent identity (AgentDescription) exported"
    );
    crate::compatibility::record_export_generated("w3c-agent-identity");

    Ok(json!({
        "@context": {
            "@vocab": "https://schema.org/",
            "ad": "https://agent-network-protocol.com/ad#",
            "jacs": "https://jacs.sh/ns#"
        },
        "@type": "ad:AgentDescription",
        "@id": description_url,
        "name": projection.name.clone(),
        "description": projection.description.clone(),
        "version": projection.jacs_version.clone(),
        "did": parts.did,
        "interfaces": [
            {
                "@type": "ad:Interface",
                "protocol": "jsonrpc",
                "url": projection.default_endpoint.clone()
            }
        ],
        "capabilities": [
            "jacs.document.signing",
            "jacs.document.verification",
            "jacs.provenance"
        ],
        "jacs": {
            "jacsId": projection.jacs_id.clone(),
            "jacsVersion": projection.jacs_version.clone(),
            "jacsLookupId": projection.jacs_lookup_id.clone(),
            "keyAlgorithm": projection.key_algorithm.clone(),
            "publicKeyHash": projection.public_key_hash.clone(),
            "verificationAlgorithms": projection.verification_algorithms.clone()
        }
    }))
}
