use crate::agent::Agent;
use crate::error::JacsError;
use crate::public_agent::PublicAgentProjection;
use crate::w3c::did_wba::{W3cDidOptions, parts_for_projection};
use serde_json::{Value, json};
use tracing::info;

pub fn export_agent_description(agent: &Agent, options: W3cDidOptions) -> Result<Value, JacsError> {
    let projection = PublicAgentProjection::from_agent(agent)?;
    export_agent_description_for_agent(agent, &projection, options)
}

/// Agent-aware funnel (P2 Task 004): the description starts as the pre-P2
/// native-only projection, and when the agent holds an ES256 compat key
/// AND a valid PQ-root-signed binding granting the `w3c-agent-identity`
/// scope, the `jacs` block is enriched with the compat kid and the
/// binding reference AS A CONTENT HASH (same fields as the DID document —
/// never a URL, NG8). The `ecosystem_export_generated` event and the
/// export counter fire ONLY on that authorized path — an ungated
/// native-only export emits no P2 telemetry (mirrors `did_wba`).
pub(crate) fn export_agent_description_for_agent(
    agent: &Agent,
    projection: &PublicAgentProjection,
    options: W3cDidOptions,
) -> Result<Value, JacsError> {
    let mut description = export_agent_description_with_options(projection, options)?;

    if let Some((compat, binding)) =
        crate::compatibility::binding::compat_enrichment_if_authorized(agent, "w3c-agent-identity")?
    {
        let binding_hash = crate::compatibility::binding::binding_hash(&binding);
        description["jacs"]["compatKid"] = json!(compat.kid);
        description["jacs"]["compatBindingHash"] = json!(binding_hash);
        info!(
            event = "ecosystem_export_generated",
            format = "w3c-agent-identity",
            jacs_id = %projection.jacs_id,
            kid = %compat.kid,
            binding_hash = %binding_hash,
            did = %description["did"].as_str().unwrap_or(""),
            "W3C agent identity (AgentDescription) exported with ES256 compatibility metadata"
        );
        crate::compatibility::record_export_generated("w3c-agent-identity");
    }

    Ok(description)
}

/// Projection-only view: the pre-P2 native-only AgentDescription shape.
/// No agent means no binding check, so this path never carries compat
/// metadata and never emits the scoped export event/counter.
pub fn export_agent_description_with_options(
    projection: &PublicAgentProjection,
    options: W3cDidOptions,
) -> Result<Value, JacsError> {
    let parts = parts_for_projection(projection, &options)?;
    let description_url = format!("{}{}", parts.origin, parts.agent_description_path);

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
