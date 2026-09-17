//! Opt-in, typed A2A 1.0 card projection for the finite report example.
//!
//! Legacy cards/codecs and discovery defaults are unchanged. This is not a
//! production host or a v1 implementation of the legacy A2ATrustPolicy parser.

use crate::{agent::Agent, error::JacsError, public_agent::PublicAgentProjection};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::JACS_EXTENSION_URI;
use crate::compatibility::exports::A2A_COMPAT_BINDING_PATH;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Card {
    pub name: String,
    pub description: String,
    pub version: String,
    pub supported_interfaces: Vec<Interface>,
    pub capabilities: Capabilities,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub skills: Vec<Skill>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Interface {
    pub url: String,
    pub protocol_binding: String,
    pub protocol_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capabilities {
    // These are optional proto booleans: Some(false) MUST retain presence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_notifications: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_agent_card: Option<bool>,
    pub extensions: Vec<Extension>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Extension {
    pub uri: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    // Ordinary proto boolean: false has no wire presence, unlike capabilities.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    pub params: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Skill {
    pub id: String,
    pub name: String,
    pub description: String,
    // Required arrays must be nonempty for a valid A2A message.
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BindingReference {
    jacs_id: String,
    jacs_version: String,
    jacs_compat_kid: String,
    jacs_compat_binding_hash: String,
    jacs_compat_binding_path: String,
}

fn invalid(message: &str) -> JacsError {
    JacsError::ValidationError(message.to_owned())
}

/// Build the narrow finite-host profile with an explicit, actually served URL.
/// The caller hosts the declared report skill; projection itself hosts nothing.
pub fn project_agent_card(agent: &Agent, messaging_url: &str) -> Result<Card, JacsError> {
    let projection = PublicAgentProjection::from_agent(agent)?;
    let url = url::Url::parse(messaging_url).map_err(|_| invalid("invalid A2A messaging URL"))?;
    if !(url.scheme() == "https"
        || (url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "A2A messaging URL must be explicit HTTP(S), without credentials/query/fragment",
        ));
    }
    Ok(Card {
        name: projection.name,
        description: projection.description,
        version: projection.jacs_version,
        supported_interfaces: vec![Interface {
            url: messaging_url.to_owned(),
            protocol_binding: "JSONRPC".into(),
            protocol_version: "1.0".into(),
        }],
        capabilities: Capabilities {
            streaming: Some(false),
            push_notifications: Some(false),
            extended_agent_card: Some(false),
            extensions: vec![Extension {
                uri: JACS_EXTENSION_URI.into(),
                description: "Key-backed document provenance; authority is established separately."
                    .into(),
                required: false,
                params: json!({}),
            }],
        },
        default_input_modes: vec!["text/plain".into()],
        default_output_modes: vec!["application/json".into()],
        skills: vec![Skill {
            id: "synthetic-report".into(),
            name: "Return synthetic report".into(),
            description: "Return one pre-signed synthetic JSON report; no remote signing.".into(),
            tags: vec!["provenance".into()],
        }],
    })
}

/// Sign a typed v1 card using existing compatibility custody and card scope.
/// No new public binding method or generic JWS signing API is introduced.
pub fn export_agent_card(
    agent: &mut Agent,
    key_directory: &str,
    card: Card,
) -> Result<Value, JacsError> {
    crate::compatibility::exports::export_a2a_v1_agent_card_from(agent, key_directory, card)
}

impl Card {
    pub(crate) fn bind(&mut self, agent: &Agent, kid: &str, hash: &str) -> Result<(), JacsError> {
        let projection = PublicAgentProjection::from_agent(agent)?;
        if self.name.is_empty()
            || self.description.is_empty()
            || self.version != projection.jacs_version
            || self.supported_interfaces.len() != 1
            || self.skills.is_empty()
            || self.default_input_modes.is_empty()
            || self.default_output_modes.is_empty()
            || self.skills.iter().any(|s| {
                s.id.is_empty()
                    || s.name.is_empty()
                    || s.description.is_empty()
                    || s.tags.is_empty()
                    || s.tags.iter().any(String::is_empty)
            })
            || self
                .default_input_modes
                .iter()
                .chain(&self.default_output_modes)
                .any(String::is_empty)
        {
            return Err(invalid("missing or inconsistent required v1 card field"));
        }
        let interface = &self.supported_interfaces[0];
        project_agent_card(agent, &interface.url)?; // Reuse explicit URL validation.
        if interface.protocol_binding != "JSONRPC"
            || interface.protocol_version != "1.0"
            || [
                self.capabilities.streaming,
                self.capabilities.push_notifications,
                self.capabilities.extended_agent_card,
            ]
            .contains(&Some(true))
        {
            return Err(invalid(
                "unsupported interface/capability in finite A2A v1 profile",
            ));
        }
        let mut uris = std::collections::HashSet::new();
        for extension in &self.capabilities.extensions {
            if extension.uri.is_empty() || !uris.insert(&extension.uri) || extension.required {
                return Err(invalid(
                    "ambiguous or required extension in finite A2A v1 profile",
                ));
            }
            if extension.uri == JACS_EXTENSION_URI {
                if extension.params != json!({}) {
                    return Err(invalid(
                        "JACS binding parameters are generated, not caller supplied",
                    ));
                }
            } else {
                if !extension.params.is_object() {
                    return Err(invalid("extension params must be a nonempty JSON object"));
                }
                validate_params(&extension.params, 0)?;
            }
        }
        let mut entries = self
            .capabilities
            .extensions
            .iter_mut()
            .filter(|e| e.uri == JACS_EXTENSION_URI);
        let entry = entries
            .next()
            .ok_or_else(|| invalid("missing JACS provenance extension"))?;
        if entries.next().is_some() {
            return Err(invalid("duplicate JACS provenance extension"));
        }
        entry.params = json!({
            "jacsId": projection.jacs_id, "jacsVersion": projection.jacs_version,
            "jacsCompatKid": kid, "jacsCompatBindingHash": hash,
            "jacsCompatBindingPath": A2A_COMPAT_BINDING_PATH,
        });
        Ok(())
    }

    pub(crate) fn signing_value(&self) -> Result<Value, JacsError> {
        // The typed serializer handles proto presence. Unsupported empty
        // parameter values are rejected at bind(), never silently erased to
        // accommodate the pinned peer's recursive-empty canonicalization bug.
        Ok(serde_json::to_value(self)?)
    }
}

// Keep the finite profile inside both protobuf Struct's numeric range and the
// pinned peer's lossless field-presence subset. This is not a generic JSON rule.
fn validate_params(value: &Value, depth: usize) -> Result<(), JacsError> {
    if depth > 16 {
        return Err(invalid("A2A extension parameters are too deep"));
    }
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, item) in map {
                if key.is_empty() {
                    return Err(invalid("empty extension parameter key"));
                }
                validate_params(item, depth + 1)?;
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for item in items {
                validate_params(item, depth + 1)?;
            }
        }
        Value::String(text) if !text.is_empty() => {}
        Value::Bool(_) => {}
        Value::Number(number)
            if number
                .as_f64()
                .is_some_and(|n| n.is_finite() && n.abs() <= 9_007_199_254_740_991.0) => {}
        _ => {
            return Err(invalid(
                "unsupported empty or numeric extension parameter; value was not removed",
            ));
        }
    }
    Ok(())
}

/// Native root/binding half of the v1 bridge. The caller must ALSO verify the
/// card JWS with the exact supplied JWK (the example uses the official SDK).
/// Expected identity/version/root are out-of-band trust inputs, not card claims.
/// This stateless bridge does not implement a remote rollback history store.
pub fn verify_card_binding(
    card: &Value,
    binding: &Value,
    jwk: &Value,
    expected_id: &str,
    expected_version: &str,
    trusted_root: &[u8],
) -> Result<(), JacsError> {
    let extensions = card
        .pointer("/capabilities/extensions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("missing JACS provenance extensions"))?;
    let mut entries = extensions.iter().filter(|e| e["uri"] == JACS_EXTENSION_URI);
    let entry = entries
        .next()
        .ok_or_else(|| invalid("missing JACS provenance extension"))?;
    if entries.next().is_some() {
        return Err(invalid("duplicate JACS provenance extension"));
    }
    let reference: BindingReference = serde_json::from_value(entry["params"].clone())
        .map_err(|_| invalid("missing or ambiguous JACS binding reference"))?;
    if reference.jacs_id != expected_id
        || reference.jacs_version != expected_version
        || card["version"] != expected_version
        || jwk["kid"].as_str() != Some(reference.jacs_compat_kid.as_str())
        || reference.jacs_compat_binding_path != A2A_COMPAT_BINDING_PATH
        || reference.jacs_compat_binding_hash.is_empty()
    {
        return Err(invalid(
            "JACS v1 binding reference does not match expected identity/key/path",
        ));
    }
    let verdict = crate::compatibility::binding::verify_remote_a2a_binding(
        binding,
        expected_id,
        expected_version,
        &reference.jacs_compat_binding_hash,
        jwk,
        trusted_root,
    )?;
    if !verdict.valid {
        return Err(invalid("native binding verification refused"));
    }
    Ok(())
}
