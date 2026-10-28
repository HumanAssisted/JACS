//! Opt-in, typed A2A 1.0 cards for bounded JSON-RPC service profiles.
//!
//! Legacy cards/codecs and discovery defaults are unchanged. This is not a
//! production host or a v1 implementation of the legacy A2ATrustPolicy parser.
//! General discovery requires explicit caller-declared skills and content modes;
//! the finite report helper remains available for the example host.

use crate::agent::boilerplate::BoilerPlate;
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

/// Explicit description of the caller's hosted JSON-RPC service. Exporting
/// discovery does not install a handler or provide any of these skills.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoveryOptions {
    pub protocol_version: String,
    pub messaging_url: String,
    pub skills: Vec<Skill>,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
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
    project_agent_card_for_discovery(
        agent,
        DiscoveryOptions {
            protocol_version: "1.0".into(),
            messaging_url: messaging_url.into(),
            skills: vec![Skill {
                id: "synthetic-report".into(),
                name: "Return synthetic report".into(),
                description: "Return one pre-signed synthetic JSON report; no remote signing."
                    .into(),
                tags: vec!["provenance".into()],
            }],
            default_input_modes: vec!["text/plain".into()],
            default_output_modes: vec!["application/json".into()],
        },
    )
}

/// Project a bounded A2A 1.0 card using only caller-declared service behavior.
/// No demo skill, endpoint, or content mode is invented for ordinary callers.
pub fn project_agent_card_for_discovery(
    agent: &Agent,
    options: DiscoveryOptions,
) -> Result<Card, JacsError> {
    if options.protocol_version != "1.0" {
        return Err(invalid(
            "discovery options require protocolVersion '1.0'; omit options for legacy discovery",
        ));
    }
    let projection = PublicAgentProjection::from_agent(agent)?;
    validate_messaging_url(&options.messaging_url)?;
    let card = Card {
        name: projection.name,
        description: projection.description,
        version: projection.jacs_version,
        supported_interfaces: vec![Interface {
            url: options.messaging_url,
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
        default_input_modes: options.default_input_modes,
        default_output_modes: options.default_output_modes,
        skills: options.skills,
    };
    card.validate_profile(&card.version, &json!({}))?;
    Ok(card)
}

fn validate_messaging_url(messaging_url: &str) -> Result<(), JacsError> {
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
    Ok(())
}

/// Sign a typed v1 card directly with the loaded ML-DSA-87 root. The key
/// directory argument is retained for source compatibility; no bridge is made.
/// This narrow finite profile emits A2A's detached JWS signature object.
pub fn export_agent_card(
    agent: &mut Agent,
    _key_directory: &str,
    mut card: Card,
) -> Result<Value, JacsError> {
    use crate::crypt::KeyManager;
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    if agent.get_key_algorithm().map(String::as_str) != Some("pq2025") {
        return Err(invalid(
            "direct v1 card requires a loaded pq2025 root; explicitly select ES256 compatibility if required",
        ));
    }
    let key = agent.get_public_key()?.clone();
    let jwk = jacs_core::jose::mldsa87_public_jwk(&key)?;
    let kid = jwk["kid"]
        .as_str()
        .ok_or_else(|| invalid("missing root kid"))?;
    let projection = PublicAgentProjection::from_agent(agent)?;
    card.bind_parameters(
        agent,
        json!({
            "jacsId": projection.jacs_id, "jacsVersion": projection.jacs_version,
            "jacsRootKid": kid,
        }),
    )?;
    let mut wire = card.signing_value()?;
    let canonical = jacs_core::canonical::canonicalize_json_try(&wire)?;
    let input = jacs_core::jose::mldsa87_jws_signing_input(canonical.as_bytes(), kid)?;
    let signature = URL_SAFE_NO_PAD.encode(STANDARD.decode(agent.sign_string(&input)?)?);
    jacs_core::jose::verify_mldsa87_jws(&format!("{input}.{signature}"), &key, Some(kid))?;
    let (protected, _) = input
        .split_once('.')
        .ok_or_else(|| invalid("invalid JWS input"))?;
    wire["signatures"] = json!([{ "protected": protected, "signature": signature }]);
    Ok(wire)
}

/// Explicit ES256 compatibility export for peers without ML-DSA-87 support.
pub fn export_agent_card_es256(
    agent: &mut Agent,
    key_directory: &str,
    card: Card,
) -> Result<Value, JacsError> {
    crate::compatibility::exports::export_a2a_v1_agent_card_from(agent, key_directory, card)
}

impl Card {
    pub(crate) fn bind(&mut self, agent: &Agent, kid: &str, hash: &str) -> Result<(), JacsError> {
        let projection = PublicAgentProjection::from_agent(agent)?;
        self.bind_parameters(
            agent,
            json!({
                "jacsId": projection.jacs_id, "jacsVersion": projection.jacs_version,
                "jacsCompatKid": kid, "jacsCompatBindingHash": hash,
                "jacsCompatBindingPath": A2A_COMPAT_BINDING_PATH,
            }),
        )
    }

    fn bind_parameters(&mut self, agent: &Agent, parameters: Value) -> Result<(), JacsError> {
        let projection = PublicAgentProjection::from_agent(agent)?;
        self.validate_profile(&projection.jacs_version, &json!({}))?;
        let entry = self
            .capabilities
            .extensions
            .iter_mut()
            .find(|e| e.uri == JACS_EXTENSION_URI)
            .ok_or_else(|| invalid("missing JACS provenance extension"))?;
        entry.params = parameters;
        Ok(())
    }

    fn validate_profile(
        &self,
        expected_version: &str,
        expected_params: &Value,
    ) -> Result<(), JacsError> {
        if self.name.is_empty()
            || self.description.is_empty()
            || self.version != expected_version
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
        let mut skill_ids = std::collections::HashSet::new();
        if self.skills.iter().any(|skill| !skill_ids.insert(&skill.id)) {
            return Err(invalid("duplicate A2A skill identifier"));
        }
        validate_messaging_url(&interface.url)?;
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
                if &extension.params != expected_params {
                    return Err(invalid(
                        "JACS identity parameters do not match the expected profile",
                    ));
                }
            } else {
                if !extension.params.is_object() {
                    return Err(invalid("extension params must be a nonempty JSON object"));
                }
                validate_params(&extension.params, 0)?;
            }
        }
        if !uris.contains(&JACS_EXTENSION_URI.to_owned()) {
            return Err(invalid("missing JACS provenance extension"));
        }
        Ok(())
    }

    pub(crate) fn signing_value(&self) -> Result<Value, JacsError> {
        // The typed serializer handles proto presence. Unsupported empty
        // parameter values are rejected at bind(), never silently erased to
        // accommodate the pinned peer's recursive-empty canonicalization bug.
        Ok(serde_json::to_value(self)?)
    }
}

// Select only the caller-pinned root's signature. Other signatures may support
// rotation or countersigning, but confer no authority here. Validate every
// entry's bounded JOSE shape before selecting, so order cannot hide malformed
// headers or duplicate key identifiers.
fn root_signature<'a>(
    card: &'a Value,
    expected_kid: &str,
) -> Result<(&'a str, &'a str), JacsError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let signatures = card["signatures"]
        .as_array()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("expected nonempty v1 card signatures"))?;
    let mut kids = std::collections::HashSet::new();
    let mut selected = None;
    for entry in signatures {
        let sig = entry
            .as_object()
            .filter(|s| s.len() == 2)
            .ok_or_else(|| invalid("invalid v1 signature object"))?;
        let protected = sig
            .get("protected")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing protected header"))?;
        let signature = sig
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing signature"))?;
        let header_bytes = URL_SAFE_NO_PAD
            .decode(protected)
            .map_err(|_| invalid("invalid protected header encoding"))?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| invalid("invalid signature encoding"))?;
        if URL_SAFE_NO_PAD.encode(&header_bytes) != protected
            || signature_bytes.is_empty()
            || URL_SAFE_NO_PAD.encode(&signature_bytes) != signature
        {
            return Err(invalid("noncanonical or empty v1 signature encoding"));
        }
        let header = jacs_core::strict_json::parse_strict_json_slice(&header_bytes)?;
        let object = header
            .as_object()
            .ok_or_else(|| invalid("protected header must be an object"))?;
        let kid = header["kid"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("missing protected kid"))?;
        if object
            .keys()
            .any(|name| !matches!(name.as_str(), "alg" | "typ" | "kid"))
            || header["alg"]
                .as_str()
                .is_none_or(|alg| alg.is_empty() || alg == "none")
            || header.get("typ").is_some_and(|typ| typ != "JOSE")
        {
            return Err(invalid("unsupported v1 protected header"));
        }
        if !kids.insert(kid.to_owned()) {
            return Err(invalid("duplicate v1 signature kid"));
        }
        if kid == expected_kid {
            if header["alg"] != "ML-DSA-87" {
                return Err(invalid("root signature must use ML-DSA-87"));
            }
            selected = Some((protected, signature));
        }
    }
    selected.ok_or_else(|| invalid("no signature for the trusted root kid"))
}

/// Verify this finite A2A v1 profile against an explicitly trusted native root
/// and identity/version. A self-published JWKS alone is not a trust input.
pub fn verify_root_card(
    card: &Value,
    jwk: &Value,
    expected_id: &str,
    expected_version: &str,
    trusted_root: &[u8],
) -> Result<(), JacsError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let key = jacs_core::jose::mldsa87_public_key(jwk)?;
    let expected_jwk = jacs_core::jose::mldsa87_public_jwk(&key)?;
    if key != trusted_root || jwk["kid"] != expected_jwk["kid"] {
        return Err(invalid(
            "v1 card key does not match the trusted root and thumbprint",
        ));
    }
    let kid = expected_jwk["kid"]
        .as_str()
        .ok_or_else(|| invalid("missing root kid"))?;
    let (protected, signature) = root_signature(card, kid)?;
    let mut unsigned = card.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| invalid("card must be an object"))?
        .remove("signatures");
    // Reject unknown fields and noncanonical presence representations rather
    // than silently removing anything before verification.
    let typed: Card = serde_json::from_value(unsigned.clone())?;
    if typed.signing_value()? != unsigned || typed.version != expected_version {
        return Err(invalid("unsupported v1 card profile or identity version"));
    }
    let entries: Vec<_> = typed
        .capabilities
        .extensions
        .iter()
        .filter(|e| e.uri == JACS_EXTENSION_URI)
        .collect();
    if entries.len() != 1
        || entries[0].params
            != json!({
                "jacsId": expected_id, "jacsVersion": expected_version, "jacsRootKid": kid,
            })
    {
        return Err(invalid("v1 root identity reference mismatch"));
    }
    typed.validate_profile(
        expected_version,
        &json!({
            "jacsId": expected_id, "jacsVersion": expected_version, "jacsRootKid": kid,
        }),
    )?;
    let payload = jacs_core::canonical::canonicalize_json_try(&unsigned)?;
    let compact = format!(
        "{protected}.{}.{signature}",
        URL_SAFE_NO_PAD.encode(payload)
    );
    jacs_core::jose::verify_mldsa87_jws(&compact, &key, Some(kid))?;
    Ok(())
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
